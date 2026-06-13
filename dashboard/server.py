#!/usr/bin/env python3
"""
dashboard/server.py

Servidor único del SOC Platform.
- Sirve todos los dashboards en un solo puerto (8888)
- Regenera cada dashboard según su frecuencia configurada
- Publica soc_status.json con datos de salud para el semáforo del index
- API REST en /api/config/* para el panel de configuración
"""

import json
import os
import secrets
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timezone, timedelta
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=False)
except ImportError:
    pass

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:
    print("[ERROR] Falta psycopg2-binary. Instala con: pip install psycopg2-binary")
    sys.exit(1)

# =============================================================================
# CONFIG
# =============================================================================
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("DB_NAME", "soc")
DB_USER = os.getenv("DB_USER", "soc_user")
DB_PASS = os.getenv("DB_PASSWORD", "")

# CORS: vacío = solo mismo origen (recomendado para uso interno)
CORS_ORIGIN = os.getenv("CORS_ORIGIN", "")

HTTP_HOST = os.getenv("DASHBOARD_HOST", "0.0.0.0")
HTTP_PORT = int(os.getenv("DASHBOARD_PORT", "8888"))

BASE_DIR = Path(__file__).resolve().parent

DASHBOARD_REFRESH = {
    "sentinel":         int(os.getenv("DASH_REFRESH_SENTINEL",         "30")),
    "nmap":             int(os.getenv("DASH_REFRESH_NMAP",             "300")),
    "fortinet":         int(os.getenv("DASH_REFRESH_FORTINET",         "60")),
    "fortinet_threats": int(os.getenv("DASH_REFRESH_FORTINET_THREATS", "120")),
    "snyk":             int(os.getenv("DASH_REFRESH_SNYK",             "300")),
    "cpanel":           int(os.getenv("DASH_REFRESH_CPANEL",           "300")),
}

# =============================================================================
# Estado global
# =============================================================================
MODULE_STATUS: dict[str, dict] = {
    "sentinel": {"last_update": None, "status": "pending", "records": 0, "health": {}},
    "nmap":     {"last_update": None, "status": "pending", "records": 0, "health": {}},
    "fortinet": {"last_update": None, "status": "pending", "records": 0, "health": {}},
    "snyk":     {"last_update": None, "status": "pending", "records": 0, "health": {}},
    "cpanel":   {"last_update": None, "status": "pending", "records": 0, "health": {}},
}


def get_active_fortinet_devices() -> list[str]:
    devices = []
    for n in range(1, 6):
        url   = os.getenv(f"FORTI_{n}_BASE_URL", "").strip()
        token = os.getenv(f"FORTI_{n}_API_TOKEN", "").strip()
        name  = os.getenv(f"FORTI_{n}_DEVICE_NAME", f"fortigate-{n}").strip()
        if url and token:
            devices.append(name)
    if not devices:
        url  = os.getenv("FORTI_BASE_URL", "").strip()
        name = os.getenv("FORTI_DEVICE_NAME", "fortigate").strip()
        if url:
            devices.append(name)
    return devices
_status_lock = threading.Lock()

# Sesiones del panel de configuración
_sessions: dict[str, datetime] = {}
SESSION_TTL_HOURS = 8

# Rutas que no requieren autenticación
_PUBLIC_PATHS = frozenset({"/config.html", "/favicon.ico"})


def db_connect():
    return psycopg2.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
        user=DB_USER, password=DB_PASS,
        cursor_factory=RealDictCursor,
    )


def now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def update_status(module: str, status: str, records: int = 0, health: dict = None):
    with _status_lock:
        MODULE_STATUS[module] = {
            "last_update": now_str(),
            "status":      status,
            "records":     records,
            "health":      health or {},
        }


def _check_auth(token: str) -> bool:
    expiry = _sessions.get(token)
    if not expiry:
        return False
    if datetime.now(timezone.utc) > expiry:
        _sessions.pop(token, None)
        return False
    return True


def _create_session() -> str:
    token = secrets.token_hex(32)
    _sessions[token] = datetime.now(timezone.utc) + timedelta(hours=SESSION_TTL_HOURS)
    return token


# =============================================================================
# SENTINEL
# =============================================================================
def build_sentinel_data() -> dict:
    with db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM sentinel_incidents")
            total = cur.fetchone()["n"]

            cur.execute("""
                SELECT COUNT(*) AS n FROM sentinel_incidents
                WHERE LOWER(COALESCE(status,'')) NOT IN ('resolved','closed','mitigated')
            """)
            active = cur.fetchone()["n"]

            cur.execute("""
                SELECT COUNT(*) AS n FROM sentinel_incidents
                WHERE LOWER(COALESCE(status,'')) = 'resolved'
            """)
            resolved = cur.fetchone()["n"]

            cur.execute("""
                SELECT COUNT(DISTINCT agent_id) AS n FROM sentinel_incidents
                WHERE agent_id IS NOT NULL AND agent_id <> ''
            """)
            endpoints = cur.fetchone()["n"]

            cur.execute("""
                SELECT COALESCE(classification,'Unknown') AS classification, COUNT(*) AS count
                FROM sentinel_incidents GROUP BY 1 ORDER BY 2 DESC
            """)
            classification_counts = [dict(r) for r in cur.fetchall()]

            cur.execute("""
                SELECT COALESCE(status,'unknown') AS status, COUNT(*) AS count
                FROM sentinel_incidents GROUP BY 1 ORDER BY 2 DESC
            """)
            status_counts = [dict(r) for r in cur.fetchall()]

            cur.execute("""
                SELECT DATE(created_at) AS day, COUNT(*) AS count
                FROM sentinel_incidents WHERE created_at IS NOT NULL
                GROUP BY 1 ORDER BY 1
            """)
            incidents_over_time = [
                {"date": str(r["day"]), "count": int(r["count"])}
                for r in cur.fetchall()
            ]

            cur.execute("""
                SELECT incident_id,
                    COALESCE(threat_name,'N/D') AS threat_name,
                    COALESCE(classification,'Unknown') AS classification,
                    COALESCE(severity,'Unknown') AS severity,
                    COALESCE(status,'Unknown') AS status,
                    COALESCE(agent_name,'N/D') AS agent_name,
                    COALESCE(username,'N/D') AS username,
                    created_at
                FROM sentinel_incidents
                ORDER BY created_at DESC NULLS LAST LIMIT 10
            """)
            recent_incidents = []
            for r in cur.fetchall():
                recent_incidents.append({
                    "incident_id":    r["incident_id"],
                    "endpoint":       r["agent_name"],
                    "threat":         r["threat_name"],
                    "classification": r["classification"],
                    "severity":       r["severity"],
                    "status":         str(r["status"]).capitalize(),
                    "username":       r["username"],
                    "created_at":     r["created_at"].strftime("%Y-%m-%d %H:%M:%S") if r["created_at"] else "N/D",
                })

            cur.execute("""
                SELECT COALESCE(agent_name,'N/D') AS agent_name, COUNT(*) AS count
                FROM sentinel_incidents GROUP BY 1 ORDER BY 2 DESC LIMIT 10
            """)
            top_endpoints = [dict(r) for r in cur.fetchall()]

    return {
        "generated_at": now_str(),
        "summary": {
            "monitored_endpoints": int(endpoints),
            "total_incidents":     int(total),
            "resolved_incidents":  int(resolved),
            "active_incidents":    int(active),
        },
        "classification_counts": classification_counts,
        "status_counts":         status_counts,
        "incidents_over_time":   incidents_over_time,
        "recent_incidents":      recent_incidents,
        "top_endpoints":         top_endpoints,
        "_health": {
            "active_incidents": int(active),
            "total_incidents":  int(total),
        },
    }


def refresh_sentinel():
    while True:
        try:
            data   = build_sentinel_data()
            health = data.pop("_health", {})
            (BASE_DIR / "sentinel_dashboard_data.json").write_text(
                json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
            )
            update_status("sentinel", "ok", data["summary"]["total_incidents"], health)
            print(f"[sentinel] OK — {data['summary']['total_incidents']} incidentes | {now_str()}")
        except Exception as e:
            update_status("sentinel", "error")
            print(f"[sentinel] ERROR: {e}")
        time.sleep(DASHBOARD_REFRESH["sentinel"])


# =============================================================================
# NMAP
# =============================================================================
def build_nmap_data() -> dict:
    with db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT ip, COALESCE(hostname,'') AS hostname, COALESCE(os_guess,'') AS os_guess, COALESCE(status,'') AS status, last_seen FROM nmap_assets ORDER BY last_seen DESC")
            assets = cur.fetchall()

            cur.execute("""
                SELECT a.ip, s.port, s.protocol,
                    COALESCE(s.service_name,'') AS service_name,
                    COALESCE(s.product,'') AS product,
                    COALESCE(s.version,'') AS version
                FROM nmap_services s JOIN nmap_assets a ON s.asset_id = a.id ORDER BY s.port
            """)
            services = cur.fetchall()

            cur.execute("""
                SELECT COALESCE(f.severity,'info') AS severity,
                    COALESCE(f.title,'') AS title,
                    COALESCE(f.category,'') AS category,
                    COALESCE(f.description,'') AS description,
                    COALESCE(f.recommendation,'') AS recommendation,
                    COALESCE(f.status,'open') AS status,
                    a.ip
                FROM nmap_findings f JOIN nmap_assets a ON f.asset_id = a.id
                ORDER BY f.created_at DESC
            """)
            findings = cur.fetchall()

    sev_counter  = Counter(f["severity"] or "unknown" for f in findings)
    port_counter = Counter(str(s["port"]) for s in services if s["port"])
    svc_counter  = Counter(s["service_name"] or "unknown" for s in services)
    risk_score = (
        sev_counter.get("critical", 0) * 10
        + sev_counter.get("high", 0) * 7
        + sev_counter.get("medium", 0) * 4
        + sev_counter.get("low", 0) * 1
    )

    return {
        "generated_at": now_str(),
        "kpis": {
            "assets":    len(assets),
            "services":  len(services),
            "findings":  len(findings),
            "critical":  sev_counter.get("critical", 0),
            "high":      sev_counter.get("high", 0),
            "medium":    sev_counter.get("medium", 0),
            "low":       sev_counter.get("low", 0),
            "risk_score": risk_score,
        },
        "severity":      dict(sev_counter),
        "ports":         dict(port_counter.most_common(10)),
        "services_dist": dict(svc_counter.most_common(10)),
        "assets_table": [
            {"ip": r["ip"], "hostname": r["hostname"], "os_guess": r["os_guess"],
             "status": r["status"], "last_seen": str(r["last_seen"])}
            for r in assets
        ],
        "services_table": [
            {"ip": r["ip"], "port": r["port"], "protocol": r["protocol"],
             "service_name": r["service_name"], "product": r["product"], "version": r["version"]}
            for r in services
        ],
        "findings_table": [
            {"severity": r["severity"], "title": r["title"], "category": r["category"],
             "description": r["description"], "recommendation": r["recommendation"],
             "status": r["status"], "ip": r["ip"]}
            for r in findings
        ],
        "summary": {"text": f"Se detectaron {len(assets)} activos, {len(services)} servicios y {len(findings)} hallazgos."},
        "_health": {
            "high_findings":     sev_counter.get("high", 0),
            "medium_findings":   sev_counter.get("medium", 0),
            "critical_findings": sev_counter.get("critical", 0),
        },
    }


def refresh_nmap():
    while True:
        try:
            data   = build_nmap_data()
            health = data.pop("_health", {})
            template = (BASE_DIR / "nmap_dashboard.html").read_text(encoding="utf-8")
            html = template.replace("{{DATA}}", json.dumps(data, ensure_ascii=False, default=str))
            (BASE_DIR / "nmap_dashboard_output.html").write_text(html, encoding="utf-8")
            update_status("nmap", "ok", data["kpis"]["assets"], health)
            print(f"[nmap] OK — {data['kpis']['assets']} activos, high={health.get('high_findings',0)} | {now_str()}")
        except Exception as e:
            update_status("nmap", "error")
            print(f"[nmap] ERROR: {e}")
        time.sleep(DASHBOARD_REFRESH["nmap"])


# =============================================================================
# FORTINET CONFIG
# =============================================================================
def refresh_fortinet():
    while True:
        try:
            sys.path.insert(0, str(BASE_DIR.parent))
            from dashboard.run_fortinet_dashboard import get_conn, fetch_latest_sections, build_html

            devices = get_active_fortinet_devices()
            total_policies = 0
            primary_written = False
            any_ok = False

            for device_name in devices:
                safe_name = device_name.lower().replace(" ", "_").replace("-", "_")
                dash_file = f"fortinet_dashboard_{safe_name}.html"
                try:
                    conn = get_conn()
                    try:
                        chosen, sections, errors = fetch_latest_sections(conn, device_name)
                    finally:
                        conn.close()

                    html = build_html(chosen, sections, errors)
                    (BASE_DIR / dash_file).write_text(html, encoding="utf-8")

                    if not primary_written:
                        (BASE_DIR / "fortinet_dashboard_output.html").write_text(html, encoding="utf-8")
                        primary_written = True

                    policies   = len(sections.get("firewall_policies", {}).get("results", []))
                    interfaces = len(sections.get("interfaces", {}).get("results", []))
                    total_policies += policies
                    any_ok = True

                    with _status_lock:
                        MODULE_STATUS[f"fortinet_{safe_name}"] = {
                            "last_update":    now_str(),
                            "status":         "ok",
                            "records":        policies,
                            "health":         {"policies": policies, "interfaces": interfaces},
                            "device_name":    device_name,
                            "dashboard_file": dash_file,
                        }
                except Exception as dev_e:
                    print(f"[fortinet] ERROR dispositivo {device_name}: {dev_e}")
                    with _status_lock:
                        MODULE_STATUS[f"fortinet_{safe_name}"] = {
                            "last_update":    now_str(),
                            "status":         "error",
                            "records":        0,
                            "health":         {},
                            "device_name":    device_name,
                            "dashboard_file": dash_file,
                        }

            with db_connect() as dbconn:
                with dbconn.cursor() as cur:
                    cur.execute("SELECT COUNT(*) AS n FROM fortinet_raw_snapshots")
                    total_snaps = int(cur.fetchone()["n"])

            health = {"snapshots": total_snaps, "policies": total_policies, "devices": len(devices)}
            update_status("fortinet", "ok" if any_ok else "error", total_snaps, health)
            print(f"[fortinet] OK — {len(devices)} dispositivo(s), snaps={total_snaps} | {now_str()}")
        except Exception as e:
            update_status("fortinet", "error")
            print(f"[fortinet] ERROR: {e}")
        time.sleep(DASHBOARD_REFRESH["fortinet"])


# =============================================================================
# FORTINET THREATS
# =============================================================================
def build_fortinet_threats_data(hours: int = 24, device_name: str | None = None) -> dict:
    df_sql   = "AND device_name = %s" if device_name else ""
    df_param = (device_name,) if device_name else ()

    with db_connect() as conn:
        with conn.cursor() as cur:
            interval = f"{hours} hours"

            cur.execute(f"""
                SELECT source, classification, COUNT(*) AS n
                FROM fortinet_threats
                WHERE collected_at >= NOW() - INTERVAL '{interval}'
                {df_sql}
                GROUP BY source, classification
            """, df_param)
            rows = cur.fetchall()

            counts: dict = {}
            for r in rows:
                src = r["source"]
                cls = r["classification"]
                n   = int(r["n"])
                if src not in counts:
                    counts[src] = {}
                counts[src][cls] = n

            cur.execute(f"""
                SELECT srcip, srcname, dstip, dstport, dstcountry,
                       action, app, apprisk, service, policyname,
                       sentbyte, rcvdbyte, classification,
                       log_date::text AS log_date, log_time
                FROM fortinet_threats
                WHERE source='traffic'
                  AND collected_at >= NOW() - INTERVAL '{interval}'
                  {df_sql}
                ORDER BY collected_at DESC LIMIT 200
            """, df_param)
            traffic_records = [dict(r) for r in cur.fetchall()]

            cur.execute(f"""
                SELECT logdesc, level, action, msg, classification,
                       log_date::text AS log_date, log_time
                FROM fortinet_threats
                WHERE source='event'
                  AND collected_at >= NOW() - INTERVAL '{interval}'
                  {df_sql}
                ORDER BY collected_at DESC LIMIT 200
            """, df_param)
            event_records = [dict(r) for r in cur.fetchall()]

            cur.execute(f"""
                SELECT srcip, dstip, hostname, url, catdesc, action, classification,
                       log_date::text AS log_date, log_time
                FROM fortinet_threats
                WHERE source='webfilter'
                  AND collected_at >= NOW() - INTERVAL '{interval}'
                  {df_sql}
                ORDER BY collected_at DESC LIMIT 200
            """, df_param)
            webfilter_records = [dict(r) for r in cur.fetchall()]

            cur.execute(f"""
                SELECT srcip, dstip, action, classification, payload,
                       log_date::text AS log_date, log_time
                FROM fortinet_threats
                WHERE source='ips'
                  AND collected_at >= NOW() - INTERVAL '{interval}'
                  {df_sql}
                ORDER BY collected_at DESC LIMIT 100
            """, df_param)
            ips_records = [dict(r) for r in cur.fetchall()]

            cur.execute(f"""
                SELECT srcip, action, level, msg, classification,
                       log_date::text AS log_date, log_time
                FROM fortinet_threats
                WHERE source='vpn'
                  AND collected_at >= NOW() - INTERVAL '{interval}'
                  {df_sql}
                ORDER BY collected_at DESC LIMIT 100
            """, df_param)
            vpn_records = [dict(r) for r in cur.fetchall()]

            cur.execute(f"""
                SELECT
                    DATE_TRUNC('hour', collected_at) AS hora,
                    COUNT(*) AS total,
                    SUM(CASE WHEN classification = 'suspicious' THEN 1 ELSE 0 END) AS suspicious,
                    SUM(CASE WHEN classification = 'blocked'    THEN 1 ELSE 0 END) AS blocked
                FROM fortinet_threats
                WHERE source = 'traffic'
                  AND collected_at >= NOW() - INTERVAL '{interval}'
                  {df_sql}
                GROUP BY 1
                ORDER BY 1
            """, df_param)
            traffic_over_time = [
                {
                    "hora":       str(r["hora"]),
                    "total":      int(r["total"]),
                    "suspicious": int(r["suspicious"]),
                    "blocked":    int(r["blocked"]),
                }
                for r in cur.fetchall()
            ]

    def top_counter(records, key, limit=8):
        c = Counter(str(r.get(key) or '') for r in records if r.get(key))
        return [{"value": k, "count": v} for k, v in c.most_common(limit)]

    tc = counts.get("traffic", {})
    ec = counts.get("event", {})
    wc = counts.get("webfilter", {})

    return {
        "generated_at": now_str(),
        "period_hours": hours,
        "period_label": "Últimas 24 horas" if hours == 24 else "Últimos 7 días",
        "summary": {
            "total_traffic":      sum(tc.values()),
            "suspicious_traffic": tc.get("suspicious", 0),
            "blocked_traffic":    tc.get("blocked", 0),
            "total_events":       sum(ec.values()),
            "login_failures":     ec.get("login_failure", 0),
            "critical_events":    ec.get("critical", 0),
            "total_webfilter":    sum(wc.values()),
            "blocked_webfilter":  wc.get("blocked", 0),
            "total_ips":          sum(counts.get("ips", {}).values()),
            "total_vpn":          sum(counts.get("vpn", {}).values()),
        },
        "traffic": {
            "records":   traffic_records,
            "over_time": traffic_over_time,
            "summary": {
                "total":      sum(tc.values()),
                "suspicious": tc.get("suspicious", 0),
                "blocked":    tc.get("blocked", 0),
                "normal":     tc.get("normal", 0),
                "top_dstcountry": top_counter(traffic_records, "dstcountry"),
                "top_app":        top_counter(traffic_records, "app"),
                "top_srcip":      top_counter(traffic_records, "srcip"),
                "top_action":     top_counter(traffic_records, "action", 5),
            },
        },
        "events": {
            "records":        event_records,
            "login_failures": [r for r in event_records if r["classification"] == "login_failure"],
            "critical":       [r for r in event_records if r["classification"] == "critical"],
            "summary": {
                "total":          sum(ec.values()),
                "login_failures": ec.get("login_failure", 0),
                "critical":       ec.get("critical", 0),
                "top_logdesc":    top_counter(event_records, "logdesc"),
            },
        },
        "webfilter": {
            "records": webfilter_records,
            "summary": {
                "total":      sum(wc.values()),
                "blocked":    wc.get("blocked", 0),
                "suspicious": wc.get("suspicious", 0),
                "allowed":    wc.get("allowed", 0),
                "top_catdesc":  top_counter(webfilter_records, "catdesc"),
                "top_hostname": top_counter(webfilter_records, "hostname"),
            },
        },
        "ips": {
            "records": ips_records,
            "summary": {"total": len(ips_records)},
        },
        "vpn": {
            "records": vpn_records,
            "summary": {"total": len(vpn_records)},
        },
    }


def refresh_fortinet_threats():
    while True:
        try:
            # Global (todos los dispositivos)
            data_24h = build_fortinet_threats_data(hours=24)
            (BASE_DIR / "fortinet_threats_data.json").write_text(
                json.dumps(data_24h, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
            )
            data_7d = build_fortinet_threats_data(hours=168)
            (BASE_DIR / "fortinet_threats_data_7d.json").write_text(
                json.dumps(data_7d, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
            )
            total = data_24h["summary"]["total_traffic"]
            susp  = data_24h["summary"]["suspicious_traffic"]
            print(f"[fortinet-threats] OK — 24h: traffic={total}, suspicious={susp} | {now_str()}")

            # Por dispositivo
            for device_name in get_active_fortinet_devices():
                safe = device_name.lower().replace(" ", "_").replace("-", "_")
                try:
                    d24 = build_fortinet_threats_data(hours=24,  device_name=device_name)
                    d7d = build_fortinet_threats_data(hours=168, device_name=device_name)
                    (BASE_DIR / f"fortinet_threats_data_{safe}.json").write_text(
                        json.dumps(d24, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
                    )
                    (BASE_DIR / f"fortinet_threats_data_{safe}_7d.json").write_text(
                        json.dumps(d7d, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
                    )
                    dev_total = d24["summary"]["total_traffic"]
                    dev_susp  = d24["summary"]["suspicious_traffic"]
                    with _status_lock:
                        MODULE_STATUS[f"fortinet_threats_{safe}"] = {
                            "last_update":   now_str(),
                            "status":        "ok",
                            "records":       dev_total,
                            "health":        {"suspicious": dev_susp, "total": dev_total},
                            "device_name":   device_name,
                            "dashboard_url": f"fortinet_threats_dashboard.html?device={safe}",
                        }
                except Exception as dev_e:
                    print(f"[fortinet-threats] ERROR dispositivo {device_name}: {dev_e}")
                    with _status_lock:
                        MODULE_STATUS[f"fortinet_threats_{safe}"] = {
                            "last_update":   now_str(),
                            "status":        "error",
                            "records":       0,
                            "health":        {},
                            "device_name":   device_name,
                            "dashboard_url": f"fortinet_threats_dashboard.html?device={safe}",
                        }
        except Exception as e:
            print(f"[fortinet-threats] ERROR: {e}")
        time.sleep(DASHBOARD_REFRESH["fortinet_threats"])


def cleanup_fortinet_threats():
    """Borra registros de fortinet_threats con más de 1 año. Corre cada 24 horas."""
    while True:
        try:
            with db_connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        DELETE FROM fortinet_threats
                        WHERE collected_at < NOW() - INTERVAL '1 year'
                    """)
                    deleted = cur.rowcount
                conn.commit()
            if deleted > 0:
                print(f"[forti-cleanup] Eliminados {deleted} registros > 1 año | {now_str()}")
        except Exception as e:
            print(f"[forti-cleanup] ERROR: {e}")
        time.sleep(86400)


# =============================================================================
# SNYK
# =============================================================================
def build_snyk_health() -> dict:
    with db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT LOWER(COALESCE(severity,'unknown')) AS sev, COUNT(*) AS n
                FROM snyk_findings GROUP BY 1
            """)
            rows   = cur.fetchall()
            counts = {r["sev"]: int(r["n"]) for r in rows}
            cur.execute("SELECT COUNT(*) AS n FROM snyk_findings")
            total = cur.fetchone()["n"]
    return {
        "critical": counts.get("critical", 0),
        "high":     counts.get("high", 0),
        "medium":   counts.get("medium", 0),
        "low":      counts.get("low", 0),
        "total":    int(total),
    }


def refresh_snyk():
    while True:
        try:
            sys.path.insert(0, str(BASE_DIR.parent))
            from dashboard.run_snyk_dashboard import build_dashboard_data as snyk_build
            snyk_build()
            health = build_snyk_health()
            update_status("snyk", "ok", health["total"], health)
            print(f"[snyk] OK — total={health['total']}, critical={health['critical']} | {now_str()}")
        except Exception as e:
            update_status("snyk", "error")
            print(f"[snyk] ERROR: {e}")
        time.sleep(DASHBOARD_REFRESH["snyk"])


# =============================================================================
# CPANEL / WHM
# =============================================================================
def build_cpanel_health() -> dict:
    with db_connect() as conn:
        with conn.cursor() as cur:
            # Último stat registrado
            cur.execute("""
                SELECT cpu_load_1, cpu_load_5, cpu_load_15, mail_queue, hostname, version
                FROM cpanel_server_stats ORDER BY collected_at DESC LIMIT 1
            """)
            stat = cur.fetchone() or {}

            # Cuentas suspendidas (último snapshot de accounts)
            cur.execute("""
                SELECT COUNT(*) AS n FROM cpanel_accounts
                WHERE suspended = TRUE
                AND collected_at = (SELECT MAX(collected_at) FROM cpanel_accounts)
            """)
            suspended = int((cur.fetchone() or {}).get("n", 0))

            # Total de cuentas
            cur.execute("""
                SELECT COUNT(*) AS n FROM cpanel_accounts
                WHERE collected_at = (SELECT MAX(collected_at) FROM cpanel_accounts)
            """)
            total_accts = int((cur.fetchone() or {}).get("n", 0))

            # Bandwidth del mes (último stat)
            cur.execute("""
                SELECT payload->'bandwidth'->'data'->>'totalused' AS bw
                FROM cpanel_server_stats ORDER BY collected_at DESC LIMIT 1
            """)
            bw_row = cur.fetchone() or {}
            bw_bytes = int(bw_row.get("bw") or 0)
            bw_gb = round(bw_bytes / 1_073_741_824, 2) if bw_bytes else None

    return {
        "cpu_load_1":   float(stat.get("cpu_load_1") or 0),
        "cpu_load_5":   float(stat.get("cpu_load_5") or 0),
        "cpu_load_15":  float(stat.get("cpu_load_15") or 0),
        "mail_queue":   stat.get("mail_queue"),
        "suspended":    suspended,
        "total_accts":  total_accts,
        "bw_gb":        bw_gb,
        "hostname":     stat.get("hostname"),
        "version":      stat.get("version"),
    }


def build_cpanel_dashboard_data() -> dict:
    with db_connect() as conn:
        with conn.cursor() as cur:
            # Último stat
            cur.execute("""
                SELECT cpu_load_1, cpu_load_5, cpu_load_15, hostname, version,
                       mail_queue, collected_at,
                       payload->'bandwidth'->'data'->>'totalused' AS bw_bytes,
                       payload->'bandwidth'->'data'->'acct'       AS bw_accts
                FROM cpanel_server_stats ORDER BY collected_at DESC LIMIT 1
            """)
            stat = cur.fetchone() or {}

            # Bandwidth por dominio (del último stat)
            bw_bytes = int(stat.get("bw_bytes") or 0)
            bw_accts = stat.get("bw_accts") or []
            bw_domains = []
            for acct in (bw_accts if isinstance(bw_accts, list) else []):
                for domain_entry in (acct.get("bwusage") or []):
                    usage = int(domain_entry.get("usage") or 0)
                    if usage > 0:
                        bw_domains.append({
                            "domain": domain_entry.get("domain"),
                            "gb":     round(usage / 1_073_741_824, 3),
                            "mb":     round(usage / 1_048_576, 1),
                        })
            bw_domains.sort(key=lambda x: x["gb"], reverse=True)

            # Resumen de eventos mail últimas 24h
            cur.execute("""
                SELECT event_type, COUNT(*) AS n
                FROM cpanel_mail_events
                WHERE event_time >= NOW() - INTERVAL '24 hours'
                GROUP BY event_type
            """)
            event_counts = {r["event_type"]: int(r["n"]) for r in cur.fetchall()}

            # Tendencia por hora últimas 24h
            cur.execute("""
                SELECT date_trunc('hour', event_time) AS hour,
                       event_type, COUNT(*) AS n
                FROM cpanel_mail_events
                WHERE event_time >= NOW() - INTERVAL '24 hours'
                GROUP BY 1, 2 ORDER BY 1
            """)
            hourly_raw = cur.fetchall()
            hourly: dict = {}
            for r in hourly_raw:
                h = str(r["hour"])[:16] if r["hour"] else "?"
                if h not in hourly:
                    hourly[h] = {}
                hourly[h][r["event_type"]] = int(r["n"])
            hourly_list = [{"hour": h, **v} for h, v in sorted(hourly.items())]

            # Top IPs rechazadas (últimas 24h)
            cur.execute("""
                SELECT remote_ip, COUNT(*) AS n,
                       MAX(reject_reason) AS reason
                FROM cpanel_mail_events
                WHERE event_type IN ('rejected','connection_rejected')
                  AND event_time >= NOW() - INTERVAL '24 hours'
                  AND remote_ip IS NOT NULL
                GROUP BY remote_ip ORDER BY n DESC LIMIT 20
            """)
            top_rejected_ips = [dict(r) for r in cur.fetchall()]

            # Top spam senders (últimas 24h)
            cur.execute("""
                SELECT sender, COUNT(*) AS n,
                       ROUND(AVG(spam_score)::numeric, 2) AS avg_score,
                       MAX(spam_score) AS max_score
                FROM cpanel_mail_events
                WHERE event_type = 'spam'
                  AND event_time >= NOW() - INTERVAL '24 hours'
                  AND sender IS NOT NULL
                GROUP BY sender ORDER BY n DESC LIMIT 20
            """)
            top_spam = [dict(r) for r in cur.fetchall()]

            # Detecciones de virus
            cur.execute("""
                SELECT sender, remote_ip, reject_reason, event_time
                FROM cpanel_mail_events
                WHERE event_type = 'virus'
                  AND event_time >= NOW() - INTERVAL '7 days'
                ORDER BY event_time DESC LIMIT 50
            """)
            virus_events = [dict(r) for r in cur.fetchall()]

            # Eventos recientes (últimas 6h)
            cur.execute("""
                SELECT event_time, event_type, sender, recipient,
                       remote_ip, spam_score, reject_reason
                FROM cpanel_mail_events
                WHERE event_time >= NOW() - INTERVAL '6 hours'
                ORDER BY event_time DESC LIMIT 200
            """)
            recent = [dict(r) for r in cur.fetchall()]

            # Cuentas
            cur.execute("""
                SELECT username, domain, plan, suspended, disk_used_mb
                FROM cpanel_accounts
                WHERE collected_at = (SELECT MAX(collected_at) FROM cpanel_accounts)
                ORDER BY disk_used_mb DESC NULLS LAST
            """)
            accounts = [dict(r) for r in cur.fetchall()]

            # Cola de correo (de cpanel_server_stats.mail_queue)
            queue_count = stat.get("mail_queue")

    return {
        "generated_at":    now_str(),
        "server": {
            "hostname":    stat.get("hostname"),
            "version":     stat.get("version"),
            "cpu_load_1":  float(stat.get("cpu_load_1") or 0),
            "cpu_load_5":  float(stat.get("cpu_load_5") or 0),
            "cpu_load_15": float(stat.get("cpu_load_15") or 0),
            "bw_total_gb": round(bw_bytes / 1_073_741_824, 2) if bw_bytes else 0,
            "queue_count": queue_count,
        },
        "summary_24h":     {
            "accepted":            event_counts.get("accepted", 0),
            "delivered":           event_counts.get("delivered", 0),
            "rejected":            event_counts.get("rejected", 0),
            "connection_rejected": event_counts.get("connection_rejected", 0),
            "spam":                event_counts.get("spam", 0),
            "virus":               event_counts.get("virus", 0),
            "bounce":              event_counts.get("bounce", 0),
        },
        "hourly":              hourly_list,
        "top_rejected_ips":    top_rejected_ips,
        "top_spam_senders":    top_spam,
        "virus_events":        virus_events,
        "recent_events":       recent,
        "bandwidth_by_domain": bw_domains,
        "accounts":            accounts,
    }


def refresh_cpanel():
    while True:
        try:
            health = build_cpanel_health()
            update_status("cpanel", "ok", health["total_accts"], health)

            dash_data = build_cpanel_dashboard_data()
            (BASE_DIR / "cpanel_dashboard_data.json").write_text(
                json.dumps(dash_data, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
            print(f"[cpanel] OK — cuentas={health['total_accts']}, suspendidas={health['suspended']}, cpu={health['cpu_load_1']} | {now_str()}")
        except Exception as e:
            update_status("cpanel", "error")
            print(f"[cpanel] ERROR: {e}")
        time.sleep(DASHBOARD_REFRESH["cpanel"])


# =============================================================================
# INDEX STATUS JSON
# =============================================================================
def refresh_index_status():
    while True:
        with _status_lock:
            status_data = dict(MODULE_STATUS)
        status_data["generated_at"] = now_str()
        (BASE_DIR / "soc_status.json").write_text(
            json.dumps(status_data, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
        time.sleep(5)


# =============================================================================
# HTTP SERVER — con API REST para el panel de configuración
# =============================================================================
class SOCHandler(SimpleHTTPRequestHandler):

    def log_message(self, format, *args):
        if args and len(args) >= 2 and str(args[1]).startswith(("4", "5")):
            super().log_message(format, *args)

    def _get_token(self) -> str:
        return self.headers.get("X-SOC-Token", "")

    def _cookie_token(self) -> str:
        for part in self.headers.get("Cookie", "").split(";"):
            part = part.strip()
            if part.startswith("soc_session="):
                return part[len("soc_session="):]
        return ""

    def _is_authenticated(self) -> bool:
        return _check_auth(self._get_token()) or _check_auth(self._cookie_token())

    def _send_json(self, data: dict, status: int = 200, extra_headers: dict | None = None):
        body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if CORS_ORIGIN:
            self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _require_auth(self) -> bool:
        if not self._is_authenticated():
            self._send_json({"ok": False, "error": "No autorizado"}, 401)
            return False
        return True

    def do_OPTIONS(self):
        self.send_response(204)
        if CORS_ORIGIN:
            self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-SOC-Token")
        self.end_headers()

    def do_GET(self):
        if self.path.startswith("/api/"):
            self._handle_api_get()
            return

        path_clean = self.path.split("?")[0].split("#")[0]
        if path_clean not in _PUBLIC_PATHS and not self._is_authenticated():
            self.send_response(302)
            self.send_header("Location", "/config.html")
            self.end_headers()
            return

        super().do_GET()

    def do_POST(self):
        if self.path.startswith("/api/"):
            self._handle_api_post()
        else:
            self.send_response(404)
            self.end_headers()

    def do_PUT(self):
        if self.path.startswith("/api/"):
            self._handle_api_put()
        else:
            self.send_response(404)
            self.end_headers()

    def do_PATCH(self):
        if self.path.startswith("/api/"):
            self._handle_api_patch()
        else:
            self.send_response(404)
            self.end_headers()

    def do_DELETE(self):
        if self.path.startswith("/api/"):
            self._handle_api_delete()
        else:
            self.send_response(404)
            self.end_headers()

    def _handle_api_get(self):
        path = self.path.split("?")[0]

        if path == "/api/config/rules":
            if not self._require_auth():
                return
            try:
                with db_connect() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT * FROM alert_rules ORDER BY created_at DESC")
                        rules = [dict(r) for r in cur.fetchall()]
                self._send_json({"ok": True, "rules": rules})
            except Exception as e:
                self._send_json({"ok": False, "error": str(e)}, 500)

        elif path == "/api/config/alert-log":
            if not self._require_auth():
                return
            try:
                with db_connect() as conn:
                    with conn.cursor() as cur:
                        cur.execute("""
                            SELECT id, rule_name, module, recipients, subject, sent_at, status
                            FROM alert_log ORDER BY sent_at DESC LIMIT 100
                        """)
                        logs = [dict(r) for r in cur.fetchall()]
                self._send_json({"ok": True, "logs": logs})
            except Exception as e:
                self._send_json({"ok": False, "error": str(e)}, 500)

        else:
            self._send_json({"ok": False, "error": "Endpoint no encontrado"}, 404)

    def _handle_api_post(self):
        path = self.path.split("?")[0]

        if path == "/api/config/login":
            body     = self._read_body()
            cfg_user = os.getenv("CONFIG_USER", "")
            cfg_pass = os.getenv("CONFIG_PASSWORD", "")
            if not cfg_user or not cfg_pass:
                self._send_json({"ok": False, "error": "Panel de config deshabilitado — define CONFIG_USER y CONFIG_PASSWORD en .env"}, 503)
                return
            if body.get("username") == cfg_user and body.get("password") == cfg_pass:
                token = _create_session()
                self._send_json({"ok": True, "token": token}, extra_headers={
                    "Set-Cookie": f"soc_session={token}; HttpOnly; SameSite=Strict; Path=/"
                })
            else:
                self._send_json({"ok": False, "error": "Credenciales incorrectas"}, 401)
            return

        if not self._require_auth():
            return

        if path == "/api/config/rules":
            body     = self._read_body()
            required = ["name", "module", "condition_field", "condition_value", "recipients", "subject"]
            if not all(body.get(f) for f in required):
                self._send_json({"ok": False, "error": "Faltan campos requeridos"}, 400)
                return
            try:
                with db_connect() as conn:
                    with conn.cursor() as cur:
                        cur.execute("""
                            INSERT INTO alert_rules
                            (name, module, condition_field, condition_value,
                             condition_type, threshold_count,
                             recipients, subject, cooldown_minutes)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                            RETURNING id
                        """, (
                            body["name"], body["module"],
                            body["condition_field"], body["condition_value"],
                            body.get("condition_type", "match"),
                            int(body.get("threshold_count") or 1),
                            body["recipients"], body["subject"],
                            body.get("cooldown_minutes", 60),
                        ))
                        rule_id = cur.fetchone()["id"]
                    conn.commit()
                self._send_json({"ok": True, "id": rule_id})
            except Exception as e:
                self._send_json({"ok": False, "error": str(e)}, 500)

        elif path == "/api/config/test-smtp":
            try:
                sys.path.insert(0, str(BASE_DIR.parent))
                from app.alerts.engine import send_email, build_email_html
                smtp_user = os.getenv("SMTP_USER", "")
                if not smtp_user:
                    self._send_json({"ok": False, "error": "SMTP no configurado en .env"})
                    return
                html = build_email_html(
                    module="sentinel",
                    rule_name="Test de conexión",
                    alert_type="test",
                    severity="info",
                    source_host="soc-platform",
                    destination="—",
                    description="Este es un correo de prueba del sistema SOC Leviathan.",
                    alert_datetime=now_str(),
                )
                ok = send_email([smtp_user], "[SOC] Prueba de conexión SMTP", html)
                self._send_json({"ok": ok, "error": None if ok else "Error enviando — revisa logs"})
            except Exception as e:
                self._send_json({"ok": False, "error": str(e)}, 500)

        else:
            self._send_json({"ok": False, "error": "Endpoint no encontrado"}, 404)

    def _handle_api_put(self):
        path = self.path.split("?")[0]
        if not self._require_auth():
            return
        if path.startswith("/api/config/rules/"):
            rule_id  = path.split("/")[-1]
            body     = self._read_body()
            required = ["name", "module", "condition_field", "condition_value", "recipients", "subject"]
            if not all(body.get(f) for f in required):
                self._send_json({"ok": False, "error": "Faltan campos requeridos"}, 400)
                return
            try:
                with db_connect() as conn:
                    with conn.cursor() as cur:
                        cur.execute("""
                            UPDATE alert_rules SET
                                name             = %s,
                                module           = %s,
                                condition_field  = %s,
                                condition_value  = %s,
                                condition_type   = %s,
                                threshold_count  = %s,
                                recipients       = %s,
                                subject          = %s,
                                cooldown_minutes = %s,
                                updated_at       = NOW()
                            WHERE id = %s
                        """, (
                            body["name"], body["module"],
                            body["condition_field"], body["condition_value"],
                            body.get("condition_type", "match"),
                            int(body.get("threshold_count") or 1),
                            body["recipients"], body["subject"],
                            int(body.get("cooldown_minutes") or 60),
                            rule_id,
                        ))
                        if cur.rowcount == 0:
                            self._send_json({"ok": False, "error": "Regla no encontrada"}, 404)
                            return
                    conn.commit()
                self._send_json({"ok": True})
            except Exception as e:
                self._send_json({"ok": False, "error": str(e)}, 500)
        else:
            self._send_json({"ok": False, "error": "Endpoint no encontrado"}, 404)

    def _handle_api_patch(self):
        path = self.path.split("?")[0]
        if not self._require_auth():
            return
        if path.startswith("/api/config/rules/"):
            rule_id = path.split("/")[-1]
            body    = self._read_body()
            try:
                with db_connect() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE alert_rules SET enabled = %s, updated_at = NOW() WHERE id = %s",
                            (body.get("enabled", True), rule_id)
                        )
                    conn.commit()
                self._send_json({"ok": True})
            except Exception as e:
                self._send_json({"ok": False, "error": str(e)}, 500)
        else:
            self._send_json({"ok": False, "error": "Endpoint no encontrado"}, 404)

    def _handle_api_delete(self):
        path = self.path.split("?")[0]
        if not self._require_auth():
            return
        if path.startswith("/api/config/rules/"):
            rule_id = path.split("/")[-1]
            try:
                with db_connect() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM alert_rules WHERE id = %s", (rule_id,))
                    conn.commit()
                self._send_json({"ok": True})
            except Exception as e:
                self._send_json({"ok": False, "error": str(e)}, 500)
        else:
            self._send_json({"ok": False, "error": "Endpoint no encontrado"}, 404)


def start_http_server():
    import ssl as _ssl
    os.chdir(BASE_DIR)
    server = ThreadingHTTPServer((HTTP_HOST, HTTP_PORT), SOCHandler)

    ssl_cert = os.getenv("SSL_CERT_FILE", "")
    ssl_key  = os.getenv("SSL_KEY_FILE", "")
    scheme   = "http"

    if ssl_cert and ssl_key:
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(ssl_cert, ssl_key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    else:
        print("[server] ADVERTENCIA: HTTPS no configurado. Define SSL_CERT_FILE y SSL_KEY_FILE en .env para habilitar TLS.")

    print(f"[server] Escuchando en {scheme}://{HTTP_HOST}:{HTTP_PORT}")
    server.serve_forever()


# =============================================================================
# MOTOR DE ALERTAS
# =============================================================================
def run_alert_engine():
    """Evalúa reglas de alerta cada 5 minutos y envía emails si aplica."""
    time.sleep(30)
    while True:
        try:
            sys.path.insert(0, str(BASE_DIR.parent))
            from app.alerts.engine import evaluate_and_send
            sent = evaluate_and_send()
            if sent > 0:
                print(f"[alerts] {sent} alerta(s) enviada(s) | {now_str()}")
        except Exception as e:
            print(f"[alerts] ERROR: {e}")
        time.sleep(300)


# =============================================================================
# MAIN
# =============================================================================
def main():
    print("=" * 60)
    print("  SOC Platform — Dashboard Server")
    print("=" * 60)
    print(f"  Puerto:    {HTTP_PORT}")
    print(f"  DB:        {DB_HOST}:{DB_PORT}/{DB_NAME}")
    print(f"  Sentinel:  refresh cada {DASHBOARD_REFRESH['sentinel']}s")
    print(f"  Nmap:      refresh cada {DASHBOARD_REFRESH['nmap']}s")
    print(f"  Fortinet:  refresh cada {DASHBOARD_REFRESH['fortinet']}s")
    print(f"  Forti-T:   refresh cada {DASHBOARD_REFRESH['fortinet_threats']}s")
    print(f"  Snyk:      refresh cada {DASHBOARD_REFRESH['snyk']}s")
    print("=" * 60)

    print("[init] Generando snapshots iniciales...")
    for name in ["sentinel", "nmap", "fortinet_threats"]:
        try:
            if name == "sentinel":
                data   = build_sentinel_data()
                health = data.pop("_health", {})
                (BASE_DIR / "sentinel_dashboard_data.json").write_text(
                    json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
                )
                update_status("sentinel", "ok", data["summary"]["total_incidents"], health)
            elif name == "nmap":
                data   = build_nmap_data()
                health = data.pop("_health", {})
                template = (BASE_DIR / "nmap_dashboard.html").read_text(encoding="utf-8")
                html = template.replace("{{DATA}}", json.dumps(data, ensure_ascii=False, default=str))
                (BASE_DIR / "nmap_dashboard_output.html").write_text(html, encoding="utf-8")
                update_status("nmap", "ok", data["kpis"]["assets"], health)
            elif name == "fortinet_threats":
                data = build_fortinet_threats_data()
                (BASE_DIR / "fortinet_threats_data.json").write_text(
                    json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
                )
            print(f"  [OK] {name}")
        except Exception as e:
            if name not in ("fortinet_threats",):
                update_status(name, "error")
            print(f"  [WARN] {name}: {e}")

    threads = [
        threading.Thread(target=refresh_sentinel,         daemon=True, name="sentinel"),
        threading.Thread(target=refresh_nmap,             daemon=True, name="nmap"),
        threading.Thread(target=refresh_fortinet,         daemon=True, name="fortinet"),
        threading.Thread(target=refresh_fortinet_threats, daemon=True, name="fortinet-threats"),
        threading.Thread(target=cleanup_fortinet_threats, daemon=True, name="forti-cleanup"),
        threading.Thread(target=refresh_snyk,             daemon=True, name="snyk"),
        threading.Thread(target=refresh_cpanel,           daemon=True, name="cpanel"),
        threading.Thread(target=refresh_index_status,     daemon=True, name="index-status"),
        threading.Thread(target=run_alert_engine,         daemon=True, name="alert-engine"),
        threading.Thread(target=start_http_server,        daemon=True, name="http"),
    ]

    for t in threads:
        t.start()
        print(f"[thread] {t.name} iniciado")

    _scheme = "https" if (os.getenv("SSL_CERT_FILE") and os.getenv("SSL_KEY_FILE")) else "http"
    print(f"\n[OK] Portal disponible en: {_scheme}://localhost:{HTTP_PORT}/index.html")
    print(f"[OK] Config panel en:       {_scheme}://localhost:{HTTP_PORT}/config.html")
    if not os.getenv("CONFIG_USER") or not os.getenv("CONFIG_PASSWORD"):
        print("[WARN] CONFIG_USER y CONFIG_PASSWORD no definidos — panel de config DESHABILITADO")
    print("[OK] Ctrl+C para salir\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Cerrando servidor...")


if __name__ == "__main__":
    main()

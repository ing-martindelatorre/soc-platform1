#!/usr/bin/env python3
"""
dashboard/server.py

Servidor único del SOC Platform.
- Sirve todos los dashboards en un solo puerto (8888)
- Regenera cada dashboard según su frecuencia configurada
- Publica soc_status.json con datos de salud para el semáforo del index
"""

import json
import os
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

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
DB_PORT = int(os.getenv("DB_PORT", "5433"))
DB_NAME = os.getenv("DB_NAME", "soc_db")
DB_USER = os.getenv("DB_USER", "soc_user")
DB_PASS = os.getenv("DB_PASSWORD", "")

HTTP_HOST = os.getenv("DASHBOARD_HOST", "0.0.0.0")
HTTP_PORT = int(os.getenv("DASHBOARD_PORT", "8888"))

BASE_DIR = Path(__file__).resolve().parent

DASHBOARD_REFRESH = {
    "sentinel":        int(os.getenv("DASH_REFRESH_SENTINEL",        "30")),
    "nmap":            int(os.getenv("DASH_REFRESH_NMAP",            "300")),
    "fortinet":        int(os.getenv("DASH_REFRESH_FORTINET",        "60")),
    "fortinet_threats":int(os.getenv("DASH_REFRESH_FORTINET_THREATS","120")),
    "snyk":            int(os.getenv("DASH_REFRESH_SNYK",            "300")),
}

# =============================================================================
# Estado global
# =============================================================================
MODULE_STATUS: dict[str, dict] = {
    "sentinel": {"last_update": None, "status": "pending", "records": 0, "health": {}},
    "nmap":     {"last_update": None, "status": "pending", "records": 0, "health": {}},
    "fortinet": {"last_update": None, "status": "pending", "records": 0, "health": {}},
    "snyk":     {"last_update": None, "status": "pending", "records": 0, "health": {}},
}
_status_lock = threading.Lock()


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
            from dashboard.run_fortinet_dashboard import (
                get_conn, fetch_latest_sections, build_html
            )
            device_name = os.getenv("FORTI_DEVICE_NAME")
            conn = get_conn()
            try:
                chosen_device, sections, errors = fetch_latest_sections(conn, device_name)
            finally:
                conn.close()
            html = build_html(chosen_device, sections, errors)
            (BASE_DIR / "fortinet_dashboard_output.html").write_text(html, encoding="utf-8")

            policies   = len(sections.get("firewall_policies", {}).get("results", []))
            interfaces = len(sections.get("interfaces", {}).get("results", []))

            with db_connect() as dbconn:
                with dbconn.cursor() as cur:
                    cur.execute("SELECT COUNT(*) AS n FROM fortinet_raw_snapshots")
                    snaps = cur.fetchone()["n"]

            health = {"snapshots": int(snaps), "policies": policies, "interfaces": interfaces}
            update_status("fortinet", "ok", int(snaps), health)
            print(f"[fortinet] OK — snaps={snaps}, policies={policies} | {now_str()}")
        except Exception as e:
            update_status("fortinet", "error")
            print(f"[fortinet] ERROR: {e}")
        time.sleep(DASHBOARD_REFRESH["fortinet"])


# =============================================================================
# FORTINET THREATS
# =============================================================================
def build_fortinet_threats_data() -> dict:
    """Lee datos de amenazas de fortinet_threats y genera el JSON para el dashboard."""
    with db_connect() as conn:
        with conn.cursor() as cur:
            # Summary
            cur.execute("""
                SELECT source, classification, COUNT(*) AS n
                FROM fortinet_threats
                GROUP BY source, classification
            """)
            rows = cur.fetchall()

            counts: dict = {}
            for r in rows:
                src = r["source"]
                cls = r["classification"]
                n   = int(r["n"])
                if src not in counts:
                    counts[src] = {}
                counts[src][cls] = n

            # Tráfico
            cur.execute("""
                SELECT srcip, srcname, dstip, dstport, dstcountry,
                       action, app, apprisk, service, policyname,
                       sentbyte, rcvdbyte, classification,
                       log_date::text AS log_date, log_time
                FROM fortinet_threats WHERE source='traffic'
                ORDER BY collected_at DESC LIMIT 200
            """)
            traffic_records = [dict(r) for r in cur.fetchall()]

            # Eventos
            cur.execute("""
                SELECT logdesc, level, action, msg, classification,
                       log_date::text AS log_date, log_time
                FROM fortinet_threats WHERE source='event'
                ORDER BY collected_at DESC LIMIT 200
            """)
            event_records = [dict(r) for r in cur.fetchall()]

            # Webfilter
            cur.execute("""
                SELECT srcip, dstip, hostname, url, catdesc, action, classification,
                       log_date::text AS log_date, log_time
                FROM fortinet_threats WHERE source='webfilter'
                ORDER BY collected_at DESC LIMIT 200
            """)
            webfilter_records = [dict(r) for r in cur.fetchall()]

            # IPS
            cur.execute("""
                SELECT srcip, dstip, action, classification, payload,
                       log_date::text AS log_date, log_time
                FROM fortinet_threats WHERE source='ips'
                ORDER BY collected_at DESC LIMIT 100
            """)
            ips_records = [dict(r) for r in cur.fetchall()]

            # VPN
            cur.execute("""
                SELECT srcip, action, level, msg, classification,
                       log_date::text AS log_date, log_time
                FROM fortinet_threats WHERE source='vpn'
                ORDER BY collected_at DESC LIMIT 100
            """)
            vpn_records = [dict(r) for r in cur.fetchall()]

    def top_counter(records, key, limit=8):
        c = Counter(str(r.get(key) or '') for r in records if r.get(key))
        return [{"value": k, "count": v} for k, v in c.most_common(limit)]

    tc = counts.get("traffic", {})
    ec = counts.get("event", {})
    wc = counts.get("webfilter", {})

    return {
        "generated_at": now_str(),
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
            "records": traffic_records,
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
            data = build_fortinet_threats_data()
            (BASE_DIR / "fortinet_threats_data.json").write_text(
                json.dumps(data, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8"
            )
            total = data["summary"]["total_traffic"]
            susp  = data["summary"]["suspicious_traffic"]
            print(f"[fortinet-threats] OK — traffic={total}, suspicious={susp} | {now_str()}")
        except Exception as e:
            print(f"[fortinet-threats] ERROR: {e}")
        time.sleep(DASHBOARD_REFRESH["fortinet_threats"])


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
# HTTP SERVER
# =============================================================================
class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        if args and len(args) >= 2 and str(args[1]).startswith(("4", "5")):
            super().log_message(format, *args)


def start_http_server():
    os.chdir(BASE_DIR)
    server = ThreadingHTTPServer((HTTP_HOST, HTTP_PORT), QuietHandler)
    print(f"[server] Escuchando en http://{HTTP_HOST}:{HTTP_PORT}")
    server.serve_forever()


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
        threading.Thread(target=refresh_snyk,             daemon=True, name="snyk"),
        threading.Thread(target=refresh_index_status,     daemon=True, name="index-status"),
        threading.Thread(target=start_http_server,        daemon=True, name="http"),
    ]

    for t in threads:
        t.start()
        print(f"[thread] {t.name} iniciado")

    print(f"\n[OK] Portal disponible en: http://localhost:{HTTP_PORT}/index.html")
    print("[OK] Ctrl+C para salir\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Cerrando servidor...")


if __name__ == "__main__":
    main()

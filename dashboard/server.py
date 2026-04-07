#!/usr/bin/env python3
"""
dashboard/server.py

Servidor único del SOC Platform.
- Sirve todos los dashboards en un solo puerto (8888)
- Regenera cada dashboard según su frecuencia configurada
- Actualiza el index con el estado de cada módulo en tiempo real

Uso:
    cd ~/soc-platform
    source venv/bin/activate
    set -a; source .env; set +a
    python3 dashboard/server.py
"""

import json
import os
import sys
import threading
import time
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

# =============================================================================
# Frecuencias de regeneración de cada dashboard (segundos)
# Independiente de la frecuencia de recolección del scheduler
# =============================================================================
DASHBOARD_REFRESH = {
    "sentinel": int(os.getenv("DASH_REFRESH_SENTINEL", "30")),   # 30 seg
    "nmap":     int(os.getenv("DASH_REFRESH_NMAP",     "300")),  # 5 min
    "fortinet": int(os.getenv("DASH_REFRESH_FORTINET", "60")),   # 1 min
    "snyk":     int(os.getenv("DASH_REFRESH_SNYK",     "300")),  # 5 min
}

# =============================================================================
# Estado global de cada módulo (para el index)
# =============================================================================
MODULE_STATUS: dict[str, dict] = {
    "sentinel": {"last_update": None, "status": "pending", "records": 0},
    "nmap":     {"last_update": None, "status": "pending", "records": 0},
    "fortinet": {"last_update": None, "status": "pending", "records": 0},
    "snyk":     {"last_update": None, "status": "pending", "records": 0},
}
_status_lock = threading.Lock()


def db_connect():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        cursor_factory=RealDictCursor,
    )


def now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def update_status(module: str, status: str, records: int = 0):
    with _status_lock:
        MODULE_STATUS[module] = {
            "last_update": now_str(),
            "status": status,
            "records": records,
        }


# =============================================================================
# SENTINEL DASHBOARD
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
                FROM sentinel_incidents
                GROUP BY 1 ORDER BY 2 DESC
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
    }


def refresh_sentinel():
    while True:
        try:
            data = build_sentinel_data()
            json_path = BASE_DIR / "sentinel_dashboard_data.json"
            json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
            update_status("sentinel", "ok", data["summary"]["total_incidents"])
            print(f"[sentinel] OK — {data['summary']['total_incidents']} incidentes | {now_str()}")
        except Exception as e:
            update_status("sentinel", "error")
            print(f"[sentinel] ERROR: {e}")
        time.sleep(DASHBOARD_REFRESH["sentinel"])


# =============================================================================
# NMAP DASHBOARD
# =============================================================================
def build_nmap_data() -> dict:
    from collections import Counter
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
        "summary": {
            "text": (
                f"Se detectaron {len(assets)} activos, {len(services)} servicios "
                f"y {len(findings)} hallazgos. "
                f"Altos: {sev_counter.get('high', 0)}. "
                f"Medios: {sev_counter.get('medium', 0)}."
            )
        },
    }


def refresh_nmap():
    while True:
        try:
            data = build_nmap_data()
            # Genera el HTML con los datos incrustados
            template = (BASE_DIR / "nmap_dashboard.html").read_text(encoding="utf-8")
            html = template.replace("{{DATA}}", json.dumps(data, ensure_ascii=False, default=str))
            (BASE_DIR / "nmap_dashboard_output.html").write_text(html, encoding="utf-8")
            update_status("nmap", "ok", data["kpis"]["assets"])
            print(f"[nmap] OK — {data['kpis']['assets']} activos, {data['kpis']['findings']} hallazgos | {now_str()}")
        except Exception as e:
            update_status("nmap", "error")
            print(f"[nmap] ERROR: {e}")
        time.sleep(DASHBOARD_REFRESH["nmap"])


# =============================================================================
# FORTINET DASHBOARD
# =============================================================================
def refresh_fortinet():
    while True:
        try:
            # Importa y llama al generador existente de fortinet
            sys.path.insert(0, str(BASE_DIR.parent))
            from dashboard.run_fortinet_dashboard import main as fortinet_main
            fortinet_main()
            update_status("fortinet", "ok")
            print(f"[fortinet] OK | {now_str()}")
        except Exception as e:
            update_status("fortinet", "error")
            print(f"[fortinet] ERROR: {e}")
        time.sleep(DASHBOARD_REFRESH["fortinet"])


# =============================================================================
# SNYK DASHBOARD
# =============================================================================
def refresh_snyk():
    while True:
        try:
            sys.path.insert(0, str(BASE_DIR.parent))
            from dashboard.run_snyk_dashboard import build_dashboard_data as snyk_build
            snyk_build()
            update_status("snyk", "ok")
            print(f"[snyk] OK | {now_str()}")
        except Exception as e:
            update_status("snyk", "error")
            print(f"[snyk] ERROR: {e}")
        time.sleep(DASHBOARD_REFRESH["snyk"])

# =============================================================================
# INDEX STATUS JSON
# Actualiza un JSON que el index.html consume para mostrar estado en vivo
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
    """Handler que suprime logs de cada request para no ensuciar la consola."""
    def log_message(self, format, *args):
        # Solo loguear errores (4xx, 5xx)
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
    print(f"  Snyk:      refresh cada {DASHBOARD_REFRESH['snyk']}s")
    print("=" * 60)

    # Snapshot inicial de todos los módulos
    print("[init] Generando snapshots iniciales...")
    for name, fn in [("sentinel", refresh_sentinel), ("nmap", refresh_nmap)]:
        try:
            if name == "sentinel":
                data = build_sentinel_data()
                json_path = BASE_DIR / "sentinel_dashboard_data.json"
                json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
                update_status("sentinel", "ok", data["summary"]["total_incidents"])
            elif name == "nmap":
                data = build_nmap_data()
                template = (BASE_DIR / "nmap_dashboard.html").read_text(encoding="utf-8")
                html = template.replace("{{DATA}}", json.dumps(data, ensure_ascii=False, default=str))
                (BASE_DIR / "nmap_dashboard_output.html").write_text(html, encoding="utf-8")
                update_status("nmap", "ok", data["kpis"]["assets"])
            print(f"  [OK] {name}")
        except Exception as e:
            update_status(name, "error")
            print(f"  [WARN] {name}: {e}")

    # Hilos de refresh por módulo
    threads = [
        threading.Thread(target=refresh_sentinel,    daemon=True, name="sentinel"),
        threading.Thread(target=refresh_nmap,        daemon=True, name="nmap"),
        threading.Thread(target=refresh_fortinet,    daemon=True, name="fortinet"),
        threading.Thread(target=refresh_snyk,        daemon=True, name="snyk"),
        threading.Thread(target=refresh_index_status, daemon=True, name="index-status"),
        threading.Thread(target=start_http_server,   daemon=True, name="http"),
    ]

    for t in threads:
        t.start()
        print(f"[thread] {t.name} iniciado")

    print(f"\n[OK] Dashboard disponible en: http://192.168.0.102:{HTTP_PORT}/index.html")
    print("[OK] Ctrl+C para salir\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Cerrando servidor...")


if __name__ == "__main__":
    main()

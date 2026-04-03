#!/usr/bin/env python3
import json
import os
import sys
import threading
import time
import webbrowser
from datetime import datetime
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:
    print("[ERROR] Falta psycopg2-binary")
    print("Instálalo con: pip install psycopg2-binary")
    sys.exit(1)


# =========================
# CONFIG
# =========================
DB_HOST = os.getenv("SOC_DB_HOST") or os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("SOC_DB_PORT") or os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("SOC_DB_NAME") or os.getenv("DB_NAME", "soc")
DB_USER = os.getenv("SOC_DB_USER") or os.getenv("DB_USER", "soc_user")
DB_PASS = os.getenv("SOC_DB_PASS") or os.getenv("DB_PASSWORD", "soc_pass_local")

HTTP_HOST = os.getenv("DASHBOARD_HOST", "127.0.0.1")
HTTP_PORT = int(os.getenv("DASHBOARD_PORT", "8000"))

REFRESH_SECONDS = int(os.getenv("DASHBOARD_REFRESH_SECONDS", "30"))

BASE_DIR = Path(__file__).resolve().parent
HTML_FILE = BASE_DIR / "sentinel_dashboard_simple.html"
JSON_FILE = BASE_DIR / "sentinel_dashboard_data.json"

TABLE = "sentinel_incidents"


def db_connect():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
    )


def fetch_one(cur, query, params=None, default=0):
    cur.execute(query, params or ())
    row = cur.fetchone()
    if not row:
        return default
    if isinstance(row, dict):
        return next(iter(row.values()))
    return row[0]


def fetch_all(cur, query, params=None):
    cur.execute(query, params or ())
    return cur.fetchall()


def write_json(data):
    JSON_FILE.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    print(f"[OK] JSON actualizado: {JSON_FILE} | {data['generated_at']}")


def start_http_server():
    os.chdir(BASE_DIR)
    server = ThreadingHTTPServer((HTTP_HOST, HTTP_PORT), SimpleHTTPRequestHandler)
    print(f"[OK] Servidor HTTP: http://{HTTP_HOST}:{HTTP_PORT}")
    server.serve_forever()


def open_browser():
    url = f"http://{HTTP_HOST}:{HTTP_PORT}/{HTML_FILE.name}"
    print(f"[OK] Dashboard: {url}")
    try:
        webbrowser.open(url)
    except Exception as exc:
        print(f"[WARN] No se pudo abrir navegador automáticamente: {exc}")
        print(f"[INFO] Ábrelo manualmente: {url}")


def build_dashboard_json():
    with db_connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            total_incidents = fetch_one(cur, f"SELECT COUNT(*) FROM {TABLE};")

            resolved_incidents = fetch_one(
                cur,
                f"""
                SELECT COUNT(*)
                FROM {TABLE}
                WHERE LOWER(COALESCE(status, '')) = 'resolved';
                """
            )

            active_incidents = fetch_one(
                cur,
                f"""
                SELECT COUNT(*)
                FROM {TABLE}
                WHERE LOWER(COALESCE(status, '')) NOT IN ('resolved', 'closed', 'mitigated');
                """
            )

            monitored_endpoints = fetch_one(
                cur,
                f"""
                SELECT COUNT(DISTINCT agent_id)
                FROM {TABLE}
                WHERE agent_id IS NOT NULL AND agent_id <> '';
                """
            )

            classification_rows = fetch_all(
                cur,
                f"""
                SELECT COALESCE(classification, 'Unknown') AS classification, COUNT(*) AS count
                FROM {TABLE}
                GROUP BY COALESCE(classification, 'Unknown')
                ORDER BY count DESC;
                """
            )

            classification_counts = [
                {"classification": row["classification"], "count": int(row["count"])}
                for row in classification_rows
            ]

            status_rows = fetch_all(
                cur,
                f"""
                SELECT COALESCE(status, 'unknown') AS status, COUNT(*) AS count
                FROM {TABLE}
                GROUP BY COALESCE(status, 'unknown')
                ORDER BY count DESC;
                """
            )

            status_counts = [
                {"status": str(row["status"]).capitalize(), "count": int(row["count"])}
                for row in status_rows
            ]

            trend_rows = fetch_all(
                cur,
                f"""
                SELECT DATE(created_at) AS day, COUNT(*) AS count
                FROM {TABLE}
                WHERE created_at IS NOT NULL
                GROUP BY DATE(created_at)
                ORDER BY day;
                """
            )

            incidents_over_time = [
                {
                    "date": row["day"].strftime("%Y-%m-%d") if row["day"] else "N/D",
                    "count": int(row["count"]),
                }
                for row in trend_rows
            ]

            recent_rows = fetch_all(
                cur,
                f"""
                SELECT
                    incident_id,
                    COALESCE(threat_name, 'N/D') AS threat_name,
                    COALESCE(classification, 'Unknown') AS classification,
                    COALESCE(severity, 'Unknown') AS severity,
                    COALESCE(status, 'Unknown') AS status,
                    COALESCE(agent_name, 'N/D') AS agent_name,
                    COALESCE(username, 'N/D') AS username,
                    created_at
                FROM {TABLE}
                ORDER BY created_at DESC NULLS LAST
                LIMIT 10;
                """
            )

            recent_incidents = []
            for row in recent_rows:
                recent_incidents.append({
                    "incident_id": row["incident_id"],
                    "endpoint": row["agent_name"],
                    "threat": row["threat_name"],
                    "classification": row["classification"],
                    "severity": row["severity"],
                    "status": str(row["status"]).capitalize(),
                    "username": row["username"],
                    "created_at": row["created_at"].strftime("%Y-%m-%d %H:%M:%S") if row["created_at"] else "N/D"
                })

            endpoint_rows = fetch_all(
                cur,
                f"""
                SELECT COALESCE(agent_name, 'N/D') AS agent_name, COUNT(*) AS count
                FROM {TABLE}
                GROUP BY COALESCE(agent_name, 'N/D')
                ORDER BY count DESC
                LIMIT 10;
                """
            )

            top_endpoints = [
                {"agent_name": row["agent_name"], "count": int(row["count"])}
                for row in endpoint_rows
            ]

            data = {
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "summary": {
                    "monitored_endpoints": int(monitored_endpoints),
                    "total_incidents": int(total_incidents),
                    "resolved_incidents": int(resolved_incidents),
                    "active_incidents": int(active_incidents),
                    "most_common_severity": "malicious",
                },
                "classification_counts": classification_counts,
                "status_counts": status_counts,
                "incidents_over_time": incidents_over_time,
                "recent_incidents": recent_incidents,
                "top_endpoints": top_endpoints
            }

            return data


def refresh_loop():
    while True:
        try:
            print("[*] Consultando base de datos...")
            data = build_dashboard_json()
            print("[*] Generando JSON...")
            write_json(data)
        except Exception as exc:
            print(f"[ERROR] Falló refresh del dashboard: {exc}")

        time.sleep(REFRESH_SECONDS)


def validate_files():
    if not HTML_FILE.exists():
        print(f"[ERROR] No existe el HTML: {HTML_FILE}")
        sys.exit(1)


def main():
    validate_files()

    print("[*] Generando snapshot inicial...")
    data = build_dashboard_json()
    write_json(data)

    print("[*] Levantando servidor HTTP...")
    server_thread = threading.Thread(target=start_http_server, daemon=True)
    server_thread.start()

    print(f"[*] Activando refresh automático cada {REFRESH_SECONDS} segundos...")
    refresh_thread = threading.Thread(target=refresh_loop, daemon=True)
    refresh_thread.start()

    time.sleep(1)
    open_browser()

    print("[*] Dashboard listo. Ctrl+C para salir.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Cerrando...")


if __name__ == "__main__":
    main()
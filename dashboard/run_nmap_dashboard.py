# dashboard/run_nmap_dashboard.py

import json
import os
from collections import Counter

import psycopg2
from dotenv import load_dotenv

load_dotenv()


def get_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        dbname=os.getenv("DB_NAME"),
    )


def fetch_data():
    conn = get_connection()
    cur = conn.cursor()

    # Activos desde nmap_assets
    cur.execute("""
        SELECT
            ip,
            COALESCE(hostname, '') AS hostname,
            COALESCE(os_guess, '') AS os_guess,
            COALESCE(status, '') AS status,
            first_seen,
            last_seen
        FROM nmap_assets
        ORDER BY last_seen DESC
    """)
    assets = cur.fetchall()

    # Servicios desde nmap_services
    cur.execute("""
        SELECT
            a.ip,
            s.port,
            s.protocol,
            COALESCE(s.service_name, '') AS service_name,
            COALESCE(s.product, '') AS product,
            COALESCE(s.version, '') AS version
        FROM nmap_services s
        JOIN nmap_assets a ON s.asset_id = a.id
        ORDER BY s.port
    """)
    services = cur.fetchall()

    # Hallazgos desde nmap_findings
    cur.execute("""
        SELECT
            COALESCE(f.severity, 'info') AS severity,
            COALESCE(f.title, '') AS title,
            COALESCE(f.category, '') AS category,
            COALESCE(f.description, '') AS description,
            COALESCE(f.recommendation, '') AS recommendation,
            COALESCE(f.status, 'open') AS status,
            a.ip
        FROM nmap_findings f
        JOIN nmap_assets a ON f.asset_id = a.id
        ORDER BY f.created_at DESC
    """)
    findings = cur.fetchall()

    cur.close()
    conn.close()

    return assets, services, findings


def build_dashboard_data():
    assets, services, findings = fetch_data()

    severity_counter = Counter((f[0] or "unknown") for f in findings)
    port_counter     = Counter(str(s[1]) for s in services if s[1] is not None)
    service_counter  = Counter((s[3] or "unknown") for s in services)
    category_counter = Counter((f[2] or "unknown") for f in findings)

    risk_score = (
        severity_counter.get("critical", 0) * 10
        + severity_counter.get("high", 0) * 7
        + severity_counter.get("medium", 0) * 4
        + severity_counter.get("low", 0) * 1
    )

    data = {
        "kpis": {
            "assets":    len(assets),
            "services":  len(services),
            "findings":  len(findings),
            "critical":  severity_counter.get("critical", 0),
            "high":      severity_counter.get("high", 0),
            "medium":    severity_counter.get("medium", 0),
            "low":       severity_counter.get("low", 0),
            "risk_score": risk_score,
        },
        "severity":      dict(severity_counter),
        "ports":         dict(port_counter.most_common(10)),
        "services_dist": dict(service_counter.most_common(10)),
        "categories":    dict(category_counter.most_common(10)),
        "assets_table": [
            {
                "ip":       a[0] or "",
                "hostname": a[1] or "",
                "os_guess": a[2] or "",
                "status":   a[3] or "",
                "last_seen": str(a[5]) if a[5] else "",
            }
            for a in assets
        ],
        "services_table": [
            {
                "ip":           s[0] or "",
                "port":         s[1],
                "protocol":     s[2] or "",
                "service_name": s[3] or "",
                "product":      s[4] or "",
                "version":      s[5] or "",
            }
            for s in services
        ],
        "findings_table": [
            {
                "severity":       f[0] or "",
                "title":          f[1] or "",
                "category":       f[2] or "",
                "description":    f[3] or "",
                "recommendation": f[4] or "",
                "status":         f[5] or "",
                "ip":             f[6] or "",
            }
            for f in findings
        ],
        "summary": {
            "text": (
                f"Se detectaron {len(assets)} activos, {len(services)} servicios "
                f"y {len(findings)} hallazgos en el módulo Nmap. "
                f"Hallazgos críticos: {severity_counter.get('critical', 0)}. "
                f"Hallazgos altos: {severity_counter.get('high', 0)}. "
                f"Hallazgos medios: {severity_counter.get('medium', 0)}."
            )
        },
    }

    return data


def generate_html(data, output_file):
    template_path = os.path.join(os.path.dirname(__file__), "nmap_dashboard.html")

    with open(template_path, "r", encoding="utf-8") as f:
        template = f.read()

    html = template.replace("{{DATA}}", json.dumps(data, ensure_ascii=False, default=str))

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[OK] Dashboard generado en {output_file}")


def main():
    output = os.path.join(os.path.dirname(__file__), "nmap_dashboard_output.html")
    data   = build_dashboard_data()
    generate_html(data, output)
    print(f"[INFO] Abre en tu navegador: http://192.168.0.102:8080 o abre el archivo directamente")


if __name__ == "__main__":
    main()
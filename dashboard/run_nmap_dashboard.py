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

    # Activos
    cur.execute("""
        SELECT
            COALESCE(target, asset_name)::text AS ip,
            asset_name AS hostname,
            COALESCE(host_status, '') AS status
        FROM nmap_findings
        ORDER BY target, asset_name
    """)
    assets = cur.fetchall()

    # Servicios
    cur.execute("""
        SELECT
            port,
            protocol,
            service_name,
            product,
            version
        FROM nmap_findings
        WHERE port IS NOT NULL
        ORDER BY port
    """)
    services = cur.fetchall()

    # Hallazgos adaptados al esquema real
    cur.execute("""
        SELECT
            CASE
                WHEN COALESCE(port_state, '') = 'open' THEN 'medium'
                WHEN COALESCE(port_state, '') IN ('filtered', 'open|filtered') THEN 'low'
                WHEN COALESCE(port_state, '') = 'closed' THEN 'info'
                ELSE 'info'
            END AS severity,
            COALESCE(service_name, 'unknown-service') AS title,
            COALESCE(profile_name, 'network') AS category,
            CONCAT(
                'Host ', COALESCE(target, 'N/A'),
                CASE WHEN port IS NOT NULL THEN CONCAT(' puerto ', port::text) ELSE '' END,
                CASE WHEN protocol IS NOT NULL AND protocol <> '' THEN CONCAT('/', protocol) ELSE '' END,
                CASE WHEN port_state IS NOT NULL AND port_state <> '' THEN CONCAT(' estado ', port_state) ELSE '' END,
                CASE WHEN product IS NOT NULL AND product <> '' THEN CONCAT(' producto ', product) ELSE '' END,
                CASE WHEN version IS NOT NULL AND version <> '' THEN CONCAT(' version ', version) ELSE '' END,
                CASE WHEN os_guess IS NOT NULL AND os_guess <> '' THEN CONCAT(' os ', os_guess) ELSE '' END
            ) AS description
        FROM nmap_findings
        ORDER BY created_at DESC
    """)
    findings = cur.fetchall()

    cur.close()
    conn.close()

    return assets, services, findings


def build_dashboard_data():
    assets, services, findings = fetch_data()

    severity_counter = Counter((f[0] or "unknown") for f in findings)
    port_counter = Counter(str(s[0]) for s in services if s[0] is not None)
    service_counter = Counter((s[2] or "unknown") for s in services)
    category_counter = Counter((f[2] or "unknown") for f in findings)

    risk_score = (
            severity_counter.get("critical", 0) * 10
            + severity_counter.get("high", 0) * 7
            + severity_counter.get("medium", 0) * 4
            + severity_counter.get("low", 0) * 1
    )

    top_ports = dict(port_counter.most_common(10))
    top_services = dict(service_counter.most_common(10))
    top_categories = dict(category_counter.most_common(10))

    data = {
        "kpis": {
            "assets": len(assets),
            "services": len(services),
            "findings": len(findings),
            "critical": severity_counter.get("critical", 0),
            "high": severity_counter.get("high", 0),
            "medium": severity_counter.get("medium", 0),
            "low": severity_counter.get("low", 0),
            "risk_score": risk_score,
        },
        "severity": dict(severity_counter),
        "ports": top_ports,
        "services_dist": top_services,
        "categories": top_categories,
        "assets_table": [
            {
                "ip": a[0] or "",
                "hostname": a[1] or "",
                "status": a[2] or "",
            }
            for a in assets
        ],
        "services_table": [
            {
                "port": s[0],
                "protocol": s[1] or "",
                "service_name": s[2] or "",
                "product": s[3] or "",
                "version": s[4] or "",
            }
            for s in services
        ],
        "findings_table": [
            {
                "severity": f[0] or "",
                "title": f[1] or "",
                "category": f[2] or "",
                "description": f[3] or "",
            }
            for f in findings
        ],
        "summary": {
            "text": (
                f"Se detectaron {len(assets)} activos, {len(services)} servicios "
                f"y {len(findings)} hallazgos en el módulo Nmap. "
                f"Hallazgos altos: {severity_counter.get('high', 0)}. "
                f"Hallazgos medios: {severity_counter.get('medium', 0)}."
            )
        }
    }

    return data


def generate_html(data, output_file):
    with open("dashboard/nmap_dashboard.html", "r", encoding="utf-8") as f:
        template = f.read()

    html = template.replace("{{DATA}}", json.dumps(data, ensure_ascii=False))

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[OK] Dashboard generado en {output_file}")


def main():
    output = "dashboard/nmap_dashboard_output.html"
    data = build_dashboard_data()
    generate_html(data, output)


if __name__ == "__main__":
    main()
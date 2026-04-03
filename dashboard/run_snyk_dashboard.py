import os
import json
import psycopg2
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HTML_FILE = os.path.join(BASE_DIR, "snyk_dashboard.html")
JSON_FILE = os.path.join(BASE_DIR, "snyk_dashboard_data.json")

DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")

SEVERITY_ORDER = ["critical", "high", "medium", "low", "warning", "note", "error"]


def get_connection():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        dbname=DB_NAME
    )


def ordered_severity_dict(raw_map):
    return {sev: int(raw_map.get(sev, 0)) for sev in SEVERITY_ORDER if raw_map.get(sev, 0) > 0}


def rows_to_dict(rows):
    result = {}
    for key, value in rows:
        k = str(key).strip().lower() if key is not None else "unknown"
        result[k] = int(value)
    return result


def get_columns(cur):
    cur.execute("""
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'snyk_findings'
        ORDER BY ordinal_position;
    """)
    return [r[0] for r in cur.fetchall()]


def pick_first(existing_columns, candidates):
    for c in candidates:
        if c in existing_columns:
            return c
    return None


def sql_ident(name):
    return '"' + name.replace('"', '""') + '"'


def build_dashboard_data():
    conn = get_connection()
    cur = conn.cursor()

    columns = get_columns(cur)

    repo_field = pick_first(columns, [
        "repo_name", "repository_name", "repository", "repo", "repo_slug"
    ])

    project_field = pick_first(columns, [
        "project_name", "snyk_project_name", "package_name", "target_name"
    ])

    manifest_field = pick_first(columns, [
        "target_file", "manifest_file", "file_path", "display_target_file", "package_manager_file"
    ])

    severity_field = pick_first(columns, ["severity"])
    scan_type_field = pick_first(columns, ["scan_type"])
    vuln_id_field = pick_first(columns, ["issue_id", "cve", "cwe", "vuln_id", "identifier"])
    vuln_title_field = pick_first(columns, ["title", "issue_title", "vulnerability", "name", "problem_title"])

    if not severity_field or not scan_type_field:
        raise RuntimeError("La tabla snyk_findings no tiene columnas mínimas esperadas: severity y scan_type")

    display_project_field = repo_field or project_field
    if not display_project_field:
        raise RuntimeError("No encontré una columna de repositorio/proyecto en snyk_findings")

    display_project_sql = sql_ident(display_project_field)
    severity_sql = sql_ident(severity_field)
    scan_type_sql = sql_ident(scan_type_field)

    # total findings
    cur.execute("SELECT COUNT(*) FROM snyk_findings;")
    total_findings = int(cur.fetchone()[0] or 0)

    # severity global
    cur.execute(f"""
        SELECT COALESCE(LOWER({severity_sql}), 'unknown') AS severity, COUNT(*) AS total
        FROM snyk_findings
        GROUP BY COALESCE(LOWER({severity_sql}), 'unknown');
    """)
    severity_raw = rows_to_dict(cur.fetchall())
    severity = ordered_severity_dict(severity_raw)

    # por scan type
    cur.execute(f"""
        SELECT COALESCE(LOWER({scan_type_sql}), 'unknown') AS scan_type, COUNT(*) AS total
        FROM snyk_findings
        GROUP BY COALESCE(LOWER({scan_type_sql}), 'unknown')
        ORDER BY total DESC;
    """)
    scan_type = rows_to_dict(cur.fetchall())

    # severity SCA
    cur.execute(f"""
        SELECT COALESCE(LOWER({severity_sql}), 'unknown') AS severity, COUNT(*) AS total
        FROM snyk_findings
        WHERE LOWER({scan_type_sql}) = 'sca'
        GROUP BY COALESCE(LOWER({severity_sql}), 'unknown');
    """)
    sca_raw = rows_to_dict(cur.fetchall())
    sca_severity = ordered_severity_dict(sca_raw)

    # severity Code
    cur.execute(f"""
        SELECT COALESCE(LOWER({severity_sql}), 'unknown') AS severity, COUNT(*) AS total
        FROM snyk_findings
        WHERE LOWER({scan_type_sql}) = 'code'
        GROUP BY COALESCE(LOWER({severity_sql}), 'unknown');
    """)
    code_raw = rows_to_dict(cur.fetchall())
    code_severity = ordered_severity_dict(code_raw)

    # top proyectos/repos
    cur.execute(f"""
        SELECT COALESCE(NULLIF(TRIM({display_project_sql}), ''), 'unknown') AS project_display,
               COUNT(*) AS total
        FROM snyk_findings
        GROUP BY COALESCE(NULLIF(TRIM({display_project_sql}), ''), 'unknown')
        ORDER BY total DESC
        LIMIT 15;
    """)
    top_projects = [
        {"project_name": str(name), "total": int(total)}
        for name, total in cur.fetchall()
    ]

    # tabla por proyecto con severidades
    cur.execute(f"""
        SELECT
            COALESCE(NULLIF(TRIM({display_project_sql}), ''), 'unknown') AS project_display,
            COUNT(*) AS total,
            SUM(CASE WHEN LOWER({severity_sql}) = 'critical' THEN 1 ELSE 0 END) AS critical,
            SUM(CASE WHEN LOWER({severity_sql}) = 'high' THEN 1 ELSE 0 END) AS high,
            SUM(CASE WHEN LOWER({severity_sql}) = 'medium' THEN 1 ELSE 0 END) AS medium,
            SUM(CASE WHEN LOWER({severity_sql}) = 'low' THEN 1 ELSE 0 END) AS low,
            SUM(CASE WHEN LOWER({severity_sql}) = 'warning' THEN 1 ELSE 0 END) AS warning,
            SUM(CASE WHEN LOWER({severity_sql}) = 'note' THEN 1 ELSE 0 END) AS note,
            SUM(CASE WHEN LOWER({severity_sql}) = 'error' THEN 1 ELSE 0 END) AS error
        FROM snyk_findings
        GROUP BY COALESCE(NULLIF(TRIM({display_project_sql}), ''), 'unknown')
        ORDER BY total DESC
        LIMIT 50;
    """)
    project_summary = []
    for row in cur.fetchall():
        project_summary.append({
            "project_name": str(row[0]),
            "total": int(row[1]),
            "critical": int(row[2] or 0),
            "high": int(row[3] or 0),
            "medium": int(row[4] or 0),
            "low": int(row[5] or 0),
            "warning": int(row[6] or 0),
            "note": int(row[7] or 0),
            "error": int(row[8] or 0),
        })

    # detalle de vulnerabilidades por proyecto
    project_vulns = []
    if vuln_title_field or vuln_id_field:
        vuln_title_sql = sql_ident(vuln_title_field) if vuln_title_field else None
        vuln_id_sql = sql_ident(vuln_id_field) if vuln_id_field else None

        vuln_display_expr_parts = []
        if vuln_id_sql:
            vuln_display_expr_parts.append(f"COALESCE(NULLIF(TRIM({vuln_id_sql}::text), ''), '')")
        if vuln_title_sql:
            vuln_display_expr_parts.append(f"COALESCE(NULLIF(TRIM({vuln_title_sql}), ''), '')")

        if len(vuln_display_expr_parts) == 2:
            vuln_display_expr = f"""
                CASE
                    WHEN {vuln_display_expr_parts[0]} <> '' AND {vuln_display_expr_parts[1]} <> ''
                        THEN {vuln_display_expr_parts[0]} || ' - ' || {vuln_display_expr_parts[1]}
                    WHEN {vuln_display_expr_parts[0]} <> ''
                        THEN {vuln_display_expr_parts[0]}
                    WHEN {vuln_display_expr_parts[1]} <> ''
                        THEN {vuln_display_expr_parts[1]}
                    ELSE 'unknown'
                END
            """
        else:
            vuln_display_expr = vuln_display_expr_parts[0] if vuln_display_expr_parts else "'unknown'"

        cur.execute(f"""
            SELECT
                project_display,
                vuln_display,
                severity,
                total
            FROM (
                SELECT
                    COALESCE(NULLIF(TRIM({display_project_sql}), ''), 'unknown') AS project_display,
                    {vuln_display_expr} AS vuln_display,
                    COALESCE(LOWER({severity_sql}), 'unknown') AS severity,
                    COUNT(*) AS total,
                    ROW_NUMBER() OVER (
                        PARTITION BY COALESCE(NULLIF(TRIM({display_project_sql}), ''), 'unknown')
                        ORDER BY COUNT(*) DESC
                    ) AS rn
                FROM snyk_findings
                GROUP BY
                    COALESCE(NULLIF(TRIM({display_project_sql}), ''), 'unknown'),
                    {vuln_display_expr},
                    COALESCE(LOWER({severity_sql}), 'unknown')
            ) t
            WHERE rn <= 10
            ORDER BY project_display, total DESC;
        """)
        for row in cur.fetchall():
            project_vulns.append({
                "project_name": str(row[0]),
                "vulnerability": str(row[1]),
                "severity": str(row[2]),
                "total": int(row[3]),
            })

    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": total_findings,
        "field_detection": {
            "repo_field": repo_field,
            "project_field": project_field,
            "manifest_field": manifest_field,
            "display_project_field_used": display_project_field,
            "vuln_id_field": vuln_id_field,
            "vuln_title_field": vuln_title_field,
        },
        "severity_order": SEVERITY_ORDER,
        "severity": severity,
        "scan_type": scan_type,
        "sca_severity": sca_severity,
        "code_severity": code_severity,
        "top_projects": top_projects,
        "project_summary": project_summary,
        "project_vulnerabilities": project_vulns,
    }

    with open(JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    cur.close()
    conn.close()
    print(f"[OK] JSON generado: {JSON_FILE}")
    print(f"[INFO] Campo usado como proyecto/repo: {display_project_field}")


class DashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)


def main():
    if not all([DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME]):
        raise RuntimeError("Faltan variables de entorno. Carga tu .env con: set -a; source .env; set +a")

    if not os.path.exists(HTML_FILE):
        raise FileNotFoundError(f"No existe el HTML del dashboard: {HTML_FILE}")

    build_dashboard_data()

    port = int(os.getenv("SNYK_DASHBOARD_PORT", "8010"))
    server = ThreadingHTTPServer(("0.0.0.0", port), DashboardHandler)

    print(f"[OK] Dashboard Snyk: http://127.0.0.1:{port}/snyk_dashboard.html")
    print("[INFO] Ctrl+C para detener")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[INFO] Cerrando servidor...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
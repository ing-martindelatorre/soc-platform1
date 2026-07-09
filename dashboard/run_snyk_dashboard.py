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

# hallazgos con estas combinaciones (repo_name, issue_id) marcadas como
# is_dismissed=TRUE se excluyen de las vistas/KPIs activos del dashboard
NOT_DISMISSED_FRAGMENT = """
    NOT EXISTS (
        SELECT 1 FROM snyk_dismissals sd
        WHERE sd.repo_name = snyk_findings.repo_name
          AND sd.issue_id = snyk_findings.issue_id
          AND sd.is_dismissed = TRUE
    )
"""


def get_connection():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        dbname=DB_NAME
    )


def ensure_dismissals_table():
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS snyk_dismissals (
                id BIGSERIAL PRIMARY KEY,
                repo_name TEXT NOT NULL,
                issue_id TEXT NOT NULL,
                is_dismissed BOOLEAN NOT NULL DEFAULT TRUE,
                reason TEXT NOT NULL DEFAULT '',
                dismissed_by TEXT,
                dismissed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
        """)
        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS uq_snyk_dismissals_repo_issue
                ON snyk_dismissals (repo_name, issue_id);
        """)
        conn.commit()
        cur.close()
    finally:
        conn.close()


def set_dismissal(repo_name: str, issue_id: str, reason: str, dismissed_by: str | None) -> None:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO snyk_dismissals (repo_name, issue_id, is_dismissed, reason, dismissed_by, dismissed_at, updated_at)
            VALUES (%s, %s, TRUE, %s, %s, NOW(), NOW())
            ON CONFLICT (repo_name, issue_id) DO UPDATE SET
                is_dismissed = TRUE,
                reason = EXCLUDED.reason,
                dismissed_by = EXCLUDED.dismissed_by,
                dismissed_at = NOW(),
                updated_at = NOW()
        """, (repo_name, issue_id, reason, dismissed_by))
        conn.commit()
        cur.close()
    finally:
        conn.close()


def clear_dismissal(repo_name: str, issue_id: str) -> None:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE snyk_dismissals
            SET is_dismissed = FALSE, updated_at = NOW()
            WHERE repo_name = %s AND issue_id = %s
        """, (repo_name, issue_id))
        conn.commit()
        cur.close()
    finally:
        conn.close()


def get_dismissals() -> dict:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT repo_name, issue_id, is_dismissed, reason, dismissed_by, dismissed_at
            FROM snyk_dismissals
        """)
        result = {}
        for repo_name, issue_id, is_dismissed, reason, dismissed_by, dismissed_at in cur.fetchall():
            key = (repo_name, issue_id)
            result[key] = {
                "is_dismissed": bool(is_dismissed),
                "reason": reason or "",
                "dismissed_by": dismissed_by,
                "dismissed_at": dismissed_at.isoformat() if dismissed_at else None,
            }
        cur.close()
        return result
    finally:
        conn.close()


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

    # total findings activos (excluye combinaciones repo+issue descartadas)
    cur.execute(f"""
        SELECT COUNT(*) FROM snyk_findings WHERE {NOT_DISMISSED_FRAGMENT};
    """)
    total_findings = int(cur.fetchone()[0] or 0)

    # total de vulnerabilidades descartadas (grupos repo+issue, no filas individuales)
    cur.execute("SELECT COUNT(*) FROM snyk_dismissals WHERE is_dismissed = TRUE;")
    total_dismissed = int(cur.fetchone()[0] or 0)

    # severity global
    cur.execute(f"""
        SELECT COALESCE(LOWER({severity_sql}), 'unknown') AS severity, COUNT(*) AS total
        FROM snyk_findings
        WHERE {NOT_DISMISSED_FRAGMENT}
        GROUP BY COALESCE(LOWER({severity_sql}), 'unknown');
    """)
    severity_raw = rows_to_dict(cur.fetchall())
    severity = ordered_severity_dict(severity_raw)

    # por scan type
    cur.execute(f"""
        SELECT COALESCE(LOWER({scan_type_sql}), 'unknown') AS scan_type, COUNT(*) AS total
        FROM snyk_findings
        WHERE {NOT_DISMISSED_FRAGMENT}
        GROUP BY COALESCE(LOWER({scan_type_sql}), 'unknown')
        ORDER BY total DESC;
    """)
    scan_type = rows_to_dict(cur.fetchall())

    # severity SCA
    cur.execute(f"""
        SELECT COALESCE(LOWER({severity_sql}), 'unknown') AS severity, COUNT(*) AS total
        FROM snyk_findings
        WHERE LOWER({scan_type_sql}) = 'sca' AND {NOT_DISMISSED_FRAGMENT}
        GROUP BY COALESCE(LOWER({severity_sql}), 'unknown');
    """)
    sca_raw = rows_to_dict(cur.fetchall())
    sca_severity = ordered_severity_dict(sca_raw)

    # severity Code
    cur.execute(f"""
        SELECT COALESCE(LOWER({severity_sql}), 'unknown') AS severity, COUNT(*) AS total
        FROM snyk_findings
        WHERE LOWER({scan_type_sql}) = 'code' AND {NOT_DISMISSED_FRAGMENT}
        GROUP BY COALESCE(LOWER({severity_sql}), 'unknown');
    """)
    code_raw = rows_to_dict(cur.fetchall())
    code_severity = ordered_severity_dict(code_raw)

    # top proyectos/repos (solo activos)
    cur.execute(f"""
        SELECT COALESCE(NULLIF(TRIM({display_project_sql}), ''), 'unknown') AS project_display,
               COUNT(*) AS total
        FROM snyk_findings
        WHERE {NOT_DISMISSED_FRAGMENT}
        GROUP BY COALESCE(NULLIF(TRIM({display_project_sql}), ''), 'unknown')
        ORDER BY total DESC
        LIMIT 15;
    """)
    top_projects = [
        {"project_name": str(name), "total": int(total)}
        for name, total in cur.fetchall()
    ]

    # tabla por proyecto con severidades (solo activos)
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
        WHERE {NOT_DISMISSED_FRAGMENT}
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

    # detalle de vulnerabilidades por proyecto (activas, para el bloque "top vulnerabilidades")
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
                WHERE {NOT_DISMISSED_FRAGMENT}
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

    # detalle completo agrupado por aplicación + issue_id (activas y descartadas),
    # es la fuente para poder marcar/reactivar desde el dashboard
    dismissals = get_dismissals()

    vuln_title_sql = sql_ident(vuln_title_field) if vuln_title_field else None
    title_expr = f"COALESCE(NULLIF(TRIM({vuln_title_sql}), ''), issue_id)" if vuln_title_sql else "issue_id"

    cur.execute(f"""
        SELECT
            repo_name,
            issue_id,
            {title_expr} AS title,
            COALESCE(LOWER({severity_sql}), 'unknown') AS severity,
            COALESCE(package_name, '') AS package_name,
            COALESCE(version, '') AS version,
            COALESCE(cve, '') AS cve,
            COUNT(*) AS occurrences
        FROM snyk_findings
        GROUP BY repo_name, issue_id, {title_expr}, COALESCE(LOWER({severity_sql}), 'unknown'),
                 COALESCE(package_name, ''), COALESCE(version, ''), COALESCE(cve, '')
        ORDER BY repo_name,
                 CASE COALESCE(LOWER({severity_sql}), 'unknown')
                     WHEN 'critical' THEN 0
                     WHEN 'high' THEN 1
                     WHEN 'medium' THEN 2
                     WHEN 'low' THEN 3
                     ELSE 4
                 END,
                 occurrences DESC;
    """)

    projects_map: dict[str, list] = {}
    for repo_name, issue_id, title, severity_val, package_name, version, cve, occurrences in cur.fetchall():
        info = dismissals.get((repo_name, issue_id))
        item = {
            "repo_name": repo_name,
            "issue_id": issue_id,
            "title": title,
            "severity": severity_val,
            "package_name": package_name,
            "version": version,
            "cve": cve,
            "occurrences": int(occurrences),
            "dismissed": bool(info and info["is_dismissed"]),
            "reason": info["reason"] if info else None,
            "dismissed_by": info["dismissed_by"] if info else None,
            "dismissed_at": info["dismissed_at"] if info else None,
        }
        projects_map.setdefault(repo_name, []).append(item)

    vulnerabilities_by_project = [
        {"project_name": name, "items": items}
        for name, items in sorted(
            projects_map.items(),
            key=lambda kv: sum(1 for i in kv[1] if not i["dismissed"]),
            reverse=True,
        )
    ]

    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": total_findings,
        "total_dismissed": total_dismissed,
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
        "vulnerabilities_by_project": vulnerabilities_by_project,
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

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/api/dismissals":
            self._send_json(404, {"error": "not found"})
            return

        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(length) if length else b"{}"
            payload = json.loads(raw or b"{}")
        except (ValueError, json.JSONDecodeError):
            self._send_json(400, {"error": "JSON inválido"})
            return

        action = str(payload.get("action", "")).strip().lower()
        repo_name = str(payload.get("repo_name", "")).strip()
        issue_id = str(payload.get("issue_id", "")).strip()

        if not repo_name or not issue_id or action not in ("dismiss", "reactivate"):
            self._send_json(400, {"error": "Faltan repo_name, issue_id o action inválida"})
            return

        try:
            if action == "dismiss":
                reason = str(payload.get("reason", "")).strip()
                if not reason:
                    self._send_json(400, {"error": "El motivo es obligatorio para descartar"})
                    return
                dismissed_by = str(payload.get("dismissed_by", "")).strip() or None
                set_dismissal(repo_name, issue_id, reason, dismissed_by)
            else:
                clear_dismissal(repo_name, issue_id)

            build_dashboard_data()
            self._send_json(200, {"ok": True})
        except Exception as exc:
            self._send_json(500, {"error": str(exc)})


def main():
    if not all([DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME]):
        raise RuntimeError("Faltan variables de entorno. Carga tu .env con: set -a; source .env; set +a")

    if not os.path.exists(HTML_FILE):
        raise FileNotFoundError(f"No existe el HTML del dashboard: {HTML_FILE}")

    ensure_dismissals_table()
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

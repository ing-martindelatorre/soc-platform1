import os
import json
import psycopg2
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HTML_FILE = os.path.join(BASE_DIR, "snyk_dashboard.html")
JSON_FILE = os.path.join(BASE_DIR, "snyk_dashboard_data.json")
# Batch generado por app/pipeline/sync_repos.py con los repos en scope
# (custom property de GitHub ambiente=produccion)
SCOPE_BATCH_FILE = os.path.join(os.path.dirname(BASE_DIR), "repos_snyk_batch.txt")
SCOPE_LABEL = "produccion"

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

# solo repos en scope; se apoya en la tabla temporal que crea _prepare_scope
IN_SCOPE_FRAGMENT = "snyk_findings.repo_name IN (SELECT repo_name FROM snyk_scope)"


def load_scope_repos() -> list[str] | None:
    """
    Nombres de los repos en scope según repos_snyk_batch.txt. Devuelve None
    si el batch no existe o está vacío (entonces no se filtra nada).
    """
    if not os.path.exists(SCOPE_BATCH_FILE):
        return None
    names = []
    with open(SCOPE_BATCH_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                names.append(os.path.basename(line.rstrip("/")))
    return sorted(set(names)) or None


def _prepare_scope(cur, scope_repos: list[str] | None) -> None:
    """Crea la tabla temporal snyk_scope con los repos a mostrar."""
    cur.execute("CREATE TEMP TABLE IF NOT EXISTS snyk_scope (repo_name TEXT PRIMARY KEY)")
    cur.execute("TRUNCATE snyk_scope")
    if scope_repos is None:
        # sin batch: mostrar todos los repos con hallazgos
        cur.execute("INSERT INTO snyk_scope SELECT DISTINCT repo_name FROM snyk_findings WHERE repo_name IS NOT NULL")
    else:
        cur.executemany("INSERT INTO snyk_scope (repo_name) VALUES (%s)", [(r,) for r in scope_repos])


def scan_state(total_active: int, last_status: str | None) -> str:
    """
    Estado de un repo para el dashboard:
      vulnerable  — tiene hallazgos activos
      clean       — se escaneó y no tiene hallazgos activos
      pending     — todavía no se ha escaneado
      unsupported — Snyk no encontró un proyecto soportado
      error       — el último escaneo falló
    """
    if total_active > 0:
        return "vulnerable"
    if not last_status:
        return "pending"
    if last_status.startswith("success"):
        return "clean"
    if last_status == "no_supported_project":
        return "unsupported"
    if last_status.startswith("failed"):
        return "error"
    return "pending"


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

    scope_repos = load_scope_repos()
    _prepare_scope(cur, scope_repos)
    active = f"{IN_SCOPE_FRAGMENT} AND {NOT_DISMISSED_FRAGMENT}"

    # último escaneo de cada repo en scope (sin fila = nunca escaneado)
    cur.execute("""
        SELECT s.repo_name, r.status, r.finished_at
        FROM snyk_scope s
        LEFT JOIN LATERAL (
            SELECT status, finished_at FROM snyk_scan_runs sr
            WHERE sr.repo_name = s.repo_name
            ORDER BY sr.started_at DESC
            LIMIT 1
        ) r ON TRUE;
    """)
    last_scan = {
        repo: {"status": status, "finished_at": finished_at.isoformat() if finished_at else None}
        for repo, status, finished_at in cur.fetchall()
    }

    display_project_sql = sql_ident(display_project_field)
    severity_sql = sql_ident(severity_field)
    scan_type_sql = sql_ident(scan_type_field)

    # total findings activos (excluye combinaciones repo+issue descartadas)
    cur.execute(f"""
        SELECT COUNT(*) FROM snyk_findings WHERE {active};
    """)
    total_findings = int(cur.fetchone()[0] or 0)

    # total de vulnerabilidades descartadas (grupos repo+issue, no filas individuales)
    cur.execute("""
        SELECT COUNT(*) FROM snyk_dismissals
        WHERE is_dismissed = TRUE
          AND repo_name IN (SELECT repo_name FROM snyk_scope);
    """)
    total_dismissed = int(cur.fetchone()[0] or 0)

    # severity global
    cur.execute(f"""
        SELECT COALESCE(LOWER({severity_sql}), 'unknown') AS severity, COUNT(*) AS total
        FROM snyk_findings
        WHERE {active}
        GROUP BY COALESCE(LOWER({severity_sql}), 'unknown');
    """)
    severity_raw = rows_to_dict(cur.fetchall())
    severity = ordered_severity_dict(severity_raw)

    # por scan type
    cur.execute(f"""
        SELECT COALESCE(LOWER({scan_type_sql}), 'unknown') AS scan_type, COUNT(*) AS total
        FROM snyk_findings
        WHERE {active}
        GROUP BY COALESCE(LOWER({scan_type_sql}), 'unknown')
        ORDER BY total DESC;
    """)
    scan_type = rows_to_dict(cur.fetchall())

    # severity SCA
    cur.execute(f"""
        SELECT COALESCE(LOWER({severity_sql}), 'unknown') AS severity, COUNT(*) AS total
        FROM snyk_findings
        WHERE LOWER({scan_type_sql}) = 'sca' AND {active}
        GROUP BY COALESCE(LOWER({severity_sql}), 'unknown');
    """)
    sca_raw = rows_to_dict(cur.fetchall())
    sca_severity = ordered_severity_dict(sca_raw)

    # severity Code
    cur.execute(f"""
        SELECT COALESCE(LOWER({severity_sql}), 'unknown') AS severity, COUNT(*) AS total
        FROM snyk_findings
        WHERE LOWER({scan_type_sql}) = 'code' AND {active}
        GROUP BY COALESCE(LOWER({severity_sql}), 'unknown');
    """)
    code_raw = rows_to_dict(cur.fetchall())
    code_severity = ordered_severity_dict(code_raw)

    # top proyectos/repos (solo activos)
    cur.execute(f"""
        SELECT COALESCE(NULLIF(TRIM({display_project_sql}), ''), 'unknown') AS project_display,
               COUNT(*) AS total
        FROM snyk_findings
        WHERE {active}
        GROUP BY COALESCE(NULLIF(TRIM({display_project_sql}), ''), 'unknown')
        ORDER BY total DESC
        LIMIT 15;
    """)
    top_projects = [
        {"project_name": str(name), "total": int(total)}
        for name, total in cur.fetchall()
    ]

    # tabla por proyecto con severidades: todos los repos en scope, aunque
    # no tengan hallazgos activos (limpios o pendientes de escanear)
    cur.execute(f"""
        SELECT
            s.repo_name AS project_display,
            COUNT(f.*) AS total,
            SUM(CASE WHEN LOWER(f.{severity_sql}) = 'critical' THEN 1 ELSE 0 END) AS critical,
            SUM(CASE WHEN LOWER(f.{severity_sql}) = 'high' THEN 1 ELSE 0 END) AS high,
            SUM(CASE WHEN LOWER(f.{severity_sql}) = 'medium' THEN 1 ELSE 0 END) AS medium,
            SUM(CASE WHEN LOWER(f.{severity_sql}) = 'low' THEN 1 ELSE 0 END) AS low,
            SUM(CASE WHEN LOWER(f.{severity_sql}) = 'warning' THEN 1 ELSE 0 END) AS warning,
            SUM(CASE WHEN LOWER(f.{severity_sql}) = 'note' THEN 1 ELSE 0 END) AS note,
            SUM(CASE WHEN LOWER(f.{severity_sql}) = 'error' THEN 1 ELSE 0 END) AS error
        FROM snyk_scope s
        LEFT JOIN snyk_findings f
               ON f.repo_name = s.repo_name
              AND {NOT_DISMISSED_FRAGMENT.replace("snyk_findings.", "f.")}
        GROUP BY s.repo_name
        ORDER BY total DESC, s.repo_name;
    """)
    project_summary = []
    for row in cur.fetchall():
        scan = last_scan.get(row[0], {})
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
            "state": scan_state(int(row[1]), scan.get("status")),
            "last_status": scan.get("status"),
            "last_scan_at": scan.get("finished_at"),
        })
    state_rank = {"vulnerable": 0, "clean": 1, "unsupported": 2, "error": 3, "pending": 4}
    project_summary.sort(key=lambda p: (state_rank.get(p["state"], 9), -p["total"], p["project_name"].lower()))
    states = {p["project_name"]: p for p in project_summary}

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
                WHERE {active}
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
        WHERE {IN_SCOPE_FRAGMENT}
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

    for name in states:
        projects_map.setdefault(name, [])

    vulnerabilities_by_project = [
        {
            "project_name": name,
            "items": items,
            "state": states.get(name, {}).get("state"),
            "last_status": states.get(name, {}).get("last_status"),
        }
        for name, items in sorted(
            projects_map.items(),
            key=lambda kv: (-sum(1 for i in kv[1] if not i["dismissed"]), kv[0]),
        )
    ]

    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": {
            "label": SCOPE_LABEL if scope_repos is not None else None,
            "repos": scope_repos or [],
            "total_repos": len(scope_repos) if scope_repos is not None else None,
            "states": {
                st: sum(1 for p in project_summary if p["state"] == st)
                for st in ("vulnerable", "clean", "pending", "unsupported", "error")
            },
        },
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

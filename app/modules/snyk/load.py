from __future__ import annotations

import json
import os
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import psycopg2
import psycopg2.extras
from psycopg2 import sql


def _db_params() -> dict:
    return {
        "host": os.getenv("DB_HOST", "localhost"),
        "port": int(os.getenv("DB_PORT", "5432")),
        "dbname": os.getenv("DB_NAME", "soc"),
        "user": os.getenv("DB_USER", "postgres"),
        "password": os.getenv("DB_PASSWORD", ""),
    }


@contextmanager
def get_conn():
    conn = psycopg2.connect(**_db_params())
    try:
        yield conn
    finally:
        conn.close()


def ensure_snyk_tables() -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS snyk_scan_runs (
                    id BIGSERIAL PRIMARY KEY,
                    repo_name TEXT NOT NULL,
                    repo_path TEXT NOT NULL,
                    scan_type VARCHAR(20) NOT NULL DEFAULT 'sca',
                    account_alias TEXT NOT NULL,
                    org_id TEXT,
                    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    finished_at TIMESTAMPTZ,
                    exit_code INT,
                    status VARCHAR(40) NOT NULL,
                    findings_count INT NOT NULL DEFAULT 0,
                    raw_json_path TEXT,
                    stdout_log TEXT,
                    stderr_log TEXT,
                    error_signature TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                );
                """
            )

            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS snyk_account_state (
                    account_alias TEXT PRIMARY KEY,
                    org_id TEXT,
                    is_enabled BOOLEAN NOT NULL DEFAULT true,
                    last_success_at TIMESTAMPTZ,
                    last_failure_at TIMESTAMPTZ,
                    last_failure_type VARCHAR(40),
                    consecutive_failures INT NOT NULL DEFAULT 0,
                    blocked_until TIMESTAMPTZ,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                );
                """
            )

            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS snyk_findings (
                    id BIGSERIAL PRIMARY KEY,
                    repo_name TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    issue_id TEXT NOT NULL,
                    severity TEXT,
                    title TEXT,
                    description TEXT,
                    package_name TEXT,
                    version TEXT,
                    cve TEXT,
                    project_name TEXT,
                    file_path TEXT NOT NULL DEFAULT '',
                    line INTEGER,
                    rule_id TEXT,
                    language TEXT,
                    exploit_maturity TEXT,
                    is_upgradable BOOLEAN,
                    is_patchable BOOLEAN,
                    scan_timestamp TIMESTAMPTZ NOT NULL,
                    raw_file_path TEXT,
                    first_seen TIMESTAMPTZ NOT NULL,
                    last_seen TIMESTAMPTZ NOT NULL,
                    is_active BOOLEAN NOT NULL DEFAULT true,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                );
                """
            )

            alter_statements = [
                "ALTER TABLE snyk_findings ADD COLUMN IF NOT EXISTS scan_run_id BIGINT",
                "ALTER TABLE snyk_findings ADD COLUMN IF NOT EXISTS repo_path TEXT",
                "ALTER TABLE snyk_findings ADD COLUMN IF NOT EXISTS vuln_id TEXT",
                "ALTER TABLE snyk_findings ADD COLUMN IF NOT EXISTS issue_url TEXT",
                "ALTER TABLE snyk_findings ADD COLUMN IF NOT EXISTS fixed_version TEXT",
                "ALTER TABLE snyk_findings ADD COLUMN IF NOT EXISTS cves TEXT",
                "ALTER TABLE snyk_findings ADD COLUMN IF NOT EXISTS cwes TEXT",
                "ALTER TABLE snyk_findings ADD COLUMN IF NOT EXISTS is_pinnable BOOLEAN DEFAULT false",
                "ALTER TABLE snyk_findings ADD COLUMN IF NOT EXISTS json_data JSONB",
                "ALTER TABLE snyk_findings ADD COLUMN IF NOT EXISTS issue_type TEXT",
                "ALTER TABLE snyk_findings ADD COLUMN IF NOT EXISTS target_file TEXT",
            ]
            for stmt in alter_statements:
                cur.execute(stmt)

        conn.commit()


def insert_scan_run_start(
        repo_name: str,
        repo_path: str,
        account_alias: str,
        org_id: str | None,
        started_at: datetime,
        scan_type: str = "sca",
) -> int:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO snyk_scan_runs (
                    repo_name, repo_path, scan_type, account_alias, org_id, started_at, status
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    repo_name,
                    repo_path,
                    scan_type,
                    account_alias,
                    org_id,
                    started_at,
                    "running",
                ),
            )
            scan_run_id = cur.fetchone()[0]
        conn.commit()
        return scan_run_id


def finalize_scan_run(
        scan_run_id: int,
        finished_at: datetime,
        exit_code: int,
        status: str,
        findings_count: int,
        raw_json_path: str,
        stdout_log: str,
        stderr_log: str,
        error_signature: str,
) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE snyk_scan_runs
                SET finished_at = %s,
                    exit_code = %s,
                    status = %s,
                    findings_count = %s,
                    raw_json_path = %s,
                    stdout_log = %s,
                    stderr_log = %s,
                    error_signature = %s
                WHERE id = %s
                """,
                (
                    finished_at,
                    exit_code,
                    status,
                    findings_count,
                    raw_json_path,
                    stdout_log,
                    stderr_log,
                    error_signature,
                    scan_run_id,
                ),
            )
        conn.commit()


def delete_previous_findings_for_repo(repo_name: str, scan_type: str = "sca") -> None:
    """
    Se conserva por compatibilidad con tu flujo actual.
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM snyk_findings
                WHERE repo_name = %s
                  AND scan_type = %s
                """,
                (repo_name, scan_type),
            )
        conn.commit()


def _get_table_columns(cur, table_name: str) -> list[str]:
    cur.execute(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = %s
        ORDER BY ordinal_position
        """,
        (table_name,),
    )
    return [r[0] for r in cur.fetchall()]


def insert_snyk_findings(rows: list[dict]) -> int:
    if not rows:
        return 0

    now_ts = datetime.now(timezone.utc)

    with get_conn() as conn:
        with conn.cursor() as cur:
            table_columns = set(_get_table_columns(cur, "snyk_findings"))

            prepared_rows = []
            for row in rows:
                item = dict(row)

                # campos obligatorios del esquema real
                item["repo_name"] = item.get("repo_name") or ""
                item["scan_type"] = item.get("scan_type") or "sca"
                item["issue_id"] = item.get("issue_id") or item.get("vuln_id") or "unknown_issue"

                # la constraint única usa file_path, así que no puede ir vacío en SCA
                item["file_path"] = item.get("file_path") or item.get("target_file") or item.get("project_name") or ""

                # timestamps heredados
                if not item.get("scan_timestamp"):
                    item["scan_timestamp"] = now_ts
                if not item.get("first_seen"):
                    item["first_seen"] = now_ts
                if not item.get("last_seen"):
                    item["last_seen"] = now_ts
                if not item.get("created_at"):
                    item["created_at"] = now_ts
                if item.get("is_active") is None:
                    item["is_active"] = True

                # aliases/compatibilidad
                if "vuln_id" in table_columns and not item.get("vuln_id"):
                    item["vuln_id"] = item["issue_id"]

                if "cve" in table_columns and not item.get("cve"):
                    cves_text = item.get("cves") or ""
                    item["cve"] = cves_text.split(",")[0].strip() if cves_text else ""

                if "json_data" in item and "json_data" in table_columns:
                    item["json_data"] = json.dumps(item["json_data"], ensure_ascii=False)

                prepared_rows.append(item)

            insert_columns = [col for col in prepared_rows[0].keys() if col in table_columns]
            if not insert_columns:
                raise RuntimeError("No encontré columnas compatibles para insertar en snyk_findings")

            values_template = sql.SQL(", ").join(sql.Placeholder(col) for col in insert_columns)

            # actualizamos columnas relevantes si ya existe el mismo (repo_name, scan_type, issue_id, file_path)
            update_columns = [
                col for col in insert_columns
                if col not in {"repo_name", "scan_type", "issue_id", "file_path", "created_at", "first_seen"}
            ]

            if update_columns:
                on_conflict_sql = sql.SQL("""
                    ON CONFLICT (repo_name, scan_type, issue_id, file_path)
                    DO UPDATE SET
                """) + sql.SQL(", ").join(
                    sql.SQL("{col} = EXCLUDED.{col}").format(col=sql.Identifier(col))
                    for col in update_columns
                )
            else:
                on_conflict_sql = sql.SQL("""
                    ON CONFLICT (repo_name, scan_type, issue_id, file_path)
                    DO NOTHING
                """)

            insert_sql = (
                    sql.SQL("INSERT INTO snyk_findings ({fields}) VALUES ({values}) ")
                    .format(
                        fields=sql.SQL(", ").join(sql.Identifier(col) for col in insert_columns),
                        values=values_template,
                    )
                    + on_conflict_sql
            )

            psycopg2.extras.execute_batch(
                cur,
                insert_sql.as_string(conn),
                [{col: row.get(col) for col in insert_columns} for row in prepared_rows],
                page_size=500,
            )

        conn.commit()

    return len(rows)


def get_account_state(alias: str) -> dict | None:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT *
                FROM snyk_account_state
                WHERE account_alias = %s
                """,
                (alias,),
            )
            row = cur.fetchone()
            return dict(row) if row else None


def touch_account(alias: str, org_id: str | None, is_enabled: bool = True) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO snyk_account_state (account_alias, org_id, is_enabled, updated_at)
                VALUES (%s, %s, %s, now())
                ON CONFLICT (account_alias)
                DO UPDATE SET
                    org_id = EXCLUDED.org_id,
                    is_enabled = EXCLUDED.is_enabled,
                    updated_at = now()
                """,
                (alias, org_id, is_enabled),
            )
        conn.commit()


def mark_account_success(alias: str, org_id: str | None) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO snyk_account_state (
                    account_alias, org_id, is_enabled, last_success_at,
                    last_failure_type, consecutive_failures, blocked_until, updated_at
                ) VALUES (%s, %s, true, now(), NULL, 0, NULL, now())
                ON CONFLICT (account_alias)
                DO UPDATE SET
                    org_id = EXCLUDED.org_id,
                    is_enabled = true,
                    last_success_at = now(),
                    last_failure_type = NULL,
                    consecutive_failures = 0,
                    blocked_until = NULL,
                    updated_at = now()
                """,
                (alias, org_id),
            )
        conn.commit()


def mark_account_failure(alias: str, org_id: str | None, failure_type: str, block_minutes: int = 0) -> None:
    blocked_until = None
    if block_minutes > 0:
        blocked_until = datetime.now(timezone.utc) + timedelta(minutes=block_minutes)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO snyk_account_state (
                    account_alias, org_id, is_enabled, last_failure_at,
                    last_failure_type, consecutive_failures, blocked_until, updated_at
                ) VALUES (%s, %s, true, now(), %s, 1, %s, now())
                ON CONFLICT (account_alias)
                DO UPDATE SET
                    org_id = EXCLUDED.org_id,
                    last_failure_at = now(),
                    last_failure_type = EXCLUDED.last_failure_type,
                    consecutive_failures = snyk_account_state.consecutive_failures + 1,
                    blocked_until = EXCLUDED.blocked_until,
                    updated_at = now()
                """,
                (alias, org_id, failure_type, blocked_until),
            )
        conn.commit()


def is_account_blocked(alias: str) -> bool:
    row = get_account_state(alias)
    if not row:
        return False

    blocked_until = row.get("blocked_until")
    if blocked_until is None:
        return False

    return blocked_until > datetime.now(timezone.utc)


def get_accounts_status() -> list[dict]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT
                    account_alias,
                    org_id,
                    is_enabled,
                    last_success_at,
                    last_failure_at,
                    last_failure_type,
                    consecutive_failures,
                    blocked_until,
                    updated_at
                FROM snyk_account_state
                ORDER BY account_alias
                """
            )
            rows = cur.fetchall()
            return [dict(r) for r in rows]
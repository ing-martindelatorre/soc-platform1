"""
app/modules/cpanel/load.py

Loader de datos de WHM/cPanel a PostgreSQL.
Modos: stats, security, accounts.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List

import psycopg2


def _get_conn():
    return psycopg2.connect(
        host=os.environ["DB_HOST"],
        port=os.environ["DB_PORT"],
        dbname=os.environ["DB_NAME"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
    )


# =============================================================================
# STATS
# =============================================================================
def load_stats(data: Dict[str, Any]) -> None:
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO cpanel_server_stats (
                        server_host, hostname, version,
                        mail_queue,
                        cpu_load_1, cpu_load_5, cpu_load_15,
                        memory_total, memory_used, memory_free,
                        disk_used_pct, payload
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
                    """,
                    (
                        data.get("server_host"),
                        data.get("hostname"),
                        data.get("version"),
                        data.get("mail_queue"),
                        data.get("cpu_load_1"),
                        data.get("cpu_load_5"),
                        data.get("cpu_load_15"),
                        data.get("memory_total"),
                        data.get("memory_used"),
                        data.get("memory_free"),
                        data.get("disk_used_pct"),
                        json.dumps(data.get("raw", {})),
                    ),
                )
    finally:
        conn.close()


# =============================================================================
# SECURITY
# =============================================================================
def load_security(data: Dict[str, Any]) -> None:
    events: List[Dict[str, Any]] = data.get("events", [])
    if not events:
        return

    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                for ev in events:
                    cur.execute(
                        """
                        INSERT INTO cpanel_cphulk_events (
                            server_host, ip, username, service,
                            attempts, blocked, blocked_until, payload
                        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
                        """,
                        (
                            data.get("server_host"),
                            ev.get("ip"),
                            ev.get("username"),
                            ev.get("service"),
                            ev.get("attempts"),
                            ev.get("blocked", False),
                            ev.get("blocked_until"),
                            json.dumps(ev.get("payload", {})),
                        ),
                    )
    finally:
        conn.close()


# =============================================================================
# ACCOUNTS
# =============================================================================
def load_accounts(data: Dict[str, Any]) -> None:
    accounts: List[Dict[str, Any]] = data.get("accounts", [])
    if not accounts:
        return

    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                for acct in accounts:
                    cur.execute(
                        """
                        INSERT INTO cpanel_accounts (
                            server_host, username, domain, plan,
                            suspended, disk_used_mb, disk_limit_mb, payload
                        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
                        """,
                        (
                            data.get("server_host"),
                            acct.get("username"),
                            acct.get("domain"),
                            acct.get("plan"),
                            acct.get("suspended", False),
                            acct.get("disk_used_mb"),
                            acct.get("disk_limit_mb"),
                            json.dumps(acct.get("payload", {})),
                        ),
                    )
    finally:
        conn.close()


# =============================================================================
# LOGS (Exim via SSH)
# =============================================================================
def load_logs(data: Dict[str, Any]) -> None:
    import json as _json
    events: List[Dict[str, Any]] = data.get("events", [])
    if not events:
        return

    conn = _get_conn()
    inserted = 0
    try:
        with conn:
            with conn.cursor() as cur:
                for ev in events:
                    try:
                        cur.execute(
                            """
                            INSERT INTO cpanel_mail_events (
                                event_time, server_host, event_type,
                                message_id, sender, recipient,
                                remote_host, remote_ip,
                                spam_score, reject_reason, size_bytes,
                                line_hash, payload
                            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
                            ON CONFLICT (line_hash) DO NOTHING
                            """,
                            (
                                ev.get("event_time"),
                                data.get("server_host"),
                                ev.get("event_type"),
                                ev.get("message_id"),
                                ev.get("sender"),
                                ev.get("recipient"),
                                ev.get("remote_host"),
                                ev.get("remote_ip"),
                                ev.get("spam_score"),
                                ev.get("reject_reason"),
                                ev.get("size_bytes"),
                                ev.get("line_hash"),
                                _json.dumps({"raw": ev.get("raw", "")}),
                            ),
                        )
                        inserted += 1
                    except Exception:
                        pass
    finally:
        conn.close()


# =============================================================================
# Entry point
# =============================================================================
def load(data: Dict[str, Any]) -> None:
    mode = data.get("mode", "stats")
    if mode == "security":
        load_security(data)
    elif mode == "accounts":
        load_accounts(data)
    elif mode == "logs":
        load_logs(data)
    else:
        load_stats(data)

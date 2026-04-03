from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

import psycopg2


def get_conn():
    return psycopg2.connect(
        host=os.environ["DB_HOST"],
        port=os.environ["DB_PORT"],
        dbname=os.environ["DB_NAME"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
    )


def _to_int(value: Any) -> Optional[int]:
    try:
        if value in (None, "", "N/A"):
            return None
        return int(value)
    except Exception:
        return None


def load_config(data: Dict[str, Any]) -> None:
    device_name = os.getenv("FORTI_DEVICE_NAME", "fortigate")
    meta = data.get("meta", {})
    raw_sections = data.get("raw_sections", {})
    errors = data.get("errors", [])

    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                for section_name, payload in raw_sections.items():
                    cur.execute(
                        """
                        INSERT INTO fortinet_raw_snapshots
                        (device_name, serial, version, build, vdom, section, payload)
                        VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
                        """,
                        (
                            device_name,
                            meta.get("serial"),
                            meta.get("version"),
                            meta.get("build"),
                            meta.get("vdom", "root"),
                            section_name,
                            json.dumps(payload),
                        ),
                    )

                for err in errors:
                    cur.execute(
                        """
                        INSERT INTO fortinet_collection_errors
                        (device_name, section, error_message)
                        VALUES (%s, %s, %s)
                        """,
                        (
                            device_name,
                            err.get("section", "unknown"),
                            err.get("error", "unknown error"),
                        ),
                    )
    finally:
        conn.close()


def load_logs(data: Dict[str, Any]) -> None:
    device_name = os.getenv("FORTI_DEVICE_NAME", "fortigate")
    meta = data.get("meta", {})
    logs = data.get("logs", [])
    errors = data.get("errors", [])
    endpoint = meta.get("requested_endpoint")

    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                for entry in logs:
                    cur.execute(
                        """
                        INSERT INTO fortinet_log_raw
                        (
                            device_name,
                            serial,
                            version,
                            build,
                            vdom,
                            endpoint,
                            log_id,
                            log_type,
                            subtype,
                            action,
                            level,
                            srcip,
                            dstip,
                            srcport,
                            dstport,
                            payload
                        )
                        VALUES
                        (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
                        """,
                        (
                            device_name,
                            meta.get("serial"),
                            meta.get("version"),
                            meta.get("build"),
                            meta.get("vdom", "root"),
                            endpoint,
                            str(entry.get("logid")) if entry.get("logid") is not None else None,
                            entry.get("type"),
                            entry.get("subtype"),
                            entry.get("action"),
                            entry.get("level"),
                            entry.get("srcip"),
                            entry.get("dstip"),
                            _to_int(entry.get("srcport")),
                            _to_int(entry.get("dstport")),
                            json.dumps(entry),
                        ),
                    )

                for err in errors:
                    cur.execute(
                        """
                        INSERT INTO fortinet_log_collection_errors
                        (device_name, endpoint, error_message)
                        VALUES (%s, %s, %s)
                        """,
                        (
                            device_name,
                            endpoint,
                            err.get("error", "unknown error"),
                        ),
                    )
    finally:
        conn.close()


def load(data: Dict[str, Any]) -> None:
    mode = data.get("mode", "config")

    if mode == "logs":
        load_logs(data)
        return

    load_config(data)
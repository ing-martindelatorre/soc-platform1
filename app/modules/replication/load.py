"""
app/modules/replication/load.py

A diferencia del resto de módulos, este load.py NO escribe los datos
extraídos en Postgres — el destino real es la otra ubicación (sender.py).
Acá solo se persiste, después del ACK del receptor, hasta dónde se llegó
(watermark) para que la próxima corrida no reenvíe lo mismo.
"""
from __future__ import annotations

from app.core.db import db_connection


def get_enabled_targets() -> list[dict]:
    with db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM replication_targets WHERE enabled = TRUE ORDER BY id")
            return [dict(r) for r in cur.fetchall()]


def get_watermark(target_id: int, table: str) -> int:
    with db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT last_sent_id FROM replication_watermarks WHERE target_id = %s AND table_name = %s",
                (target_id, table),
            )
            row = cur.fetchone()
            return row["last_sent_id"] if row else 0


def advance_watermark(target_id: int, table: str, last_id: int) -> None:
    with db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO replication_watermarks (target_id, table_name, last_sent_id, updated_at)
                VALUES (%s, %s, %s, NOW())
                ON CONFLICT (target_id, table_name) DO UPDATE SET
                    last_sent_id = EXCLUDED.last_sent_id,
                    updated_at = NOW()
                """,
                (target_id, table, last_id),
            )

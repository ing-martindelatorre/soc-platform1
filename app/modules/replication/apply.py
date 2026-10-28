"""
app/modules/replication/apply.py

Aplica en la Postgres local un batch ya descifrado y validado, recibido de
otra instancia del SOC Platform. Solo se usa en el lado receptor
(app/pipeline/replication_receiver.py).

Inserta preservando el "id" original del emisor y usa ON CONFLICT (id) DO
NOTHING — idempotente ante reintentos del mismo batch (ej. si el ACK se
perdió mandado por la red pero el batch ya había llegado).
"""
from __future__ import annotations

import json

from app.core.db import bulk_upsert, db_connection
from app.modules.replication.tables import REPLICABLE_TABLE_NAMES


def apply_batch(table: str, rows: list[dict]) -> int:
    if table not in REPLICABLE_TABLE_NAMES:
        raise ValueError(f"Tabla no replicable: {table}")
    if not rows:
        return 0

    columns = list(rows[0].keys())
    col_list = ", ".join(columns)
    sql = f"INSERT INTO {table} ({col_list}) VALUES %s ON CONFLICT (id) DO NOTHING"

    values = [tuple(_adapt(row.get(col)) for col in columns) for row in rows]

    with db_connection() as conn:
        bulk_upsert(conn, sql, values)

    return len(rows)


def _adapt(value):
    """
    Las columnas jsonb (payload, tags, evidence, raw_json, ...) llegan del
    batch como dict/list de Python (así las deserializa json.loads); hay que
    volver a convertirlas a texto JSON para que psycopg2 las pueda mandar —
    Postgres las castea solo a jsonb porque la columna destino ya es jsonb.
    """
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    return value

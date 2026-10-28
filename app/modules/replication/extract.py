"""
app/modules/replication/extract.py

Extrae de Postgres local las filas nuevas de una tabla replicable
(id > último watermark confirmado para ese destino).
"""
from __future__ import annotations

from app.core.db import db_connection
from app.modules.replication.tables import REPLICABLE_TABLE_NAMES

BATCH_SIZE = 2000  # filas por batch — evita mandar de golpe todo el backlog tras una caída larga


def fetch_new_rows(table: str, since_id: int, limit: int = BATCH_SIZE) -> list[dict]:
    if table not in REPLICABLE_TABLE_NAMES:
        # Defensa en profundidad: table siempre debería venir de tables_for_target(),
        # pero nunca se arma la consulta con un nombre fuera de la lista fija.
        raise ValueError(f"Tabla no replicable: {table}")

    with db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT * FROM {table} WHERE id > %s ORDER BY id ASC LIMIT %s",
                (since_id, limit),
            )
            return [dict(r) for r in cur.fetchall()]

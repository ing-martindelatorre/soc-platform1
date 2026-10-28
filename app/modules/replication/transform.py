"""
app/modules/replication/transform.py

Convierte las filas extraídas en un batch serializable: JSON + gzip
(reduce bastante el tamaño de fortinet_raw_snapshots, que trae jsonb grande).
"""
from __future__ import annotations

import gzip
import json


def serialize_batch(table: str, rows: list[dict]) -> bytes:
    payload = {"table": table, "rows": rows}
    raw = json.dumps(payload, default=str, ensure_ascii=False).encode("utf-8")
    return gzip.compress(raw)


def deserialize_batch(data: bytes) -> dict:
    raw = gzip.decompress(data)
    return json.loads(raw.decode("utf-8"))

"""
app/modules/replication/service.py

Orquesta la replicación: por cada destino activo, por cada tabla
configurada, extrae lo nuevo, lo serializa y cifra, lo manda, y solo
avanza el watermark si el receptor confirmó el batch con ACK.
"""
from __future__ import annotations

import logging
import uuid

from app.modules.replication.crypto import encrypt
from app.modules.replication.extract import BATCH_SIZE, fetch_new_rows
from app.modules.replication.load import advance_watermark, get_enabled_targets, get_watermark
from app.modules.replication.sender import send_batch
from app.modules.replication.tables import tables_for_target
from app.modules.replication.transform import serialize_batch

logger = logging.getLogger("soc-platform")


class ReplicationPipeline:
    name = "replication"

    def execute(self, **kwargs) -> dict:
        targets = get_enabled_targets()
        if not targets:
            return {"ok": True, "module": self.name, "message": "No hay destinos de replicación activos"}

        total_batches = 0
        total_rows = 0
        errors: list[str] = []

        for target in targets:
            for table_def in tables_for_target(target.get("tables")):
                table = table_def["table"]
                try:
                    sent = self._replicate_table(target, table)
                    total_batches += sent["batches"]
                    total_rows += sent["rows"]
                except Exception as exc:
                    msg = f"{target['name']} / {table}: {exc}"
                    logger.warning(f"[replication] ERROR {msg}")
                    errors.append(msg)

        ok = not errors
        message = f"{total_batches} batch(es), {total_rows} fila(s) replicadas"
        if errors:
            message += f" — {len(errors)} error(es)"

        return {"ok": ok, "module": self.name, "message": message, "errors": errors}

    def _replicate_table(self, target: dict, table: str) -> dict:
        target_id = target["id"]
        since_id = get_watermark(target_id, table)
        batches = 0
        rows_sent = 0

        while True:
            rows = fetch_new_rows(table, since_id)
            if not rows:
                break

            batch_id = str(uuid.uuid4())
            payload = serialize_batch(table, rows)
            associated_data = f"{table}:{batch_id}".encode("utf-8")
            encrypted = encrypt(payload, associated_data=associated_data)

            send_batch(
                target["host"], target["port"], table, encrypted, batch_id,
                expected_fingerprint=target.get("tls_fingerprint"),
            )

            since_id = rows[-1]["id"]
            advance_watermark(target_id, table, since_id)
            batches += 1
            rows_sent += len(rows)

            if len(rows) < BATCH_SIZE:
                break  # último batch parcial: no queda más por ahora

        return {"batches": batches, "rows": rows_sent}

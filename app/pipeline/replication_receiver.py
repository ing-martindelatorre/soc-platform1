"""
app/pipeline/replication_receiver.py

Proceso receptor de replicación — corre en la OTRA ubicación, no en la
instancia emisora. Escucha en REPLICATION_LISTEN_HOST:REPLICATION_LISTEN_PORT,
acepta conexiones TLS del emisor, descifra cada batch con la misma
REPLICATION_ENC_KEY que el emisor, y lo aplica a la Postgres local
(app/modules/replication/apply.py).

No es un job de APScheduler — es un proceso de larga duración. Pensado
para correr como su propio servicio systemd EN VEZ del scheduler normal:
la otra ubicación no tiene los tokens de Sentinel/Fortinet/Snyk/etc., así
que no tiene caso correr esos jobs ahí; solo recibe y sirve los dashboards
(dashboard/server.py, sin cambios, ya lee de la Postgres local sin
importar si los datos llegaron por un collector o por replicación).

Uso:
    python -m app.pipeline.replication_receiver

Variables de entorno requeridas en esta ubicación:
    REPLICATION_ENC_KEY       — misma llave AES-256 que en el emisor (.env)
    REPLICATION_TLS_CERT_FILE — certificado TLS del receptor (autofirmado sirve)
    REPLICATION_TLS_KEY_FILE  — llave privada de ese certificado
    REPLICATION_LISTEN_HOST   — default 0.0.0.0
    REPLICATION_LISTEN_PORT   — default 9443 (debe coincidir con el "puerto"
                                 configurado para este destino en el panel del emisor)
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import struct
import sys
import threading

from app.core.logging import setup_logging
from app.modules.replication.apply import apply_batch
from app.modules.replication.crypto import decrypt
from app.modules.replication.tables import REPLICABLE_TABLE_NAMES
from app.modules.replication.transform import deserialize_batch

logger = setup_logging()

LISTEN_HOST = os.getenv("REPLICATION_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("REPLICATION_LISTEN_PORT", "9443"))
IO_TIMEOUT = 30


def _build_server_context() -> ssl.SSLContext:
    cert = os.getenv("REPLICATION_TLS_CERT_FILE", "")
    key = os.getenv("REPLICATION_TLS_KEY_FILE", "")
    if not cert or not key:
        logger.error(
            "REPLICATION_TLS_CERT_FILE / REPLICATION_TLS_KEY_FILE no configurados en .env — "
            "el receptor necesita un certificado TLS (uno autofirmado sirve; el emisor lo "
            "valida por fingerprint fijado en el panel, no contra una CA pública)."
        )
        sys.exit(1)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    return ctx


def _send_frame(sock: ssl.SSLSocket, data: bytes) -> None:
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_frame(sock: ssl.SSLSocket) -> bytes:
    (length,) = struct.unpack(">I", _recv_exact(sock, 4))
    return _recv_exact(sock, length)


def _recv_exact(sock: ssl.SSLSocket, n: int) -> bytes:
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Conexión cerrada antes de recibir los datos esperados")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _handle_connection(tls_sock: ssl.SSLSocket, addr) -> None:
    batch_id = None
    try:
        tls_sock.settimeout(IO_TIMEOUT)

        header = json.loads(_recv_frame(tls_sock).decode("utf-8"))
        batch_id = header.get("batch_id")
        table = header.get("table")

        if table not in REPLICABLE_TABLE_NAMES:
            raise ValueError(f"Tabla no reconocida/replicable: {table}")

        encrypted = _recv_frame(tls_sock)
        associated_data = f"{table}:{batch_id}".encode("utf-8")
        # decrypt() valida el tag de autenticación de AES-GCM: si el batch
        # fue alterado en tránsito, o la llave no coincide con la del
        # emisor, lanza cryptography.exceptions.InvalidTag acá.
        plaintext = decrypt(encrypted, associated_data=associated_data)
        batch = deserialize_batch(plaintext)

        applied = apply_batch(table, batch["rows"])

        logger.info(
            f"[replication-receiver] {addr[0]} — {table}: {applied} fila(s) procesadas (batch {batch_id})"
        )
        _send_frame(tls_sock, json.dumps({"ok": True, "batch_id": batch_id}).encode("utf-8"))

    except Exception as exc:
        logger.warning(f"[replication-receiver] ERROR de {addr[0]}: {exc}")
        try:
            _send_frame(
                tls_sock,
                json.dumps({"ok": False, "batch_id": batch_id, "error": str(exc)}).encode("utf-8"),
            )
        except Exception:
            pass
    finally:
        try:
            tls_sock.close()
        except Exception:
            pass


def main() -> None:
    ctx = _build_server_context()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((LISTEN_HOST, LISTEN_PORT))
    server_sock.listen(20)

    logger.info(f"[replication-receiver] Escuchando en {LISTEN_HOST}:{LISTEN_PORT}")

    try:
        while True:
            raw_sock, addr = server_sock.accept()
            try:
                tls_sock = ctx.wrap_socket(raw_sock, server_side=True)
            except ssl.SSLError as exc:
                logger.warning(f"[replication-receiver] Handshake TLS fallido con {addr[0]}: {exc}")
                raw_sock.close()
                continue
            threading.Thread(target=_handle_connection, args=(tls_sock, addr), daemon=True).start()
    except KeyboardInterrupt:
        logger.info("[replication-receiver] Cerrando...")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()

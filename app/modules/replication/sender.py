"""
app/modules/replication/sender.py

Envía un batch cifrado a un destino de replicación por TLS, con un
protocolo simple de frames longitud-prefijada y un ACK del receptor antes
de dar el batch por confirmado. Ver app/pipeline/replication_receiver.py
(en la instancia destino) para el lado que recibe.
"""
from __future__ import annotations

import hashlib
import json
import socket
import ssl
import struct

CONNECT_TIMEOUT = 10
IO_TIMEOUT = 30


def _build_ssl_context(pinned: bool) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if pinned:
        # Pinning manual del certificado (ver _verify_fingerprint): no depende
        # de una CA pública, apropiado para dos máquinas propias.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_default_certs()
    return ctx


def _verify_fingerprint(tls_sock: ssl.SSLSocket, expected: str) -> None:
    der = tls_sock.getpeercert(binary_form=True)
    if der is None:
        raise ssl.SSLCertVerificationError("El receptor no presentó certificado TLS")
    actual = hashlib.sha256(der).hexdigest()
    if actual.lower() != expected.lower().replace(":", ""):
        raise ssl.SSLCertVerificationError(
            f"Fingerprint del certificado no coincide: esperado {expected}, recibido {actual}"
        )


def test_connection(host: str, port: int, expected_fingerprint: str | None = None) -> None:
    """
    Abre un canal TLS contra el destino sin mandar ningún batch — solo
    valida que se puede conectar (y que el fingerprint coincide, si está
    fijado). Lanza excepción si falla. Usado por el botón "Probar conexión"
    del panel de configuración.
    """
    ctx = _build_ssl_context(pinned=bool(expected_fingerprint))
    with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as raw_sock:
        with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            if expected_fingerprint:
                _verify_fingerprint(tls_sock, expected_fingerprint)


def send_batch(
    host: str,
    port: int,
    table: str,
    encrypted_payload: bytes,
    batch_id: str,
    expected_fingerprint: str | None = None,
) -> None:
    """
    Manda un batch cifrado y espera el ACK del receptor.
    Lanza excepción si falla la conexión, el TLS, o no llega ACK — el
    llamador (service.py) decide si reintenta en la próxima corrida; el
    watermark solo avanza si esta función retorna sin error.
    """
    ctx = _build_ssl_context(pinned=bool(expected_fingerprint))

    with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as raw_sock:
        with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            tls_sock.settimeout(IO_TIMEOUT)

            if expected_fingerprint:
                _verify_fingerprint(tls_sock, expected_fingerprint)

            header = json.dumps({"batch_id": batch_id, "table": table}).encode("utf-8")
            _send_frame(tls_sock, header)
            _send_frame(tls_sock, encrypted_payload)

            ack_raw = _recv_frame(tls_sock)
            ack = json.loads(ack_raw.decode("utf-8"))
            if not ack.get("ok") or ack.get("batch_id") != batch_id:
                raise RuntimeError(f"ACK inválido o negativo del receptor: {ack}")


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

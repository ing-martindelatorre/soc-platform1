"""
app/modules/replication/crypto.py

Cifrado autenticado (AES-256-GCM) de los batches de replicación. La llave
vive en REPLICATION_ENC_KEY (.env), nunca en la base de datos ni en git —
debe ser la misma en el emisor y en el receptor.

Generar una llave nueva:
    python -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"
"""
from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12  # 96 bits — tamaño recomendado para GCM


def _load_key() -> bytes:
    raw = os.getenv("REPLICATION_ENC_KEY", "")
    if not raw:
        raise RuntimeError(
            "REPLICATION_ENC_KEY no está definida en .env. Generar con: "
            'python -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"'
        )
    key = base64.b64decode(raw)
    if len(key) != 32:
        raise RuntimeError("REPLICATION_ENC_KEY debe decodificar a 32 bytes (AES-256)")
    return key


def encrypt(plaintext: bytes, associated_data: bytes = b"") -> bytes:
    """Devuelve nonce(12) || ciphertext+tag, listo para mandar por la red."""
    key = _load_key()
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext


def decrypt(payload: bytes, associated_data: bytes = b"") -> bytes:
    """
    Inverso de encrypt(). Lanza cryptography.exceptions.InvalidTag si el
    payload fue alterado en tránsito o la llave no coincide con la del emisor.
    """
    key = _load_key()
    nonce, ciphertext = payload[:NONCE_SIZE], payload[NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data)

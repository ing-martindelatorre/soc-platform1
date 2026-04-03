from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def stable_hash(data: dict) -> str:
    raw = json.dumps(data, sort_keys=True, default=str).encode()
    return hashlib.sha256(raw).hexdigest()


def safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
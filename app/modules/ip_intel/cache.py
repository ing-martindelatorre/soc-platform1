"""
Caché persistente de reputación de IPs en PostgreSQL.
TTL por defecto: 7 días (configurable con IP_INTEL_CACHE_TTL_HOURS).
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

import psycopg2
from psycopg2.extras import RealDictCursor

CACHE_TTL_HOURS = int(os.getenv("IP_INTEL_CACHE_TTL_HOURS", "168"))


def _get_conn():
    return psycopg2.connect(
        host=os.environ["DB_HOST"],
        port=os.environ["DB_PORT"],
        dbname=os.environ["DB_NAME"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
    )


def ensure_table() -> None:
    """Crea la tabla de caché si no existe."""
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS ip_reputation_cache (
                        ip           VARCHAR(45)  PRIMARY KEY,
                        asn          TEXT,
                        org          TEXT,
                        country      VARCHAR(10),
                        hostnames    JSONB        NOT NULL DEFAULT '[]',
                        tags         JSONB        NOT NULL DEFAULT '[]',
                        vulns        JSONB        NOT NULL DEFAULT '[]',
                        is_trusted   BOOLEAN      NOT NULL DEFAULT FALSE,
                        trust_reason TEXT,
                        source       TEXT         NOT NULL DEFAULT 'shodan+ipinfo',
                        checked_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
                    )
                """)
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_ip_rep_cache_checked
                    ON ip_reputation_cache (checked_at)
                """)
    finally:
        conn.close()


def get_cached(ip: str) -> dict[str, Any] | None:
    """Retorna entrada de caché si existe y no expiró, o None."""
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT * FROM ip_reputation_cache
                WHERE ip = %s
                  AND checked_at >= NOW() - INTERVAL '{CACHE_TTL_HOURS} hours'
                """,
                (ip,),
            )
            row = cur.fetchone()
            if row:
                d = dict(row)
                # psycopg2 devuelve JSONB como dict/list ya parseado
                for field in ("hostnames", "tags", "vulns"):
                    if isinstance(d.get(field), str):
                        d[field] = json.loads(d[field])
                return d
    finally:
        conn.close()
    return None


def save_cache(ip: str, data: dict[str, Any]) -> None:
    """Inserta o actualiza entrada de caché para una IP."""
    conn = _get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO ip_reputation_cache
                        (ip, asn, org, country, hostnames, tags, vulns,
                         is_trusted, trust_reason, source, checked_at)
                    VALUES (%s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb,
                            %s, %s, %s, %s)
                    ON CONFLICT (ip) DO UPDATE SET
                        asn=EXCLUDED.asn,
                        org=EXCLUDED.org,
                        country=EXCLUDED.country,
                        hostnames=EXCLUDED.hostnames,
                        tags=EXCLUDED.tags,
                        vulns=EXCLUDED.vulns,
                        is_trusted=EXCLUDED.is_trusted,
                        trust_reason=EXCLUDED.trust_reason,
                        source=EXCLUDED.source,
                        checked_at=EXCLUDED.checked_at
                    """,
                    (
                        ip,
                        data.get("asn"),
                        data.get("org"),
                        data.get("country"),
                        json.dumps(data.get("hostnames", [])),
                        json.dumps(data.get("tags", [])),
                        json.dumps(data.get("vulns", [])),
                        bool(data.get("is_trusted", False)),
                        data.get("trust_reason"),
                        data.get("source", "shodan+ipinfo"),
                        datetime.now(timezone.utc),
                    ),
                )
    finally:
        conn.close()

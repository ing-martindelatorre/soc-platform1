"""
app/pipeline/cleanup.py

Limpieza periódica de datos históricos.
Cada tabla tiene una política de retención configurable via .env.
"""
from __future__ import annotations

import logging
import os

from app.core.db import get_connection

logger = logging.getLogger("soc-platform")

# (tabla, columna_fecha, variable_de_entorno, días_por_defecto)
RETENTION_POLICIES: list[tuple[str, str, str, int]] = [
    ("sentinel_incidents", "created_at",   "RETENTION_SENTINEL_DAYS",    90),
    ("snyk_findings",      "created_at",   "RETENTION_SNYK_DAYS",       180),
    ("nmap_findings",      "created_at",   "RETENTION_NMAP_DAYS",        90),
    ("nmap_assets",        "last_seen",    "RETENTION_NMAP_ASSETS_DAYS", 180),
    ("fortinet_threats",   "collected_at", "RETENTION_FORTINET_DAYS",   365),
    ("job_runs",           "started_at",   "RETENTION_JOB_RUNS_DAYS",    30),
    ("alert_log",          "sent_at",      "RETENTION_ALERT_LOG_DAYS",  365),
]


def run_data_cleanup() -> dict:
    """
    Borra registros más antiguos que el umbral configurado en cada tabla.

    Variables de entorno (días de retención):
      RETENTION_SENTINEL_DAYS    (default 90)
      RETENTION_SNYK_DAYS        (default 180)
      RETENTION_NMAP_DAYS        (default 90)
      RETENTION_NMAP_ASSETS_DAYS (default 180)
      RETENTION_FORTINET_DAYS    (default 365)
      RETENTION_JOB_RUNS_DAYS    (default 30)
      RETENTION_ALERT_LOG_DAYS   (default 365)
    """
    results: dict[str, dict] = {}
    total_deleted = 0

    conn = get_connection()
    cur  = conn.cursor()

    for table, col, env_var, default_days in RETENTION_POLICIES:
        days = int(os.getenv(env_var, str(default_days)))
        try:
            cur.execute(
                f"DELETE FROM {table} WHERE {col} < NOW() - make_interval(days => %s)",
                (days,),
            )
            deleted = cur.rowcount
            results[table] = {"deleted": deleted, "retention_days": days}
            if deleted > 0:
                logger.info(f"[cleanup] {table}: {deleted} registros eliminados (>{days}d)")
            total_deleted += deleted
        except Exception as e:
            logger.error(f"[cleanup] Error limpiando {table}: {e}")
            conn.rollback()
            results[table] = {"error": str(e), "retention_days": days}
            # Reconectar para continuar con las demás tablas
            conn = get_connection()
            cur  = conn.cursor()
            continue

    conn.commit()
    cur.close()
    conn.close()

    logger.info(f"[cleanup] Limpieza completada — {total_deleted} registros eliminados en total")
    return {"ok": True, "total_deleted": total_deleted, "tables": results}

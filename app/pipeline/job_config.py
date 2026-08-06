"""
app/pipeline/job_config.py

Persistencia y validación de los intervalos de recolección configurables
desde el panel (tabla `job_config`). Separa la parte "fija" de cada job
(qué pipeline ejecuta, con qué argumentos) de la parte "configurable"
(cada cuánto corre), que vive en base de datos y puede cambiarse en
caliente desde el dashboard sin reiniciar el scheduler.
"""

from __future__ import annotations

from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from app.core.db import db_connection

TIMEZONE = "America/Mexico_City"

# Límites de sanidad para intervalos en minutos: al menos 1 minuto,
# como mucho una semana (10080 min) para evitar valores sin sentido.
MIN_INTERVAL_MINUTES = 1
MAX_INTERVAL_MINUTES = 10080

# Partes fijas de cada job de recolección (qué ejecuta y con qué kwargs).
# El intervalo/cron vive en la tabla job_config y es lo único editable
# desde el panel.
JOB_DEFINITIONS: list[dict] = [
    {
        "job_id": "sentinel_job", "args": ["sentinel"], "kwargs": {},
        "misfire_grace_time": 60, "start_offset_minutes": 0,
        "label": "Sentinel",
        "default_schedule_type": "interval", "default_schedule_value": "5",
    },
    {
        "job_id": "fortinet_config_job", "args": ["fortinet"], "kwargs": {"mode": "config"},
        "misfire_grace_time": 120, "start_offset_minutes": 0,
        "label": "Fortinet — Configuración",
        "default_schedule_type": "interval", "default_schedule_value": "15",
    },
    {
        "job_id": "fortinet_logs_job", "args": ["fortinet"], "kwargs": {"mode": "logs"},
        "misfire_grace_time": 120, "start_offset_minutes": 7,
        "label": "Fortinet — Logs",
        "default_schedule_type": "interval", "default_schedule_value": "15",
    },
    {
        "job_id": "fortinet_threats_job", "args": ["fortinet"], "kwargs": {"mode": "threats"},
        "misfire_grace_time": 60, "start_offset_minutes": 0,
        "label": "Fortinet — Amenazas",
        "default_schedule_type": "interval", "default_schedule_value": "5",
    },
    {
        "job_id": "nmap_quick_job", "args": ["nmap"], "kwargs": {"profile_override": "quick"},
        "misfire_grace_time": 300, "start_offset_minutes": 0,
        "label": "Nmap — Escaneo rápido",
        "default_schedule_type": "interval", "default_schedule_value": "360",
    },
    {
        "job_id": "nmap_deep_job", "args": ["nmap"], "kwargs": {"profile_override": "full_tcp"},
        "misfire_grace_time": 600, "start_offset_minutes": 0,
        "label": "Nmap — Escaneo completo",
        "default_schedule_type": "cron", "default_schedule_value": "0 2 * * 0",
    },
    {
        "job_id": "snyk_job", "args": ["snyk"], "kwargs": {},
        "misfire_grace_time": 600, "start_offset_minutes": 0,
        "label": "Snyk",
        "default_schedule_type": "cron", "default_schedule_value": "0 1 * * *",
    },
    {
        "job_id": "cpanel_stats_job", "args": ["cpanel"], "kwargs": {"mode": "stats"},
        "misfire_grace_time": 120, "start_offset_minutes": 0,
        "label": "cPanel — Estadísticas",
        "default_schedule_type": "interval", "default_schedule_value": "15",
    },
    {
        "job_id": "cpanel_security_job", "args": ["cpanel"], "kwargs": {"mode": "security"},
        "misfire_grace_time": 120, "start_offset_minutes": 5,
        "label": "cPanel — Seguridad (cPHulk)",
        "default_schedule_type": "interval", "default_schedule_value": "15",
    },
    {
        "job_id": "cpanel_accounts_job", "args": ["cpanel"], "kwargs": {"mode": "accounts"},
        "misfire_grace_time": 300, "start_offset_minutes": 0,
        "label": "cPanel — Cuentas",
        "default_schedule_type": "interval", "default_schedule_value": "60",
    },
    {
        "job_id": "cpanel_logs_job", "args": ["cpanel"], "kwargs": {"mode": "logs"},
        "misfire_grace_time": 300, "start_offset_minutes": 0,
        "label": "cPanel — Logs SSH",
        "default_schedule_type": "interval", "default_schedule_value": "30",
    },
]

JOB_DEFINITIONS_BY_ID: dict[str, dict] = {jd["job_id"]: jd for jd in JOB_DEFINITIONS}


def validate_schedule(schedule_type: str, schedule_value: str) -> None:
    """Lanza ValueError con mensaje en español si la combinación no es válida."""
    if schedule_type == "interval":
        try:
            minutes = int(schedule_value)
        except (TypeError, ValueError):
            raise ValueError("El intervalo debe ser un número entero de minutos")
        if not (MIN_INTERVAL_MINUTES <= minutes <= MAX_INTERVAL_MINUTES):
            raise ValueError(
                f"El intervalo debe estar entre {MIN_INTERVAL_MINUTES} y "
                f"{MAX_INTERVAL_MINUTES} minutos"
            )
    elif schedule_type == "cron":
        try:
            CronTrigger.from_crontab(schedule_value, timezone=TIMEZONE)
        except Exception as exc:
            raise ValueError(f"Expresión cron inválida: {exc}")
    else:
        raise ValueError("schedule_type debe ser 'interval' o 'cron'")


def build_trigger(schedule_type: str, schedule_value: str, start_date=None):
    """Construye el trigger de APScheduler correspondiente. Asume valores ya validados."""
    if schedule_type == "interval":
        return IntervalTrigger(minutes=int(schedule_value), start_date=start_date)
    if schedule_type == "cron":
        return CronTrigger.from_crontab(schedule_value, timezone=TIMEZONE)
    raise ValueError("schedule_type debe ser 'interval' o 'cron'")


def get_all_schedules() -> dict[str, dict]:
    """
    Devuelve {job_id: fila} para todos los jobs en JOB_DEFINITIONS,
    sembrando en la tabla cualquier job que aún no tenga fila (primer arranque
    en un ambiente sin la migración 025 aplicada a mano, o un job nuevo).
    """
    with db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM job_config")
            rows = {r["job_name"]: dict(r) for r in cur.fetchall()}

            missing = [jd for jd in JOB_DEFINITIONS if jd["job_id"] not in rows]
            for jd in missing:
                cur.execute(
                    """
                    INSERT INTO job_config (job_name, enabled, schedule_type, schedule_value, label)
                    VALUES (%s, TRUE, %s, %s, %s)
                    ON CONFLICT (job_name) DO NOTHING
                    RETURNING *
                    """,
                    (jd["job_id"], jd["default_schedule_type"], jd["default_schedule_value"], jd["label"]),
                )
                row = cur.fetchone()
                if row:
                    rows[jd["job_id"]] = dict(row)

    return rows


def update_schedule(job_id: str, schedule_type: str, schedule_value: str, enabled: bool) -> None:
    """Valida y persiste el nuevo horario de un job. Lanza ValueError si algo es inválido."""
    if job_id not in JOB_DEFINITIONS_BY_ID:
        raise ValueError(f"Job desconocido: {job_id}")

    validate_schedule(schedule_type, schedule_value)

    with db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE job_config
                SET schedule_type = %s, schedule_value = %s, enabled = %s, updated_at = NOW()
                WHERE job_name = %s
                """,
                (schedule_type, schedule_value, enabled, job_id),
            )

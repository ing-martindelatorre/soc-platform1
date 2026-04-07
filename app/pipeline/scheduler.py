"""
app/pipeline/scheduler.py

Motor de recolección del SOC Platform.
Ejecuta cada pipeline con su frecuencia propia e independiente.

Frecuencias de recolección (traer datos nuevos desde las fuentes):
  - Sentinel:  cada 5 minutos   (amenazas en tiempo real)
  - Fortinet:  cada 15 minutos  (logs y config)
  - Nmap quick: cada 6 horas   (discovery de red)
  - Nmap deep:  domingos 2am   (scan completo)
  - Snyk:       domingos 1am   (scans pesados de repos)

Uso:
    cd ~/soc-platform
    source venv/bin/activate
    set -a; source .env; set +a
    python3 -m app.pipeline.scheduler
"""

import traceback
from datetime import datetime

from apscheduler.schedulers.blocking import BlockingScheduler

from app.core.db import get_connection
from app.pipeline.runner import run_pipeline


# =============================================================================
# Registro de ejecuciones en DB
# =============================================================================

def register_job_start(job_name: str) -> int:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO job_runs (job_name, status, started_at)
        VALUES (%s, %s, %s)
        RETURNING id
        """,
        (job_name, "running", datetime.now()),
    )
    run_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return run_id


def register_job_end(run_id: int, status: str, message: str = "") -> None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE job_runs
        SET status      = %s,
            finished_at = %s,
            message     = %s
        WHERE id = %s
        """,
        (status, datetime.now(), message[:5000], run_id),
    )
    conn.commit()
    cur.close()
    conn.close()


def execute_job(job_name: str, **kwargs) -> None:
    """
    Ejecuta un pipeline registrando inicio y fin en la tabla job_runs.
    """
    run_id = register_job_start(job_name)
    started = datetime.now()

    try:
        result = run_pipeline(job_name, **kwargs)
        elapsed = (datetime.now() - started).seconds
        register_job_end(run_id, "success", str(result)[:5000])
        print(f"[OK] {job_name} | {elapsed}s | {result.get('message', '')}")

    except Exception as exc:
        elapsed = (datetime.now() - started).seconds
        error_text = f"{exc}\n{traceback.format_exc()}"
        register_job_end(run_id, "failed", error_text[:5000])
        print(f"[ERROR] {job_name} | {elapsed}s | {exc}")


# =============================================================================
# Main
# =============================================================================

def main() -> None:
    scheduler = BlockingScheduler(timezone="America/Mexico_City")

    # -------------------------------------------------------------------------
    # SENTINEL — cada 5 minutos
    # Justificación: alertas y amenazas en tiempo real
    # -------------------------------------------------------------------------
    scheduler.add_job(
        execute_job,
        trigger="interval",
        minutes=5,
        args=["sentinel"],
        id="sentinel_job",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
        misfire_grace_time=60,
    )

    # -------------------------------------------------------------------------
    # FORTINET config — cada 15 minutos
    # Justificación: cambios de configuración y logs de tráfico
    # -------------------------------------------------------------------------
    scheduler.add_job(
        execute_job,
        trigger="interval",
        minutes=15,
        args=["fortinet"],
        kwargs={"mode": "config"},
        id="fortinet_config_job",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
        misfire_grace_time=120,
    )

    # -------------------------------------------------------------------------
    # FORTINET logs — cada 15 minutos (offset de 7 min para no coincidir)
    # -------------------------------------------------------------------------
    scheduler.add_job(
        execute_job,
        trigger="interval",
        minutes=15,
        args=["fortinet"],
        kwargs={"mode": "logs"},
        id="fortinet_logs_job",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
        misfire_grace_time=120,
        start_date=datetime.now().replace(minute=(datetime.now().minute + 7) % 60),
    )

    # -------------------------------------------------------------------------
    # NMAP quick — cada 6 horas
    # Justificación: discovery rápido de activos, no requiere ser frecuente
    # -------------------------------------------------------------------------
    scheduler.add_job(
        execute_job,
        trigger="interval",
        hours=6,
        args=["nmap"],
        id="nmap_quick_job",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
        misfire_grace_time=300,
    )

    # -------------------------------------------------------------------------
    # NMAP deep — domingos a las 2am
    # Justificación: scan completo semanal para auditoría
    # -------------------------------------------------------------------------
    scheduler.add_job(
        execute_job,
        trigger="cron",
        day_of_week="sun",
        hour=2,
        minute=0,
        args=["nmap"],
        id="nmap_deep_job",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
        misfire_grace_time=600,
    )

    # -------------------------------------------------------------------------
    # SNYK — domingos a la 1am
    # Justificación: scans pesados de repositorios, semanal es suficiente
    # -------------------------------------------------------------------------
    scheduler.add_job(
        execute_job,
        trigger="cron",
        day_of_week="sun",
        hour=1,
        minute=0,
        args=["snyk"],
        id="snyk_job",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
        misfire_grace_time=600,
    )

    print("=" * 55)
    print("  SOC Platform — Scheduler de Recolección")
    print("=" * 55)
    print("  Módulo           Frecuencia")
    print("  ─────────────────────────────────────")
    print("  Sentinel         cada 5 minutos")
    print("  Fortinet config  cada 15 minutos")
    print("  Fortinet logs    cada 15 minutos")
    print("  Nmap quick       cada 6 horas")
    print("  Nmap deep        domingos 02:00")
    print("  Snyk             domingos 01:00")
    print("=" * 55)
    print("  Ctrl+C para detener\n")

    scheduler.start()


if __name__ == "__main__":
    main()

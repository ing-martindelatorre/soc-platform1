"""
app/pipeline/scheduler.py

Motor de recolección del SOC Platform.
Ejecuta cada pipeline con su frecuencia propia e independiente.

Las frecuencias de los jobs de recolección (Sentinel, Fortinet, Nmap, Snyk,
cPanel) ya NO están hardcodeadas aquí: se leen de la tabla `job_config`
(ver app/pipeline/job_config.py) y pueden cambiarse en caliente desde el
panel de configuración del dashboard — el job `config_watcher_job` revisa
esa tabla cada 30s y reprograma/pausa/reanuda los jobs sin reiniciar este
proceso.
"""

import traceback
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.blocking import BlockingScheduler

from app.alerts.engine import evaluate_and_send, evaluate_job_failures
from app.core.db import get_connection
from app.pipeline.cleanup import run_data_cleanup
from app.pipeline.job_config import JOB_DEFINITIONS, build_trigger, get_all_schedules
from app.pipeline.runner import run_pipeline


# =============================================================================
# Registro de ejecuciones en DB
# =============================================================================

def register_job_start(job_name: str) -> int:
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute(
        """
        INSERT INTO job_runs (job_name, status, started_at)
        VALUES (%s, %s, %s)
        RETURNING id
        """,
        (job_name, "running", datetime.now(timezone.utc)),
    )
    run_id = cur.fetchone()["id"]
    conn.commit()
    cur.close()
    conn.close()
    return run_id


def register_job_end(run_id: int, status: str, message: str = "") -> None:
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute(
        """
        UPDATE job_runs
        SET status      = %s,
            finished_at = %s,
            message     = %s
        WHERE id = %s
        """,
        (status, datetime.now(timezone.utc), message[:5000], run_id),
    )
    conn.commit()
    cur.close()
    conn.close()


def execute_cleanup_job() -> None:
    try:
        result = run_data_cleanup()
        print(f"[cleanup] {result.get('total_deleted', 0)} registros eliminados")
    except Exception as exc:
        print(f"[cleanup] ERROR: {exc}")


def execute_alert_job() -> None:
    try:
        sent = evaluate_and_send()
        if sent > 0:
            print(f"[alerts] {sent} alerta(s) enviada(s)")
    except Exception as exc:
        print(f"[alerts] ERROR en reglas: {exc}")

    try:
        sent_failures = evaluate_job_failures()
        if sent_failures > 0:
            print(f"[alerts] {sent_failures} alerta(s) de pipeline enviada(s)")
    except Exception as exc:
        print(f"[alerts] ERROR en fallos de pipeline: {exc}")


# =============================================================================
# Aplicación en caliente de cambios de intervalo (panel de configuración)
# =============================================================================

# Cache en memoria de (schedule_type, schedule_value, enabled) por job,
# para detectar cambios sin reprogramar de más en cada tick.
_applied_schedules: dict[str, tuple] = {}


def sync_job_schedules(scheduler: BlockingScheduler) -> None:
    try:
        schedules = get_all_schedules()
    except Exception as exc:
        print(f"[config] ERROR leyendo job_config: {exc}")
        return

    for job_id, row in schedules.items():
        current = (row["schedule_type"], row["schedule_value"], row["enabled"])
        previous = _applied_schedules.get(job_id)

        if previous == current:
            continue

        try:
            if row["enabled"]:
                if previous is None or previous[:2] != current[:2]:
                    trigger = build_trigger(row["schedule_type"], row["schedule_value"])
                    scheduler.reschedule_job(job_id, trigger=trigger)
                    print(f"[config] {job_id}: intervalo actualizado a {row['schedule_type']}={row['schedule_value']}")
                if previous is not None and not previous[2]:
                    scheduler.resume_job(job_id)
                    print(f"[config] {job_id}: reactivado")
            else:
                scheduler.pause_job(job_id)
                print(f"[config] {job_id}: desactivado")

            _applied_schedules[job_id] = current
        except Exception as exc:
            print(f"[config] ERROR aplicando cambio a {job_id}: {exc}")


def execute_job(job_name: str, **kwargs) -> None:
    run_id  = register_job_start(job_name)
    started = datetime.now(timezone.utc)

    try:
        result  = run_pipeline(job_name, **kwargs)
        elapsed = (datetime.now(timezone.utc) - started).seconds

        # Varios módulos (Fortinet, cPanel, Nmap y los _Fallback del registry)
        # capturan sus errores y devuelven ok=False en lugar de lanzar
        # excepción; sin este chequeo quedarían registrados como "success".
        if result.get("ok") is False:
            detalle = result.get("error") or str(result)
            register_job_end(run_id, "failed", str(result)[:5000])
            print(f"[ERROR] {job_name} | {elapsed}s | {str(detalle)[:300]}")
            return

        register_job_end(run_id, "success", str(result)[:5000])
        print(f"[OK] {job_name} | {elapsed}s | {result.get('message', '')}")

    except Exception as exc:
        elapsed    = (datetime.now(timezone.utc) - started).seconds
        error_text = f"{exc}\n{traceback.format_exc()}"
        register_job_end(run_id, "failed", error_text[:5000])
        print(f"[ERROR] {job_name} | {elapsed}s | {exc}")


# =============================================================================
# Main
# =============================================================================

def main() -> None:
    scheduler = BlockingScheduler(timezone="America/Mexico_City")

    now = datetime.now(timezone.utc)

    # ── JOBS DE RECOLECCIÓN — Sentinel, Fortinet, Nmap, Snyk, cPanel ─────────
    # Frecuencia leída de job_config (ver app/pipeline/job_config.py);
    # config_watcher_job la reaplica en caliente si cambia desde el panel.
    schedules = get_all_schedules()

    for jd in JOB_DEFINITIONS:
        job_id = jd["job_id"]
        row    = schedules[job_id]

        start_date = None
        if jd["start_offset_minutes"]:
            start_date = now + timedelta(minutes=jd["start_offset_minutes"])

        trigger = build_trigger(row["schedule_type"], row["schedule_value"], start_date=start_date)

        scheduler.add_job(
            execute_job, trigger=trigger,
            args=jd["args"], kwargs=jd["kwargs"],
            id=job_id, replace_existing=True,
            max_instances=1, coalesce=True,
            misfire_grace_time=jd["misfire_grace_time"],
        )
        if not row["enabled"]:
            scheduler.pause_job(job_id)

        _applied_schedules[job_id] = (row["schedule_type"], row["schedule_value"], row["enabled"])

    # ── WATCHER DE CONFIGURACIÓN — cada 30s ──────────────────────────────────
    # Revisa job_config y aplica cambios de intervalo/enabled en caliente.
    scheduler.add_job(
        sync_job_schedules, trigger="interval", seconds=30,
        args=[scheduler],
        id="config_watcher_job", replace_existing=True,
        max_instances=1, coalesce=True, misfire_grace_time=30,
    )

    # ── MOTOR DE ALERTAS — cada 5 minutos ────────────────────────────────────
    scheduler.add_job(
        execute_alert_job, trigger="interval", minutes=5,
        id="alert_engine_job", replace_existing=True,
        max_instances=1, coalesce=True, misfire_grace_time=60,
    )

    # ── LIMPIEZA DE DATOS — diaria 3am ───────────────────────────────────────
    scheduler.add_job(
        execute_cleanup_job, trigger="cron", hour=3, minute=0,
        id="cleanup_job", replace_existing=True,
        max_instances=1, coalesce=True, misfire_grace_time=1800,
    )

    print("=" * 55)
    print("  SOC Platform — Scheduler de Recolección")
    print("=" * 55)
    print("  Job                          Config actual")
    print("  ──────────────────────────────────────────")
    for jd in JOB_DEFINITIONS:
        row    = schedules[jd["job_id"]]
        estado = "" if row["enabled"] else " (desactivado)"
        valor  = f"{row['schedule_type']}={row['schedule_value']}{estado}"
        print(f"  {jd['label']:<28} {valor}")
    print("  Motor de alertas             cada 5 minutos")
    print("  Limpieza de datos            diaria 03:00")
    print("=" * 55)
    print("  Los intervalos de arriba se pueden cambiar en caliente")
    print("  desde el panel de configuración (config_watcher_job, cada 30s)")
    print("  Ctrl+C para detener\n")

    scheduler.start()


if __name__ == "__main__":
    main()

import traceback
from datetime import datetime

from apscheduler.schedulers.blocking import BlockingScheduler

from app.core.db import get_connection
from app.pipeline.runner import run_pipeline


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
        SET status = %s,
            finished_at = %s,
            message = %s
        WHERE id = %s
        """,
        (status, datetime.now(), message, run_id),
    )
    conn.commit()
    cur.close()
    conn.close()


def execute_job(job_name: str) -> None:
    run_id = register_job_start(job_name)

    try:
        result = run_pipeline(job_name)
        register_job_end(run_id, "success", str(result))
        print(f"[OK] Job {job_name} ejecutado correctamente")
    except Exception as exc:
        error_text = f"{exc}\n{traceback.format_exc()}"
        register_job_end(run_id, "failed", error_text)
        print(f"[ERROR] Job {job_name}: {exc}")


def main() -> None:
    scheduler = BlockingScheduler()

    scheduler.add_job(
        execute_job,
        trigger="interval",
        minutes=1,
        args=["sentinel"],
        id="sentinel_job",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )

    scheduler.add_job(
        execute_job,
        trigger="interval",
        hours=1,
        args=["nmap"],
        id="nmap_job",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )

    scheduler.add_job(
        execute_job,
        trigger="cron",
        day_of_week="sun",
        hour=0,
        minute=0,
        args=["snyk"],
        id="snyk_job",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )

    print("Scheduler SOC iniciado")
    print(" - Sentinel: cada minuto")
    print(" - Nmap: cada hora")
    print(" - Snyk: cada domingo a las 00:00")

    scheduler.start()


if __name__ == "__main__":
    main()
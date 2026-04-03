-- =============================================================================
-- 009_job_runs.sql
-- Tabla de registro de ejecuciones del scheduler.
-- Usada por app/pipeline/scheduler.py
-- =============================================================================

CREATE TABLE IF NOT EXISTS job_runs (
    id          BIGSERIAL PRIMARY KEY,
    job_name    VARCHAR(100)  NOT NULL,
    status      VARCHAR(20)   NOT NULL DEFAULT 'running',  -- running | success | failed
    started_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ   NULL,
    message     TEXT          NULL
);

CREATE INDEX IF NOT EXISTS idx_job_runs_job_name
    ON job_runs (job_name);

CREATE INDEX IF NOT EXISTS idx_job_runs_status
    ON job_runs (status);

CREATE INDEX IF NOT EXISTS idx_job_runs_started_at
    ON job_runs (started_at DESC);

-- Vista útil para ver el último resultado de cada job
CREATE OR REPLACE VIEW v_job_runs_latest AS
SELECT DISTINCT ON (job_name)
    id,
    job_name,
    status,
    started_at,
    finished_at,
    EXTRACT(EPOCH FROM (finished_at - started_at))::int AS duration_seconds,
    LEFT(message, 200) AS message_preview
FROM job_runs
ORDER BY job_name, started_at DESC;

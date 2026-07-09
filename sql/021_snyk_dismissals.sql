-- Permite marcar vulnerabilidades de Snyk como revisadas/descartadas por aplicación (repo_name)
-- para que dejen de contar en las vistas activas del dashboard sin borrar el hallazgo original.

CREATE TABLE IF NOT EXISTS snyk_dismissals (
    id BIGSERIAL PRIMARY KEY,
    repo_name TEXT NOT NULL,
    issue_id TEXT NOT NULL,
    is_dismissed BOOLEAN NOT NULL DEFAULT TRUE,
    reason TEXT NOT NULL DEFAULT '',
    dismissed_by TEXT,
    dismissed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_snyk_dismissals_repo_issue
    ON snyk_dismissals (repo_name, issue_id);

CREATE INDEX IF NOT EXISTS idx_snyk_dismissals_is_dismissed
    ON snyk_dismissals (is_dismissed);

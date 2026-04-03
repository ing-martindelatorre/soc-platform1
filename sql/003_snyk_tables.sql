CREATE TABLE IF NOT EXISTS snyk_scans (
    id BIGSERIAL PRIMARY KEY,
    repo_name TEXT NOT NULL,
    repo_path TEXT NOT NULL,
    scan_type TEXT NOT NULL CHECK (scan_type IN ('code', 'sca')),
    command TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ NOT NULL,
    duration_seconds DOUBLE PRECISION NOT NULL,
    return_code INTEGER NOT NULL,
    success BOOLEAN NOT NULL,
    raw_file_path TEXT,
    stderr_file_path TEXT,
    stdout_is_json BOOLEAN NOT NULL DEFAULT FALSE,
    findings_count INTEGER,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_snyk_scans_repo_name
    ON snyk_scans (repo_name);

CREATE INDEX IF NOT EXISTS idx_snyk_scans_scan_type
    ON snyk_scans (scan_type);

CREATE INDEX IF NOT EXISTS idx_snyk_scans_finished_at
    ON snyk_scans (finished_at);


CREATE TABLE IF NOT EXISTS snyk_findings (
    id BIGSERIAL PRIMARY KEY,
    repo_name TEXT NOT NULL,
    scan_type TEXT NOT NULL CHECK (scan_type IN ('code', 'sca')),
    issue_id TEXT NOT NULL,
    severity TEXT,
    title TEXT,
    description TEXT,
    package_name TEXT,
    version TEXT,
    cve TEXT,
    project_name TEXT,
    file_path TEXT NOT NULL DEFAULT '',
    line INTEGER,
    rule_id TEXT,
    language TEXT,
    exploit_maturity TEXT,
    is_upgradable BOOLEAN,
    is_patchable BOOLEAN,
    scan_timestamp TIMESTAMPTZ NOT NULL,
    raw_file_path TEXT,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_snyk_findings_repo_scan_issue_file
    ON snyk_findings (repo_name, scan_type, issue_id, file_path);

CREATE INDEX IF NOT EXISTS idx_snyk_findings_repo_name
    ON snyk_findings (repo_name);

CREATE INDEX IF NOT EXISTS idx_snyk_findings_scan_type
    ON snyk_findings (scan_type);

CREATE INDEX IF NOT EXISTS idx_snyk_findings_severity
    ON snyk_findings (severity);

CREATE INDEX IF NOT EXISTS idx_snyk_findings_scan_timestamp
    ON snyk_findings (scan_timestamp);

CREATE INDEX IF NOT EXISTS idx_snyk_findings_is_active
    ON snyk_findings (is_active);
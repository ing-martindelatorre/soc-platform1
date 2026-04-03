CREATE TABLE IF NOT EXISTS sentinel_incidents (
    incident_id TEXT PRIMARY KEY,
    account_id TEXT,
    site_id TEXT,
    threat_name TEXT,
    classification TEXT,
    severity TEXT,
    status TEXT,
    agent_id TEXT,
    agent_name TEXT,
    username TEXT,
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ,
    raw_hash TEXT,
    raw_json JSONB,
    ingested_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sentinel_incidents_created_at
    ON sentinel_incidents (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_sentinel_incidents_severity
    ON sentinel_incidents (severity);

CREATE INDEX IF NOT EXISTS idx_sentinel_incidents_status
    ON sentinel_incidents (status);

CREATE INDEX IF NOT EXISTS idx_sentinel_incidents_agent_name
    ON sentinel_incidents (agent_name);
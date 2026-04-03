CREATE TABLE IF NOT EXISTS fortinet_log_raw (
    id BIGSERIAL PRIMARY KEY,
    device_name TEXT NOT NULL,
    serial TEXT,
    version TEXT,
    build TEXT,
    vdom TEXT DEFAULT 'root',
    endpoint TEXT NOT NULL,
    log_id TEXT,
    log_type TEXT,
    subtype TEXT,
    action TEXT,
    level TEXT,
    srcip TEXT,
    dstip TEXT,
    srcport INTEGER,
    dstport INTEGER,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    payload JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_fortinet_log_raw_device_time
ON fortinet_log_raw (device_name, collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_fortinet_log_raw_endpoint_time
ON fortinet_log_raw (endpoint, collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_fortinet_log_raw_srcip
ON fortinet_log_raw (srcip);

CREATE INDEX IF NOT EXISTS idx_fortinet_log_raw_dstip
ON fortinet_log_raw (dstip);

CREATE INDEX IF NOT EXISTS idx_fortinet_log_raw_action
ON fortinet_log_raw (action);

CREATE INDEX IF NOT EXISTS idx_fortinet_log_raw_payload_gin
ON fortinet_log_raw USING GIN (payload);

CREATE TABLE IF NOT EXISTS fortinet_log_collection_errors (
    id BIGSERIAL PRIMARY KEY,
    device_name TEXT NOT NULL,
    endpoint TEXT,
    error_message TEXT NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fortinet_log_errors_device_time
ON fortinet_log_collection_errors (device_name, collected_at DESC);
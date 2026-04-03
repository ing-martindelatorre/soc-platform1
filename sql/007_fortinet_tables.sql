CREATE TABLE IF NOT EXISTS fortinet_raw_snapshots (
    id BIGSERIAL PRIMARY KEY,
    device_name TEXT NOT NULL,
    serial TEXT,
    version TEXT,
    build TEXT,
    vdom TEXT DEFAULT 'root',
    section TEXT NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    payload JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_fortinet_raw_device_time
ON fortinet_raw_snapshots (device_name, collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_fortinet_raw_section_time
ON fortinet_raw_snapshots (section, collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_fortinet_raw_payload_gin
ON fortinet_raw_snapshots USING GIN (payload);

CREATE TABLE IF NOT EXISTS fortinet_collection_errors (
    id BIGSERIAL PRIMARY KEY,
    device_name TEXT NOT NULL,
    section TEXT NOT NULL,
    error_message TEXT NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fortinet_errors_device_time
ON fortinet_collection_errors (device_name, collected_at DESC);
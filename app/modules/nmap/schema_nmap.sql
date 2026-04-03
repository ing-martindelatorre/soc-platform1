-- app/modules/nmap/schema_nmap.sql

CREATE TABLE IF NOT EXISTS nmap_scan_jobs (
    id BIGSERIAL PRIMARY KEY,
    scan_name TEXT NOT NULL,
    profile TEXT NOT NULL,
    target TEXT NOT NULL,
    command JSONB,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'completed',
    returncode INTEGER,
    xml_path TEXT,
    meta JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS nmap_assets (
    id BIGSERIAL PRIMARY KEY,
    ip INET NOT NULL,
    hostname TEXT,
    mac TEXT,
    os_guess TEXT,
    status TEXT,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(ip)
);

CREATE TABLE IF NOT EXISTS nmap_services (
    id BIGSERIAL PRIMARY KEY,
    asset_id BIGINT NOT NULL REFERENCES nmap_assets(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    service_name TEXT,
    product TEXT,
    version TEXT,
    extrainfo TEXT,
    tags JSONB,
    scripts JSONB,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(asset_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS nmap_findings (
    id BIGSERIAL PRIMARY KEY,
    asset_id BIGINT NOT NULL REFERENCES nmap_assets(id) ON DELETE CASCADE,
    service_id BIGINT NULL REFERENCES nmap_services(id) ON DELETE SET NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    recommendation TEXT,
    category TEXT,
    evidence JSONB,
    source TEXT DEFAULT 'nmap',
    script_name TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nmap_assets_ip ON nmap_assets(ip);
CREATE INDEX IF NOT EXISTS idx_nmap_services_asset_id ON nmap_services(asset_id);
CREATE INDEX IF NOT EXISTS idx_nmap_findings_asset_id ON nmap_findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_nmap_findings_severity ON nmap_findings(severity);
CREATE INDEX IF NOT EXISTS idx_nmap_findings_status ON nmap_findings(status);
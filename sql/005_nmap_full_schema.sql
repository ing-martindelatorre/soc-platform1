CREATE TABLE IF NOT EXISTS nmap_assets (
    id BIGSERIAL PRIMARY KEY,
    ip VARCHAR(100) UNIQUE NOT NULL,
    hostname VARCHAR(255),
    mac VARCHAR(100),
    os_guess TEXT,
    status VARCHAR(50),
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS nmap_services (
    id BIGSERIAL PRIMARY KEY,
    asset_id BIGINT REFERENCES nmap_assets(id) ON DELETE CASCADE,
    port INTEGER,
    protocol VARCHAR(10),
    service_name VARCHAR(255),
    product VARCHAR(255),
    version VARCHAR(255),
    extrainfo TEXT,
    tags JSONB,
    scripts JSONB,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(asset_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS nmap_findings (
    id BIGSERIAL PRIMARY KEY,
    asset_id BIGINT REFERENCES nmap_assets(id) ON DELETE CASCADE,
    service_id BIGINT REFERENCES nmap_services(id) ON DELETE SET NULL,
    severity VARCHAR(20),
    title TEXT,
    description TEXT,
    recommendation TEXT,
    category VARCHAR(100),
    evidence JSONB,
    source VARCHAR(50),
    script_name VARCHAR(255),
    status VARCHAR(20),
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
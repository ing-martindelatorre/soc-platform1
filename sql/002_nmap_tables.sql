CREATE TABLE IF NOT EXISTS nmap_findings (
    id BIGSERIAL PRIMARY KEY,
    asset_name VARCHAR(255) NOT NULL,
    target VARCHAR(255) NOT NULL,
    profile_name VARCHAR(100) NOT NULL,
    host_status VARCHAR(50) NULL,
    port INTEGER NULL,
    protocol VARCHAR(20) NULL,
    port_state VARCHAR(20) NULL,
    service_name VARCHAR(255) NULL,
    product VARCHAR(255) NULL,
    version VARCHAR(255) NULL,
    os_guess TEXT NULL,
    xml_path TEXT NULL,
    scan_started_at TIMESTAMP NULL,
    scan_finished_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
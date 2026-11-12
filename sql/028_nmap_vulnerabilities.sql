-- 028_nmap_vulnerabilities.sql
-- Vulnerabilidades reales detectadas por Nmap (CVE o confirmadas por NSE),
-- separadas de nmap_findings (exposición de puertos/servicios).
--
-- Una fila por (activo, puerto, protocolo, vuln_id): se actualiza en cada
-- escaneo con scripts y pasa a status='resolved' cuando un escaneo con
-- scripts del mismo activo ya no la reporta.
--
-- detection:
--   confirmed → el script NSE probó el fallo (State: VULNERABLE)
--   likely    → State: LIKELY VULNERABLE
--   version   → script vulners: sólo coincidencia producto+versión (no probado)
--
-- Idempotente.

CREATE TABLE IF NOT EXISTS nmap_vulnerabilities (
    id            BIGSERIAL PRIMARY KEY,
    asset_id      BIGINT NOT NULL REFERENCES nmap_assets(id) ON DELETE CASCADE,
    service_id    BIGINT REFERENCES nmap_services(id) ON DELETE SET NULL,
    port          INTEGER NOT NULL DEFAULT 0,   -- 0 = script a nivel host
    protocol      VARCHAR(10) NOT NULL DEFAULT '',
    vuln_id       VARCHAR(100) NOT NULL,        -- CVE-AAAA-NNNN o <script>:<id>
    is_cve        BOOLEAN NOT NULL DEFAULT TRUE,
    cvss          NUMERIC(3,1),
    severity      VARCHAR(20) NOT NULL,
    detection     VARCHAR(20) NOT NULL,
    has_exploit   BOOLEAN NOT NULL DEFAULT FALSE,  -- vulners marca exploit público
    in_kev        BOOLEAN NOT NULL DEFAULT FALSE,  -- en catálogo CISA KEV (explotado activamente)
    kev_ransomware BOOLEAN NOT NULL DEFAULT FALSE, -- KEV: usado en campañas de ransomware
    nvd_affected  BOOLEAN,                         -- KEV por versión verificado en NVD: TRUE afectado, NULL sin verificar
    title         TEXT,
    product       VARCHAR(255),
    version       VARCHAR(255),
    cpe           TEXT,
    script_name   VARCHAR(100),
    reference_url TEXT,
    status        VARCHAR(20) NOT NULL DEFAULT 'open',   -- open | resolved
    first_seen    TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen     TIMESTAMP NOT NULL DEFAULT NOW(),
    resolved_at   TIMESTAMP,
    UNIQUE (asset_id, port, protocol, vuln_id)
);

CREATE INDEX IF NOT EXISTS idx_nmap_vulns_status_sev ON nmap_vulnerabilities (status, severity);
CREATE INDEX IF NOT EXISTS idx_nmap_vulns_asset      ON nmap_vulnerabilities (asset_id);
CREATE INDEX IF NOT EXISTS idx_nmap_vulns_last_seen  ON nmap_vulnerabilities (last_seen);

-- Caché de reputación de IPs para el módulo ip_intel.
-- Evita consultas repetidas a Shodan e ipinfo.io.
-- TTL aplicado en aplicación (IP_INTEL_CACHE_TTL_HOURS, defecto 168 h = 7 días).

CREATE TABLE IF NOT EXISTS ip_reputation_cache (
    ip           VARCHAR(45)  PRIMARY KEY,
    asn          TEXT,
    org          TEXT,
    country      VARCHAR(10),
    hostnames    JSONB        NOT NULL DEFAULT '[]',
    tags         JSONB        NOT NULL DEFAULT '[]',
    vulns        JSONB        NOT NULL DEFAULT '[]',
    is_trusted   BOOLEAN      NOT NULL DEFAULT FALSE,
    trust_reason TEXT,
    source       TEXT         NOT NULL DEFAULT 'shodan+ipinfo',
    checked_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ip_rep_cache_checked
    ON ip_reputation_cache (checked_at);

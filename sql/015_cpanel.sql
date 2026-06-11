-- =============================================================================
-- 015_cpanel.sql
-- Tablas para el módulo de monitoreo WHM/cPanel
-- =============================================================================

-- Estadísticas del servidor y cola de correo
CREATE TABLE IF NOT EXISTS cpanel_server_stats (
    id              SERIAL PRIMARY KEY,
    collected_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    server_host     TEXT,
    hostname        TEXT,
    version         TEXT,
    mail_queue      INTEGER,
    cpu_load_1      NUMERIC(6,2),
    cpu_load_5      NUMERIC(6,2),
    cpu_load_15     NUMERIC(6,2),
    memory_total    BIGINT,
    memory_used     BIGINT,
    memory_free     BIGINT,
    disk_used_pct   NUMERIC(5,2),
    payload         JSONB
);

CREATE INDEX IF NOT EXISTS idx_cpanel_stats_collected ON cpanel_server_stats(collected_at);

-- Eventos de fuerza bruta detectados por cPHulk
CREATE TABLE IF NOT EXISTS cpanel_cphulk_events (
    id              SERIAL PRIMARY KEY,
    collected_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    server_host     TEXT,
    ip              TEXT,
    username        TEXT,
    service         TEXT,
    attempts        INTEGER,
    blocked         BOOLEAN DEFAULT FALSE,
    blocked_until   TIMESTAMPTZ,
    payload         JSONB
);

CREATE INDEX IF NOT EXISTS idx_cpanel_cphulk_ip        ON cpanel_cphulk_events(ip);
CREATE INDEX IF NOT EXISTS idx_cpanel_cphulk_collected ON cpanel_cphulk_events(collected_at);

-- Cuentas cPanel (snapshot periódico)
CREATE TABLE IF NOT EXISTS cpanel_accounts (
    id              SERIAL PRIMARY KEY,
    collected_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    server_host     TEXT,
    username        TEXT,
    domain          TEXT,
    plan            TEXT,
    suspended       BOOLEAN DEFAULT FALSE,
    disk_used_mb    NUMERIC(12,2),
    disk_limit_mb   NUMERIC(12,2),
    payload         JSONB
);

CREATE INDEX IF NOT EXISTS idx_cpanel_accounts_domain    ON cpanel_accounts(domain);
CREATE INDEX IF NOT EXISTS idx_cpanel_accounts_collected ON cpanel_accounts(collected_at);

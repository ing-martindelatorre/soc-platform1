-- =============================================================================
-- 010_fortinet_threats.sql
-- Tabla para almacenar logs de amenazas procesados de Fortinet.
-- Incluye tráfico sospechoso, eventos de sistema, webfilter, IPS y VPN.
-- =============================================================================

CREATE TABLE IF NOT EXISTS fortinet_threats (
    id              BIGSERIAL PRIMARY KEY,
    device_name     TEXT          NOT NULL,
    collected_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    -- Clasificación
    source          TEXT          NOT NULL,  -- traffic | event | webfilter | ips | vpn
    classification  TEXT          NOT NULL,  -- blocked | suspicious | normal | login_failure | alert | critical | info | allowed

    -- Campos comunes
    log_date        DATE,
    log_time        TEXT,
    level           TEXT,
    action          TEXT,
    logdesc         TEXT,
    msg             TEXT,

    -- Red
    srcip           TEXT,
    srcname         TEXT,
    dstip           TEXT,
    dstport         INTEGER,
    dstcountry      TEXT,
    service         TEXT,

    -- Aplicación / Web
    app             TEXT,
    apprisk         TEXT,
    hostname        TEXT,
    url             TEXT,
    catdesc         TEXT,
    policyname      TEXT,

    -- Bytes
    sentbyte        BIGINT,
    rcvdbyte        BIGINT,

    -- Payload completo
    payload         JSONB         NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_forti_threats_device_time
    ON fortinet_threats (device_name, collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_forti_threats_source
    ON fortinet_threats (source);

CREATE INDEX IF NOT EXISTS idx_forti_threats_classification
    ON fortinet_threats (classification);

CREATE INDEX IF NOT EXISTS idx_forti_threats_srcip
    ON fortinet_threats (srcip);

CREATE INDEX IF NOT EXISTS idx_forti_threats_dstcountry
    ON fortinet_threats (dstcountry);

CREATE INDEX IF NOT EXISTS idx_forti_threats_log_date
    ON fortinet_threats (log_date DESC);

CREATE INDEX IF NOT EXISTS idx_forti_threats_payload_gin
    ON fortinet_threats USING GIN (payload);

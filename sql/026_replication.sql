-- =============================================================================
-- 026_replication.sql
-- Replicación cifrada de datos del SOC hacia otra ubicación (el mismo
-- programa corriendo en modo receptor). Ver app/modules/replication/.
-- =============================================================================

CREATE TABLE IF NOT EXISTS replication_targets (
    id              BIGSERIAL   PRIMARY KEY,
    name            TEXT        NOT NULL,
    host            TEXT        NOT NULL,
    port            INTEGER     NOT NULL,
    enabled         BOOLEAN     NOT NULL DEFAULT TRUE,
    tables          JSONB       NOT NULL DEFAULT '[]'::jsonb,  -- nombres de tabla a replicar; [] = todas las de REPLICABLE_TABLES
    tls_fingerprint TEXT        NULL,  -- huella SHA-256 (hex) del certificado esperado del receptor; NULL = valida contra CA pública
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS replication_watermarks (
    target_id    BIGINT      NOT NULL REFERENCES replication_targets(id) ON DELETE CASCADE,
    table_name   TEXT        NOT NULL,
    last_sent_id BIGINT      NOT NULL DEFAULT 0,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (target_id, table_name)
);

CREATE INDEX IF NOT EXISTS idx_replication_targets_enabled ON replication_targets (enabled);

-- Job de replicación en la tabla de frecuencias configurables (job_config.py
-- lo auto-siembra si falta, pero se inserta también aquí para que quede
-- explícito en las migraciones — igual que 025_job_config_schedules.sql).
INSERT INTO job_config (job_name, enabled, schedule_type, schedule_value, label)
VALUES ('replication_job', TRUE, 'interval', '10', 'Replicación remota')
ON CONFLICT (job_name) DO NOTHING;

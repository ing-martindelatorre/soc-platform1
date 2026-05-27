-- =============================================================================
-- 011_alert_rules.sql
-- Tablas para el motor de alertas por email del SOC Platform.
-- =============================================================================

-- Reglas de alerta configurables desde la UI
CREATE TABLE IF NOT EXISTS alert_rules (
    id              BIGSERIAL PRIMARY KEY,
    name            TEXT          NOT NULL,
    module          TEXT          NOT NULL,  -- sentinel | fortinet | snyk | nmap
    condition_field TEXT          NOT NULL,  -- campo a evaluar (ej: classification, severity)
    condition_value TEXT          NOT NULL,  -- valor que dispara la alerta (ej: suspicious, critical)
    recipients      TEXT[]        NOT NULL,  -- lista de emails destinatarios
    subject         TEXT          NOT NULL,  -- asunto del correo
    enabled         BOOLEAN       NOT NULL DEFAULT TRUE,
    cooldown_minutes INTEGER      NOT NULL DEFAULT 60,  -- minutos entre alertas del mismo tipo
    last_sent_at    TIMESTAMPTZ   NULL,
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- Log de alertas enviadas
CREATE TABLE IF NOT EXISTS alert_log (
    id              BIGSERIAL PRIMARY KEY,
    rule_id         BIGINT        REFERENCES alert_rules(id) ON DELETE SET NULL,
    rule_name       TEXT          NOT NULL,
    module          TEXT          NOT NULL,
    recipients      TEXT[]        NOT NULL,
    subject         TEXT          NOT NULL,
    trigger_data    JSONB,
    sent_at         TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    status          TEXT          NOT NULL DEFAULT 'sent',  -- sent | failed
    error_message   TEXT
);

CREATE INDEX IF NOT EXISTS idx_alert_rules_module  ON alert_rules (module);
CREATE INDEX IF NOT EXISTS idx_alert_rules_enabled ON alert_rules (enabled);
CREATE INDEX IF NOT EXISTS idx_alert_log_rule_id   ON alert_log (rule_id);
CREATE INDEX IF NOT EXISTS idx_alert_log_sent_at   ON alert_log (sent_at DESC);

-- Reglas de ejemplo (comentadas — descomentar para usar)
-- INSERT INTO alert_rules (name, module, condition_field, condition_value, recipients, subject, cooldown_minutes)
-- VALUES
-- ('Virus detectado Fortinet',  'fortinet', 'classification', 'blocked',    ARRAY['ti@empresa.com'], 'SOC: Virus detectado en Fortinet', 30),
-- ('Amenaza activa Sentinel',   'sentinel', 'classification', 'Ransomware', ARRAY['ti@empresa.com'], 'SOC: Amenaza crítica en SentinelOne', 15),
-- ('Vulnerabilidad crítica Snyk','snyk',    'severity',       'critical',   ARRAY['ti@empresa.com'], 'SOC: Vulnerabilidad crítica en código', 360);

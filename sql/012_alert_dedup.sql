-- =============================================================================
-- 012_alert_dedup.sql
-- Agrega dedup_key a alert_log para deduplicación por entidad,
-- y dedup_hours a alert_rules para control de ventana de deduplicación.
-- =============================================================================

ALTER TABLE alert_log
    ADD COLUMN IF NOT EXISTS dedup_key TEXT;

CREATE INDEX IF NOT EXISTS idx_alert_log_dedup_key
    ON alert_log (dedup_key, sent_at DESC)
    WHERE dedup_key IS NOT NULL;

-- Campo informativo; la deduplicación usa cooldown_minutes como ventana.
COMMENT ON COLUMN alert_log.dedup_key IS
    'Clave única de entidad alertada: r{rule_id}:{source_label}:{detail}';

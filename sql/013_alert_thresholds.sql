-- =============================================================================
-- 013_alert_thresholds.sql
-- Agrega soporte de umbrales de cantidad y tipo de condición a alert_rules.
-- =============================================================================

ALTER TABLE alert_rules
    ADD COLUMN IF NOT EXISTS condition_type  TEXT    NOT NULL DEFAULT 'match',
    ADD COLUMN IF NOT EXISTS threshold_count INTEGER NOT NULL DEFAULT 1;

COMMENT ON COLUMN alert_rules.condition_type IS
    'match: alerta si existe cualquier evento; threshold: solo si total_events >= threshold_count';
COMMENT ON COLUMN alert_rules.threshold_count IS
    'Mínimo de eventos totales para disparar (solo aplica con condition_type = threshold)';

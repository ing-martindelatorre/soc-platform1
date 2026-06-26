-- =============================================================================
-- 019_alert_antivirus_rule.sql
-- Regla de alerta para detecciones de malware por antivirus Fortinet.
-- Se dispara cuando hay eventos en fortinet_threats WHERE source='antivirus'
-- en la última hora. Cooldown de 60 min para no saturar correos.
-- =============================================================================

INSERT INTO alert_rules (
    name,
    module,
    condition_field,
    condition_value,
    recipients,
    subject,
    enabled,
    cooldown_minutes,
    condition_type,
    threshold_count
) VALUES (
    'Antivirus Fortinet — Malware detectado',
    'fortinet',
    'antivirus',
    'antivirus',
    ARRAY['ing.martindelatorre@gmail.com'],
    '[SOC CRÍTICO] Malware detectado por Fortinet',
    true,
    60,
    'match',
    1
);

-- =============================================================================
-- 029_alert_nmap_kev_rule.sql
-- Regla de alerta para vulnerabilidades del catálogo CISA KEV (explotadas
-- activamente) detectadas por Nmap en nmap_vulnerabilities.
--
-- condition_field = 'kev'; condition_value = 'all' (todos los KEV) o
-- 'ransomware' (sólo KEV usados en ransomware). Cada (IP:puerto, CVE) se
-- avisa una vez y se recuerda cada 30 días mientras siga abierto
-- (ENTITY_DEDUP_MINUTES en app/alerts/engine.py).
--
-- Destinatarios: se copian de la regla Nmap existente (o de la primera regla
-- activa). Si no hay ninguna regla, no se inserta; créala desde el panel.
-- Idempotente.
-- =============================================================================

INSERT INTO alert_rules (
    name, module, condition_field, condition_value, recipients, subject,
    enabled, cooldown_minutes, condition_type, threshold_count
)
SELECT
    'Nmap — Vulnerabilidad explotada activamente (CISA KEV)',
    'nmap',
    'kev',
    'all',
    src.recipients,
    '[SOC CRÍTICO] Vulnerabilidad KEV explotada activamente',
    true,
    60,
    'match',
    1
FROM (
    SELECT recipients
    FROM alert_rules
    WHERE enabled
    ORDER BY (module = 'nmap') DESC, id
    LIMIT 1
) src
WHERE NOT EXISTS (
    SELECT 1 FROM alert_rules WHERE module = 'nmap' AND condition_field = 'kev'
);

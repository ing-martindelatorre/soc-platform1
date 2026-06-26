-- =============================================================================
-- 018_fortinet_antivirus_columns.sql
-- Agrega columnas específicas de antivirus a fortinet_threats.
-- Los logs de virus (source='antivirus') necesitan virus, filename y dtype.
-- =============================================================================

ALTER TABLE fortinet_threats
    ADD COLUMN IF NOT EXISTS virus    TEXT,
    ADD COLUMN IF NOT EXISTS filename TEXT,
    ADD COLUMN IF NOT EXISTS dtype    TEXT;

CREATE INDEX IF NOT EXISTS idx_forti_threats_virus
    ON fortinet_threats (virus)
    WHERE virus IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_forti_threats_source_antivirus
    ON fortinet_threats (device_name, collected_at DESC)
    WHERE source = 'antivirus';

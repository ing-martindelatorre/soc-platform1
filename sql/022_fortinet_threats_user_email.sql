-- =============================================================================
-- 022_fortinet_threats_user_email.sql
-- Agrega user_hostname/user_email a fortinet_threats. Se resuelven a partir
-- del inventario de dispositivos de FortiGate (/api/v2/monitor/user/device/query),
-- que expone el hostname del equipo y el usuario detectado por sniffing de
-- autenticación POP3/IMAP/FTP (campo unauth_user) para cada srcip.
-- =============================================================================

ALTER TABLE fortinet_threats
    ADD COLUMN IF NOT EXISTS user_hostname TEXT,
    ADD COLUMN IF NOT EXISTS user_email    TEXT;

CREATE INDEX IF NOT EXISTS idx_forti_threats_user_email
    ON fortinet_threats (user_email);

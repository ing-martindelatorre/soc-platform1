-- =============================================================================
-- 024_fortinet_threats_mail_sender_recipient.sql
-- El log crudo de antivirus de FortiGate trae "from"/"to" cuando el servicio
-- es POP3/IMAP/SMTP: el remitente y destinatario reales del correo que
-- contenía el archivo infectado. transform.py los descartaba al armar el
-- registro; ahora se guardan como sender/recipient. Da el buzón exacto sin
-- depender del device inventory (unauth_user, ver user_email/022).
-- =============================================================================

-- lock_timeout: la tabla está en uso constante por el dashboard/scheduler en
-- vivo; si el ALTER no puede tomar el lock rápido, mejor que falle y se
-- reintente que quedarse en cola bloqueando todo lo que llegue detrás.
SET lock_timeout = '3s';

ALTER TABLE fortinet_threats
    ADD COLUMN IF NOT EXISTS sender    TEXT,
    ADD COLUMN IF NOT EXISTS recipient TEXT;

RESET lock_timeout;

-- CONCURRENTLY no toma el lock exclusivo que bloquea lecturas/escrituras.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_forti_threats_recipient ON fortinet_threats (recipient);

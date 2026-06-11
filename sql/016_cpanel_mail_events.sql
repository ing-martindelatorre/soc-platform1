-- =============================================================================
-- 016_cpanel_mail_events.sql
-- Eventos de correo parseados desde el log de Exim via SSH
-- =============================================================================

CREATE TABLE IF NOT EXISTS cpanel_mail_events (
    id             SERIAL PRIMARY KEY,
    collected_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_time     TIMESTAMPTZ,
    server_host    TEXT,
    event_type     TEXT,        -- accepted, delivered, rejected, spam, virus, bounce, connection_rejected
    message_id     TEXT,
    sender         TEXT,
    recipient      TEXT,
    remote_host    TEXT,
    remote_ip      TEXT,
    spam_score     NUMERIC(7,2),
    reject_reason  TEXT,
    size_bytes     INTEGER,
    line_hash      TEXT,        -- sha256 de la línea raw (deduplicación)
    payload        JSONB
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_cpanel_mail_events_hash
    ON cpanel_mail_events(line_hash);

CREATE INDEX IF NOT EXISTS idx_cpanel_mail_events_time
    ON cpanel_mail_events(event_time);

CREATE INDEX IF NOT EXISTS idx_cpanel_mail_events_type
    ON cpanel_mail_events(event_type);

CREATE INDEX IF NOT EXISTS idx_cpanel_mail_events_ip
    ON cpanel_mail_events(remote_ip);

CREATE INDEX IF NOT EXISTS idx_cpanel_mail_events_sender
    ON cpanel_mail_events(sender);

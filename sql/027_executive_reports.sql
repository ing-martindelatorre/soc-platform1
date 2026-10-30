-- =============================================================================
-- 027_executive_reports.sql
-- Reportes ejecutivos mensuales de amenazas (pestaña "Reportes Ejecutivos" del
-- panel de configuración). Ver app/reports/executive.py.
-- =============================================================================

-- Configuración del envío automático (una sola fila, id = 1)
CREATE TABLE IF NOT EXISTS executive_report_config (
    id          INTEGER     PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    enabled     BOOLEAN     NOT NULL DEFAULT FALSE,
    recipients  TEXT[]      NOT NULL DEFAULT '{}',
    send_day    INTEGER     NOT NULL DEFAULT 1 CHECK (send_day BETWEEN 1 AND 28),
    send_hour   INTEGER     NOT NULL DEFAULT 8 CHECK (send_hour BETWEEN 0 AND 23),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO executive_report_config (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

-- Un reporte por mes; regenerarlo sobreescribe la fila del mismo periodo
CREATE TABLE IF NOT EXISTS executive_reports (
    id            BIGSERIAL   PRIMARY KEY,
    period        DATE        NOT NULL UNIQUE,  -- primer día del mes reportado
    status        TEXT        NOT NULL DEFAULT 'generating',  -- generating | ready | failed
    data          JSONB,                        -- métricas agregadas (se reusan para comparar con el mes siguiente)
    html          TEXT,
    error         TEXT,
    started_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),  -- inicio de la última generación (evita dos generaciones simultáneas)
    generated_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Historial de envíos (manuales y automáticos)
CREATE TABLE IF NOT EXISTS executive_report_sends (
    id          BIGSERIAL   PRIMARY KEY,
    report_id   BIGINT      NOT NULL REFERENCES executive_reports(id) ON DELETE CASCADE,
    recipients  TEXT[]      NOT NULL,
    trigger     TEXT        NOT NULL,  -- manual | auto
    status      TEXT        NOT NULL,  -- sent | failed
    error       TEXT,
    sent_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_exec_report_sends_report ON executive_report_sends (report_id, sent_at DESC);

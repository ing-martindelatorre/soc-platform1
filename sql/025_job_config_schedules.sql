-- Reconstruye job_config con los job-id reales de app/pipeline/scheduler.py
-- (la tabla original de 004_scheduler.sql quedó huérfana y desincronizada:
-- nunca fue leída ni escrita por ningún código).

ALTER TABLE job_config ADD COLUMN IF NOT EXISTS label VARCHAR(80);

TRUNCATE job_config;

INSERT INTO job_config (job_name, enabled, schedule_type, schedule_value, label) VALUES
    ('sentinel_job',         TRUE, 'interval', '5',         'Sentinel'),
    ('fortinet_config_job',  TRUE, 'interval', '15',        'Fortinet — Configuración'),
    ('fortinet_logs_job',    TRUE, 'interval', '15',        'Fortinet — Logs'),
    ('fortinet_threats_job', TRUE, 'interval', '5',         'Fortinet — Amenazas'),
    ('nmap_quick_job',       TRUE, 'interval', '360',       'Nmap — Escaneo rápido'),
    ('nmap_deep_job',        TRUE, 'cron',     '0 2 * * 0', 'Nmap — Escaneo completo'),
    ('snyk_job',             TRUE, 'cron',     '0 1 * * *', 'Snyk'),
    ('cpanel_stats_job',     TRUE, 'interval', '15',        'cPanel — Estadísticas'),
    ('cpanel_security_job',  TRUE, 'interval', '15',        'cPanel — Seguridad (cPHulk)'),
    ('cpanel_accounts_job',  TRUE, 'interval', '60',        'cPanel — Cuentas'),
    ('cpanel_logs_job',      TRUE, 'interval', '30',        'cPanel — Logs SSH')
ON CONFLICT (job_name) DO UPDATE SET
    enabled        = EXCLUDED.enabled,
    schedule_type  = EXCLUDED.schedule_type,
    schedule_value = EXCLUDED.schedule_value,
    label          = EXCLUDED.label;

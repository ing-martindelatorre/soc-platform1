CREATE TABLE IF NOT EXISTS job_config (
    job_name VARCHAR(50) PRIMARY KEY,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    schedule_type VARCHAR(20) NOT NULL,
    schedule_value VARCHAR(100) NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO job_config (job_name, enabled, schedule_type, schedule_value)
VALUES
    ('sentinel', TRUE, 'interval_minutes', '1'),
    ('nmap_quick', TRUE, 'interval_hours', '6'),
    ('nmap_deep', TRUE, 'cron', '0 2 * * 0'),
    ('snyk', TRUE, 'cron', '0 1 * * 0'),
    ('fortinet', TRUE, 'interval_minutes', '5')
ON CONFLICT (job_name) DO NOTHING;
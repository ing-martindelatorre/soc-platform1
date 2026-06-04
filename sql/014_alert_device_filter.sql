-- Filtro de dispositivo opcional en reglas de alerta
-- Permite crear reglas que solo disparen para un FortiGate específico (por device_name)
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS device_filter TEXT DEFAULT NULL;

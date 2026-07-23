-- =============================================================================
-- 023_fortinet_threats_eventtime_dedup.sql
-- Igual que 020 (antivirus) pero para traffic/event/vpn/webfilter: el buffer
-- de memoria del FortiGate no rota entre cada poll del scheduler (cada 5 min),
-- así que el mismo lote de log se reinserta completo en corridas consecutivas.
-- A diferencia de antivirus, aquí no armamos una clave compuesta de negocio:
-- FortiGate ya manda "eventtime", un timestamp en nanosegundos único por
-- entrada de log, en cada registro de log de memoria. Se usa como clave de
-- deduplicación vía ON CONFLICT DO NOTHING (ver load.py).
--
-- OJO: esta migración NO borra los duplicados históricos que ya existen
-- (la tabla tiene ~17M filas y está en uso por el dashboard en vivo; ese
-- limpiado se hace aparte, en una ventana de mantenimiento, con backfill de
-- eventtime a partir del payload donde sea posible). Esto solo evita que se
-- sigan generando duplicados nuevos a partir de ahora.
--
-- CREATE INDEX CONCURRENTLY no bloquea lecturas/escrituras de la tabla
-- mientras se construye, pero tampoco puede correr dentro de una transacción
-- explícita — no envolver este archivo en BEGIN/COMMIT.
-- =============================================================================

ALTER TABLE fortinet_threats
    ADD COLUMN IF NOT EXISTS eventtime BIGINT;

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_forti_threats_eventtime_dedup
    ON fortinet_threats (device_name, source, eventtime)
    WHERE source IN ('traffic', 'event', 'vpn', 'webfilter') AND eventtime IS NOT NULL;

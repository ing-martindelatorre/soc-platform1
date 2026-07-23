-- =============================================================================
-- 020_fortinet_antivirus_dedup.sql
-- El pipeline de threats reinserta el mismo lote de /log/memory/virus en cada
-- corrida cuando el buffer del FortiGate todavía no rotó, duplicando eventos
-- de antivirus. Se limpia lo ya duplicado y se agrega un índice único parcial
-- para que load.py pueda usar ON CONFLICT DO NOTHING a futuro.
-- =============================================================================

DELETE FROM fortinet_threats a USING fortinet_threats b
WHERE a.source = 'antivirus'
  AND b.source = 'antivirus'
  AND a.id > b.id
  AND a.device_name = b.device_name
  AND a.log_date    = b.log_date
  AND a.log_time    = b.log_time
  AND a.srcip       IS NOT DISTINCT FROM b.srcip
  AND a.dstip       IS NOT DISTINCT FROM b.dstip
  AND a.dstport     IS NOT DISTINCT FROM b.dstport
  AND a.virus       IS NOT DISTINCT FROM b.virus
  AND a.filename    IS NOT DISTINCT FROM b.filename;

CREATE UNIQUE INDEX IF NOT EXISTS idx_forti_threats_antivirus_dedup
    ON fortinet_threats (device_name, log_date, log_time, srcip, dstip, dstport, virus, filename)
    WHERE source = 'antivirus';

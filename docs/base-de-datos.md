# Base de datos

PostgreSQL 16 (imagen `postgres:16-alpine`) en el contenedor `soc1_postgres`.
Datos persistentes en el volumen `soc1_postgres_data`. pgAdmin 4 corre en
`soc1_pgadmin` y se publica en `http://localhost:8081`.

## Migraciones

Los archivos `sql/001_*.sql` a `sql/027_*.sql` son idempotentes en su mayoría
(`CREATE TABLE IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`). No hay runner:

- **Base nueva:** `docker-compose.yml` monta `./sql` en
  `/docker-entrypoint-initdb.d`, así que Docker los ejecuta en orden
  alfabético **solo la primera vez**, cuando el volumen está vacío.
- **Base existente:** aplica a mano cada migración nueva, en orden:

  ```bash
  docker compose exec -T postgres psql -U "$DB_USER" -d "$DB_NAME" < sql/025_job_config_schedules.sql
  ```

- **Reiniciar desde cero:** `bash scripts/start_db.sh reset` (borra todo).

Al crear una migración, numérala con el siguiente número libre y hazla
idempotente.

| Migración | Contenido |
|---|---|
| 001 | `collector_runs`, `assets` (base inicial) |
| 002, 005 | Tablas de Nmap (`nmap_assets`, `nmap_services`, `nmap_findings`) |
| 003 | `snyk_scans`, `snyk_findings` |
| 004 | Primera versión de `job_config` (reemplazada por la 025) |
| 006 | `sentinel_incidents` |
| 007 | `fortinet_raw_snapshots`, `fortinet_collection_errors` |
| 008 | `fortinet_log_raw`, `fortinet_log_collection_errors` |
| 009 | `job_runs` y la vista `v_job_runs_latest` |
| 010 | `fortinet_threats` |
| 011–014 | `alert_rules`, `alert_log`, deduplicación, umbrales y filtro por dispositivo |
| 015, 016 | `cpanel_server_stats`, `cpanel_cphulk_events`, `cpanel_accounts`, `cpanel_mail_events` |
| 017 | `ip_reputation_cache` |
| 018, 020, 022–024 | Columnas y deduplicación de antivirus, usuario/correo, remitente y destinatario en `fortinet_threats` |
| 019 | Regla de alerta de antivirus Fortinet (inserta una fila en `alert_rules`) |
| 021 | `snyk_dismissals` |
| 025 | Reconstruye `job_config` con los `job_id` reales del scheduler |
| 026 | `replication_targets`, `replication_watermarks` (replicación remota) |
| 027 | `executive_report_config`, `executive_reports`, `executive_report_sends` (reportes ejecutivos mensuales) |
| 028 | `nmap_vulnerabilities` (CVEs reales y vulnerabilidades confirmadas por NSE) |

## Tablas por dominio

### Control del pipeline

| Tabla | Descripción |
|---|---|
| `job_runs` | Una fila por ejecución de un módulo: `job_name` (módulo), `status` (`running`, `success`, `failed`), `started_at`, `finished_at`, `message` |
| `job_config` | `job_name` (PK, es el `job_id` de APScheduler), `enabled`, `schedule_type` (`interval` o `cron`), `schedule_value`, `label`, `updated_at` |
| `collector_runs`, `assets` | Tablas de la migración inicial, sin uso actual en el código |

### SentinelOne

`sentinel_incidents`: clave `incident_id`. Campos: `threat_name`,
`classification`, `severity`, `status`, `agent_id`, `agent_name`, `username`,
`created_at`, `updated_at`, `raw_hash` y `raw_json` (respuesta completa).

### Snyk

| Tabla | Descripción |
|---|---|
| `snyk_findings` | Hallazgos por repo. Clave única `(repo_name, scan_type, issue_id, file_path)`. Incluye `severity`, `title`, `package_name`, `version`, `cve`, `is_upgradable`, `is_active` |
| `snyk_scans` | Historial de la versión inicial del pipeline |
| `snyk_scan_runs`, `snyk_account_state` | **Se crean en tiempo de ejecución** desde `app/modules/snyk/load.py` (`ensure_snyk_tables`), no hay migración. Guardan cada escaneo y el estado de bloqueo de cada cuenta |
| `snyk_dismissals` | Hallazgos descartados por `(repo_name, issue_id)` con motivo y usuario. El dashboard los excluye de los KPIs |

### Nmap

`nmap_assets` (IP única, hostname, sistema operativo), `nmap_services`
(`asset_id`, `port`, `protocol`, producto y versión) y `nmap_findings`
(severidad, título, recomendación, categoría, evidencia JSONB). Borrar un
activo elimina en cascada sus servicios, hallazgos y vulnerabilidades.

`nmap_vulnerabilities` (migración 028) guarda las vulnerabilidades reales, una
fila por `(asset_id, port, protocol, vuln_id)` (`port = 0` para scripts a
nivel host): `vuln_id` (CVE o `<script>:<id>` si no hay CVE), `cvss`,
`severity`, `detection` (`confirmed` | `likely` | `version`), `in_kev`,
`kev_ransomware`, `nvd_affected`, producto/versión/CPE, `status`
(`open` | `resolved`), `first_seen`, `last_seen`, `resolved_at`. No tiene
retención propia: se borra en cascada con el activo.

### Fortinet

| Tabla | Descripción |
|---|---|
| `fortinet_raw_snapshots` | Snapshots de configuración por `device_name` y `section` (interfaces, políticas, rutas…), con `payload` JSONB |
| `fortinet_log_raw` | Logs crudos de tráfico y sistema |
| `fortinet_threats` | Eventos normalizados y clasificados. Ver abajo |
| `fortinet_collection_errors`, `fortinet_log_collection_errors` | Errores de recolección por sección o endpoint |

`fortinet_threats.source` toma los valores `traffic`, `event`, `webfilter`,
`ips`, `vpn` y `antivirus`. `classification` depende del origen:

| Origen | Clasificaciones |
|---|---|
| `traffic` | `blocked` (acción deny, block o reset), `suspicious` (país o aplicación de riesgo, `apprisk` alto o crítico), `normal` |
| `event` | `login_failure`, `alert`, `critical`, `auth_event`, `info` |
| `webfilter` | `blocked`, `suspicious`, `allowed` |
| `antivirus` | `blocked`, `detected` |

Las columnas `user_email`, `user_hostname`, `sender` y `recipient` resuelven el
buzón afectado en detecciones de antivirus sobre POP3, IMAP o SMTP.

### cPanel / WHM

| Tabla | Descripción |
|---|---|
| `cpanel_server_stats` | Carga de CPU, cola de correo, versión y ancho de banda (dentro de `payload`) |
| `cpanel_cphulk_events` | Intentos de fuerza bruta detectados por cPHulk |
| `cpanel_accounts` | Foto de cuentas cPanel en cada recolección (se usa la de `MAX(collected_at)`) |
| `cpanel_mail_events` | Eventos de correo: `accepted`, `delivered`, `rejected`, `connection_rejected`, `spam`, `virus`, `bounce`. `line_hash` evita duplicados |

### Alertas

`alert_rules` y `alert_log`; ver [alertas.md](alertas.md).

### Reportes ejecutivos

- `executive_report_config`: una sola fila (`id = 1`) con el envío automático:
  `enabled`, `recipients`, `send_day` (1–28) y `send_hour` (0–23, hora de México).
- `executive_reports`: un reporte por mes (`period` = primer día del mes, único).
  `status` = `generating | ready | failed`; guarda las métricas agregadas en `data`
  (JSONB) y el correo ya armado en `html`. Regenerar un mes sobrescribe su fila.
  Los `data.kpis` del mes anterior se reusan para la comparación mes contra mes.
- `executive_report_sends`: historial de envíos (`trigger` = `manual | auto`,
  `status` = `sent | failed`). Se borra en cascada con el reporte.

Sin política de retención: son una fila por mes.

### Reputación de IPs

`ip_reputation_cache`: por IP guarda ASN, organización, país, hostnames,
etiquetas, CVEs conocidos, si es de confianza y `checked_at`. Vigencia:
`IP_INTEL_CACHE_TTL_HOURS` (168 h por defecto).

## Retención

`cleanup_job` (03:00 diario) ejecuta `DELETE` por fecha en estas tablas. Los
días se configuran con variables de entorno.

| Tabla | Columna | Variable | Defecto |
|---|---|---|---|
| `sentinel_incidents` | `created_at` | `RETENTION_SENTINEL_DAYS` | 90 |
| `snyk_findings` | `created_at` | `RETENTION_SNYK_DAYS` | 180 |
| `nmap_findings` | `created_at` | `RETENTION_NMAP_DAYS` | 90 |
| `nmap_assets` | `last_seen` | `RETENTION_NMAP_ASSETS_DAYS` | 180 |
| `fortinet_threats` | `collected_at` | `RETENTION_FORTINET_DAYS` | 365 |
| `fortinet_log_raw` | `collected_at` | `RETENTION_FORTINET_DAYS` | 60 |
| `job_runs` | `started_at` | `RETENTION_JOB_RUNS_DAYS` | 30 |
| `alert_log` | `sent_at` | `RETENTION_ALERT_LOG_DAYS` | 365 |

No hay política para `fortinet_raw_snapshots`, las tablas
`cpanel_*` ni `ip_reputation_cache`: crecen sin límite (ver
[problemas-conocidos.md](problemas-conocidos.md)).

## Acceso y respaldo

- Conexión desde el host: `127.0.0.1:${DB_PORT_HOST}` (5434 por defecto en el
  compose). Consola: `bash scripts/start_db.sh psql`.
- Respaldo lógico de ejemplo:

  ```bash
  docker compose exec -T postgres pg_dump -U "$DB_USER" "$DB_NAME" | gzip > soc_$(date +%F).sql.gz
  ```

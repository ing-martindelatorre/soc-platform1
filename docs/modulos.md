# Módulos

Todos los módulos se registran en `app/pipeline/registry.py` y se ejecutan
con `python -m app.cli <módulo>` o desde el scheduler. Resumen:

| Módulo | Fuente | Autenticación | Modos |
|---|---|---|---|
| `sentinel` | SentinelOne (REST) | `S1_API_TOKEN` | único |
| `snyk` | CLI de Snyk sobre repos clonados | `SNYK_TOKEN` / `SNYK_ACCOUNT_<n>_TOKEN` | único |
| `nmap` | Binario `nmap` local | ninguna | perfiles `quick`, `full_tcp`, `perimeter`, `vuln` |
| `fortinet` | FortiGate REST (hasta 5 equipos) | token por equipo | `config`, `logs`, `threats` |
| `cpanel` | WHM API JSON + SSH | `WHM_API_TOKEN` + SSH | `stats`, `security`, `accounts`, `logs` |
| `ip_intel` | Shodan InternetDB + ipinfo.io | ninguna | (no es un pipeline) |

Variables de cada módulo: [variables-entorno.md](variables-entorno.md).

## SentinelOne (`app/modules/sentinel`)

- **Extract** (`SentinelExtractor`): llama a `GET {S1_BASE_URL}/web/api/v2.1/threats`
  con paginación por cursor (`limit` 200 por página). Acepta `date_from` y
  `date_to` (`createdAt__gte`, `createdAt__lte`) para reprocesar rangos.
- **Transform**: normaliza cada amenaza a `incident_id`, `threat_name`,
  `classification`, `severity`, `status`, `agent_*`, `username` y fechas.
  Calcula `raw_hash` y conserva la respuesta original en `raw_json`.
- **Load**: `INSERT … ON CONFLICT (incident_id) DO UPDATE` en lote. Un
  incidente que cambia de estado se actualiza, no se duplica.
- **Ejecutar:** `python -m app.cli sentinel [--limit 200] [--date-from …] [--date-to …]`.

## Snyk (`app/modules/snyk`)

A diferencia de lo que podría esperarse, **no usa la API de Snyk**: ejecuta
`snyk test --all-projects --json-file-output=…` sobre copias locales de los
repositorios.

Flujo completo:

1. `python -m app.pipeline.sync_repos` lista los repos de GitHub con
   `GITHUB_ORG_TOKEN`, aplica `SNYK_EXCLUDE_REPOS` y `SNYK_MAX_REPOS`, clona
   (`--depth=1`) o hace `git pull --ff-only` en `SNYK_REPOS_DIR`, y
   **reescribe `repos_snyk_batch.txt`** con las rutas clonadas.
2. El scheduler ejecuta `snyk_job`. El registry lee `repos_snyk_batch.txt`
   (una ruta por línea, `#` para comentarios) y llama a
   `run_snyk_scan_for_repos`.
3. Para cada repo, `pick_available_account` elige una cuenta habilitada y no
   bloqueada. Tras el escaneo, `snyk_error_classifier.py` traduce el código de
   salida y los mensajes en un estado.
4. Si el estado es válido, se parsean los hallazgos SCA, se **borran los
   hallazgos anteriores de ese repo** y se insertan los nuevos.

Estados de un escaneo: `success_no_issues`, `success_with_issues`,
`no_supported_project`, `failed_quota`, `failed_rate_limit`, `failed_auth`,
`failed_network`, `failed_cli_error`, `skipped_quota_guard`.

Rotación de cuentas: un fallo bloquea la cuenta un tiempo (`failed_rate_limit`
60 min, `failed_quota` 720 min, `failed_auth` 1440 min). Si todas están
bloqueadas o deshabilitadas, el repo se omite con `skipped_quota_guard`.

Otras utilidades:

- `python -m app.pipeline.backfill_snyk --repos-file … | --repo … | --status`:
  escaneo controlado o consulta del estado de las cuentas.
- Descarte de hallazgos desde el dashboard (`snyk_dismissals`); el motivo es
  obligatorio. Ver [dashboard-api.md](dashboard-api.md).
- `app/backfill_sentinel.py` es en realidad un pipeline **legado de Snyk**
  (nombre engañoso, ver [problemas-conocidos.md](problemas-conocidos.md)).

Requisitos: CLI de `snyk` instalada y `git`.

## Nmap (`app/modules/nmap`)

Flujo por target: `run_nmap_for_target` → XML → `parse_xml` → `enrich` →
`load_to_db`. Guarda además `<nombre>_<fecha>_enriched.json` y
`nmap_batch_last_summary.json` bajo `data/nmap_scans/`.

**Targets.** Se leen de `targets_nmap_batch.txt`, una línea por target:

```
# nombre|target|perfil|enabled
fw-principal|10.1.108.10|perimeter|true
```

`enabled` acepta `true`, `1`, `yes` o `si`. Las líneas con formato inválido
se omiten con una advertencia.

**Perfiles** (`profiles.py`):

| Perfil | Argumentos | Notas |
|---|---|---|
| `quick` | `-Pn -T4 -sT -sV --top-ports 100` | Ligero, sin root |
| `full_tcp` | `-Pn -T4 -sT -sV -p-` | Todos los puertos TCP |
| `perimeter` | `-Pn -T4 -sS -sV -O --top-ports 1000` | **Requiere root** (`-sS`, `-O`) |
| `vuln` | `-Pn -T4 -sT -sV --script vuln --top-ports 1000` | Pesado |

El scheduler ejecuta `nmap_quick_job` con `profile_override="quick"` y
`nmap_deep_job` con `profile_override="full_tcp"`, es decir, **ignora el perfil
de la tercera columna** y aplica el mismo a todos los targets habilitados.

**Enriquecimiento.** `service_mapper.py` clasifica servicios, calcula el
riesgo del puerto y marca versiones antiguas; `enrich_nmap_findings.py`
convierte todo en hallazgos con severidad, recomendación y categoría.

**Carga.** `upsert_asset` (por IP) y `upsert_service` (por activo, puerto y
protocolo); los hallazgos se insertan con vínculo al activo y al servicio.

## Fortinet (`app/modules/fortinet`)

`run_fortinet_pipeline(mode=…, device_id=…)` recorre cada equipo activo y
ejecuta `extract → transform → load`. Un fallo en un equipo no detiene a los
demás; `ok` es verdadero solo si todos tuvieron éxito. Equipos activos: los
que tengan URL y token (`FORTI_1_*` a `FORTI_5_*`).

| Modo | Endpoints (API v2) | Destino |
|---|---|---|
| `config` | `monitor/system/status`, `monitor/system/ha-status`, `cmdb/system/interface`, `cmdb/firewall/address`, `cmdb/firewall/policy`, `cmdb/router/static`, `cmdb/system/admin` | `fortinet_raw_snapshots` |
| `logs` | un endpoint de log en disco, por defecto `/api/v2/log/disk/traffic/forward/system` (cámbialo con `--endpoint`) | `fortinet_log_raw` |
| `threats` | logs en memoria: `traffic/forward`, `event/system`, `webfilter`, `event/vpn`, `ips`, `virus`; más el inventario `monitor/user/device/query` | `fortinet_threats` |

**Clasificación** (`transform.py`): `traffic` → `blocked` / `suspicious` /
`normal`; `event` → `login_failure` / `alert` / `critical` / `auth_event` /
`info`; `webfilter` → `blocked` / `suspicious` / `allowed`; `antivirus` →
`blocked` / `detected`. Las listas `HIGH_RISK_COUNTRIES`, `HIGH_RISK_APPS`,
`LOGIN_FAIL_LOGIDS` y `SUSPICIOUS_WEBFILTER_CATS` están al inicio de esa
sección y son el lugar para ajustar qué se considera sospechoso.

**Resolución de usuario.** El inventario de dispositivos de FortiGate
entrega, por IP, el hostname y el `unauth_user` (usuario o correo detectado al
vigilar autenticación POP3/IMAP/FTP). Se guarda en `user_email` y
`user_hostname`. Para antivirus, `sender` y `recipient` traen el buzón real
del correo infectado.

**Deduplicación.** El buffer en memoria del FortiGate rota lento, así que el
mismo lote reaparece en corridas consecutivas. `load.py` usa
`ON CONFLICT DO NOTHING` con clave `(device_name, source, eventtime)` para
tráfico, eventos, VPN y webfilter, y con una clave compuesta
`(device_name, log_date, log_time, srcip, dstip, dstport, virus, filename)`
para antivirus. Por eso `fortinet_threats_job` corre cada 5 minutos.

**Scripts de apoyo** (`scripts/`):

- `fortinet_policy_export.py [salida.json]`: exporta la configuración de
  todos los equipos a un JSON consolidado (por defecto en
  `data/fortinet_export/`). Contiene datos sensibles; no se sube a git.
- `fortinet_policy_analysis.py`: análisis de las políticas exportadas.

## cPanel / WHM (`app/modules/cpanel`)

| Modo | Fuente | Qué recolecta | Destino |
|---|---|---|---|
| `stats` | WHM API: `loadavg`, `version`, `gethostname`, `showbw` | Carga de CPU, versión, hostname, ancho de banda, cola de correo | `cpanel_server_stats` |
| `security` | WHM API (cPHulk) | Intentos de fuerza bruta y bloqueos | `cpanel_cphulk_events` |
| `accounts` | WHM API | Cuentas, plan, suspensión, uso de disco | `cpanel_accounts` |
| `logs` | SSH (paramiko) | Últimas 20 000 líneas de `/var/log/exim_mainlog` y `/var/log/maillog` | `cpanel_mail_events` |

Notas del modo `logs`:

- Clasifica cada línea de Exim como `accepted`, `delivered`, `bounce`,
  `virus`, `spam`, `rejected` o `connection_rejected`.
- El veredicto real de SpamAssassin **no está en `exim_mainlog`**; lo emite
  `spamd` en `/var/log/maillog` ("identified spam (score/threshold) for
  user:uid"), por eso se parsean ambos archivos. `spamd` solo indica el
  destinatario, no el remitente.
- Cada evento lleva un `line_hash` (sha256 de la línea) para no duplicar
  entre corridas.
- La conexión SSH usa `WHM_SSH_KEY_FILE` si existe y, si no, la contraseña.
  Requiere `paramiko`.
- `run_cpanel_pipeline` **captura la excepción y devuelve
  `{"ok": False, "error": …}`** en lugar de propagarla; `execute_job` trata
  `ok: False` como fallo y lo registra como `failed` en `job_runs`. Fortinet y
  Nmap se comportan igual.

## IP Intel (`app/modules/ip_intel`)

Enriquecedor que usa el dashboard de amenazas de Fortinet para quitar ruido
del tráfico saliente.

1. Para cada IP destino única consulta la caché (`ip_reputation_cache`,
   vigencia `IP_INTEL_CACHE_TTL_HOURS`).
2. Si no está, consulta Shodan InternetDB (hostnames, etiquetas, CVEs) e
   ipinfo.io (ASN, organización, país). No requiere API keys.
3. `trusted_orgs.py` decide si pertenece a una organización de confianza
   (lista de ASNs y patrones de nombre: Google, Microsoft, AWS, Cloudflare,
   Akamai, Meta, Apple, Netflix…).
4. `enrich_traffic_records(records, filter_known=True)` añade `intel_org`,
   `intel_verdict` (`trusted` o `unknown`) e `intel_vulns`, y **descarta** los
   registros hacia orgs de confianza.

Las IPs privadas no se consultan. Para confiar en una organización nueva,
agrega su ASN o un patrón a `trusted_orgs.py`.

## Cómo añadir un módulo nuevo

1. Crea `app/modules/<nombre>/` con `extract.py`, `transform.py`, `load.py`
   y `service.py`.
2. Registra el módulo en `app/pipeline/registry.py` (mismo esquema de
   `try/except` con fallback) y añádelo a `MODULES`.
3. Agrega su tabla en una migración `sql/0NN_*.sql`.
4. Añádelo a `choices` en `app/cli.py` y a `JOB_DEFINITIONS` en
   `app/pipeline/job_config.py`.
5. Si tendrá dashboard: hilo de refresh y entrada en `MODULE_STATUS` de
   `dashboard/server.py`, más la tarjeta en `dashboard/index.html`.
6. Si generará alertas: consultas en `QUERIES` y `MODULE_NAMES` de
   `app/alerts/engine.py`.
7. Documenta las variables en [variables-entorno.md](variables-entorno.md).

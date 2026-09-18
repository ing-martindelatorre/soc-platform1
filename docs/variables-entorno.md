# Variables de entorno

Se leen del archivo `.env` en la raíz del proyecto (nunca se versiona).
`app/core/config.py` usa `pydantic-settings` para un subconjunto;
el resto se lee con `os.getenv` en cada módulo. El scheduler y el
dashboard cargan el `.env` con `python-dotenv` o con `EnvironmentFile` de
systemd.

En las tablas, **Requerida** indica si el módulo falla sin la variable.
Un valor "—" significa que no hay valor por defecto.

## Base de datos

| Variable | Defecto | Requerida | Uso |
|---|---|---|---|
| `DB_HOST` | `127.0.0.1` (`localhost` en `Settings`) | sí | Host de PostgreSQL |
| `DB_PORT` | `5432` | sí | Puerto. Con Docker, el puerto publicado (`DB_PORT_HOST`) |
| `DB_NAME` | `soc_db` en `db.py`, `soc` en `server.py` y `config.py` | sí | Nombre de la base |
| `DB_USER` | `soc_user` | sí | Usuario |
| `DB_PASSWORD` | — | sí | Contraseña |
| `DB_APP_NAME` | `soc-platform` | no | `application_name` de la conexión |
| `DB_PORT_HOST` | `5434` (compose) / `5433` (`start_db.sh`) | no | Puerto externo que publica Docker |
| `SOC_DB_HOST`, `SOC_DB_PORT`, `SOC_DB_NAME`, `SOC_DB_USER`, `SOC_DB_PASS` | valor de `DB_*` | no | Anulan `DB_*` solo en `run_sentinel_dashboard.py` |
| `DATABASE_URL` | — | solo `app/backfill_sentinel.py` | Cadena de conexión para el pipeline legado de Snyk |
| `PGADMIN_EMAIL`, `PGADMIN_PASSWORD` | `admin@soc.local`, `socadmin` | no | Login de pgAdmin |

> Los valores por defecto de `DB_NAME` no coinciden entre archivos. Define
> siempre `DB_NAME` explícitamente.

## SentinelOne

| Variable | Requerida | Uso |
|---|---|---|
| `S1_BASE_URL` | sí | URL de la consola (se consulta `/web/api/v2.1/threats`) |
| `S1_API_TOKEN` | sí | Token de API (`Authorization: ApiToken …`) |

## Snyk y GitHub

| Variable | Defecto | Uso |
|---|---|---|
| `SNYK_TOKEN` | — | Cuenta única de Snyk (alias `SNYK_ACCOUNT_ALIAS`, por defecto `default`) |
| `SNYK_ACCOUNT_<n>_TOKEN` | — | Token de la cuenta `n` (1, 2, 3… hasta que falte alguna) |
| `SNYK_ACCOUNT_<n>_ALIAS` | `account_<n>` | Nombre de la cuenta |
| `SNYK_ACCOUNT_<n>_ENABLED` | `true` | Habilita o deshabilita la cuenta |
| `SNYK_ORG_ID` | — | Organización de Snyk (se pasa a la CLI) |
| `SNYK_RAW_DIR` | `data/raw/snyk` | Dónde se guardan los JSON crudos |
| `SNYK_LOGS_DIR` | — | Logs (solo pipeline legado) |
| `SNYK_TIMEOUT_SECONDS` | `900` | Timeout por repo (solo pipeline legado) |
| `SNYK_REPOS_DIR` | `./data/repos` | Directorio donde `sync_repos.py` clona |
| `SNYK_MAX_REPOS` | sin límite | Máximo de repos a procesar |
| `SNYK_EXCLUDE_REPOS` | — | Repos a excluir, separados por coma |
| `SNYK_SYNC_FROM_GITHUB` | `true` | Solo pipeline legado |
| `SNYK_DASHBOARD_PORT` | `8010` | Puerto de `run_snyk_dashboard.py` en modo independiente |
| `GITHUB_ORG` | — | Organización de GitHub (requerida por `sync_repos.py`) |
| `GITHUB_ORG_TOKEN` | — | Token con permisos `repo` y `read:org` (requerida por `sync_repos.py`) |
| `GH_CLONE_PROTOCOL` | `https` | Solo pipeline legado |

## FortiGate

Se soportan hasta 5 equipos. Para el equipo `n` (1 a 5):

| Variable | Defecto | Uso |
|---|---|---|
| `FORTI_<n>_BASE_URL` (o `_HOST`) | — | URL del equipo. Activa el equipo junto con el token |
| `FORTI_<n>_API_TOKEN` (o `_TOKEN`) | — | Token de la API REST |
| `FORTI_<n>_DEVICE_NAME` | `fortigate-<n>` | Nombre mostrado y clave `device_name` en la DB |
| `FORTI_<n>_VDOM` | `root` | VDOM |
| `FORTI_<n>_VERIFY_SSL` | `true` | Verificación del certificado |
| `FORTI_<n>_TIMEOUT` | `30` | Timeout en segundos |

Para el equipo 1 también se aceptan las variables heredadas sin número:
`FORTI_BASE_URL`, `FORTI_HOST`, `FORTI_API_TOKEN`, `FORTI_TOKEN`,
`FORTI_DEVICE_NAME`, `FORTI_VDOM`, `FORTI_VERIFY_SSL`, `FORTI_TIMEOUT`.
Si ningún equipo tiene URL y token, el pipeline intenta el equipo 1 de todos
modos.

## Nmap

| Variable | Uso |
|---|---|
| `NMAP_DEFAULT_TARGETS` | Declarada en `Settings`; los targets reales salen de `targets_nmap_batch.txt` |
| `ZEEK_LOG_DIR` | Declarada en `Settings`; no hay módulo que la use hoy |

## WHM / cPanel

| Variable | Defecto | Uso |
|---|---|---|
| `WHM_BASE_URL` | — | URL de WHM, por ejemplo `https://servidor:2087` |
| `WHM_API_TOKEN` | — | Token de API de WHM (`Authorization: whm root:<token>`) |
| `WHM_VERIFY_SSL` | `true` | Verificación del certificado |
| `WHM_TIMEOUT` | `30` | Timeout en segundos |
| `WHM_SSH_HOST` | host derivado de `WHM_BASE_URL` | Host SSH para leer los logs de correo |
| `WHM_SSH_PORT` | `22` | Puerto SSH |
| `WHM_SSH_USER` | `root` | Usuario SSH |
| `WHM_SSH_PASSWORD` | — | Contraseña SSH (alternativa a la llave) |
| `WHM_SSH_KEY_FILE` | — | Ruta a la llave privada. Tiene prioridad sobre la contraseña |
| `WHM_SSH_TIMEOUT` | `30` | Timeout SSH |

## Correo y Slack (alertas)

| Variable | Defecto | Uso |
|---|---|---|
| `SMTP_HOST` | — | Servidor SMTP. Sin él, no se envía nada |
| `SMTP_PORT` | `587` | `465` usa SSL directo; otro valor usa STARTTLS si `SMTP_TLS` es verdadero |
| `SMTP_USER` | — | Usuario SMTP |
| `SMTP_PASSWORD` | — | Contraseña SMTP |
| `SMTP_FROM` | `SMTP_USER` | Remitente |
| `SMTP_TLS` | `true` | Habilita STARTTLS |
| `SLACK_WEBHOOK_URL` | — | Webhook de Slack; si está vacío no se notifica en Slack |
| `SOC_URL` | `localhost:8888` | Host que aparece en los enlaces de correos y Slack |
| `PIPELINE_ALERT_RECIPIENTS` | — | Correos (separados por coma) que reciben alertas de fallos de pipeline |
| `PIPELINE_ALERT_COOLDOWN` | `60` | Minutos entre alertas de fallo del mismo job |

## Dashboard

| Variable | Defecto | Uso |
|---|---|---|
| `DASHBOARD_HOST` | `0.0.0.0` | Interfaz de escucha |
| `DASHBOARD_PORT` | `8888` | Puerto |
| `CONFIG_USER`, `CONFIG_PASSWORD` | — | Credenciales de acceso. Sin ellas el panel queda **deshabilitado** |
| `CORS_ORIGIN` | vacío | Origen permitido; vacío significa solo mismo origen |
| `SSL_CERT_FILE`, `SSL_KEY_FILE` | — | Si ambos existen, el servidor usa HTTPS |
| `DASH_REFRESH_SENTINEL` | `30` | Segundos entre refrescos |
| `DASH_REFRESH_NMAP` | `300` | Ídem |
| `DASH_REFRESH_FORTINET` | `60` | Ídem |
| `DASH_REFRESH_FORTINET_THREATS` | `120` | Ídem |
| `DASH_REFRESH_SNYK` | `300` | Ídem |
| `DASH_REFRESH_CPANEL` | `300` | Ídem |
| `DASHBOARD_REFRESH_SECONDS` | `30` | Solo `run_sentinel_dashboard.py` independiente |

## Retención

Días que se conservan los datos (ver
[base-de-datos.md](base-de-datos.md#retención)):

| Variable | Defecto |
|---|---|
| `RETENTION_SENTINEL_DAYS` | 90 |
| `RETENTION_SNYK_DAYS` | 180 |
| `RETENTION_NMAP_DAYS` | 90 |
| `RETENTION_NMAP_ASSETS_DAYS` | 180 |
| `RETENTION_FORTINET_DAYS` | 365 |
| `RETENTION_JOB_RUNS_DAYS` | 30 |
| `RETENTION_ALERT_LOG_DAYS` | 365 |

## Otras

| Variable | Defecto | Uso |
|---|---|---|
| `IP_INTEL_CACHE_TTL_HOURS` | `168` (7 días) | Vigencia de la caché de reputación de IPs |
| `APP_NAME`, `APP_ENV` | `soc-platform`, `dev` | Declaradas en `Settings` |

## Plantilla mínima de `.env`

No existe un `.env.example` en el repositorio (`setup.sh` lo menciona). Esta
plantilla cubre lo esencial; agrega solo los módulos que uses.

```dotenv
# Base de datos
DB_HOST=127.0.0.1
DB_PORT=5434
DB_NAME=soc
DB_USER=soc_user
DB_PASSWORD=cambia-esto
DB_PORT_HOST=5434

# Dashboard
CONFIG_USER=admin
CONFIG_PASSWORD=cambia-esto
SOC_URL=soc.tu-dominio.local:8888

# SentinelOne
S1_BASE_URL=https://tu-consola.sentinelone.net
S1_API_TOKEN=

# FortiGate 1
FORTI_1_BASE_URL=https://10.0.0.1
FORTI_1_API_TOKEN=
FORTI_1_DEVICE_NAME=fortigate-principal

# Correo
SMTP_HOST=smtp.tu-dominio.com
SMTP_PORT=587
SMTP_USER=alertas@tu-dominio.com
SMTP_PASSWORD=
```

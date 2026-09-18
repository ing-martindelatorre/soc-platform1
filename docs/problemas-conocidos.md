# Problemas conocidos

Inconsistencias y riesgos detectados al revisar el código en septiembre de
2026. Están ordenados por prioridad sugerida. Al resolver uno, bórralo de
esta lista.

## Alta prioridad

### 1. Datos sensibles: pendiente el historial de git

Los archivos con datos sensibles ya **no se versionan** (se sacaron del
índice y se añadieron al `.gitignore`), pero **siguen en el historial de
git**: cualquiera con acceso al repositorio puede recuperarlos con
`git log`. Afecta a:

| Archivo | Contenido |
|---|---|
| `virus_bloqueados_fortinet_2semanas.csv` | Buzones y remitentes reales de correos infectados |
| `repos_snyk_batch.txt` | Rutas de repos |
| `dashboard/fortinet_dashboard_*.html` | Generados desde la DB; incluyen políticas e interfaces del firewall |
| `dashboard/nmap_dashboard_output.html` | Generado; incluye activos, puertos y hallazgos |
| `targets_nmap_batch.txt` | IPs públicas e internas de la red |

Además, `sql/019_alert_antivirus_rule.sql` (que sigue versionada) tiene un
correo personal como destinatario de la regla.

Si el repositorio se comparte fuera de la organización, hay que reescribir el
historial (por ejemplo con `git filter-repo`) y rotar lo que corresponda. Es
una operación destructiva que obliga a un `push --force` y a que todo el
equipo vuelva a clonar; no se ha hecho.

Para arrancar en un clon nuevo, copia `targets_nmap_batch.example.txt` a
`targets_nmap_batch.txt` y ajústalo; `repos_snyk_batch.txt` lo genera
`sync_repos.py`.

### 2. Fallos parciales ahora cuentan como `failed`

Corregido: `execute_job` marca `failed` cuando el pipeline devuelve
`ok: False`, no solo cuando lanza una excepción. Efecto a tener en cuenta:
Fortinet devuelve `ok: False` si **falla cualquier equipo**, y Nmap si falla
**cualquier target**, así que un solo equipo caído deja el job completo en
`failed` (con el detalle por equipo en `message`) y, si está definido
`PIPELINE_ALERT_RECIPIENTS`, dispara alerta de fallo.

### 3. Seguridad del dashboard y de los clones

- Sesiones en memoria, cookie sin `Secure`, credenciales comparadas con `==`,
  sin límite de intentos de login.
- Escucha en `0.0.0.0` y sirve HTTP si no se definen `SSL_CERT_FILE` y
  `SSL_KEY_FILE`.
- `sync_repos.py` incrusta `GITHUB_ORG_TOKEN` en la URL de `git clone`; el
  token queda guardado en el `.git/config` de cada clon y visible en la lista
  de procesos durante la clonación. Usar un helper de credenciales o
  `GIT_ASKPASS`.
- `ssh_extract.py` usa `AutoAddPolicy` (acepta cualquier huella de host).
  Cargar `known_hosts` evita ataques de intermediario.
- `build_email_html` inserta datos de logs externos en HTML sin escapar.
- `snyk_scan_runs` guarda los últimos 10 000 caracteres de stdout y stderr de
  cada escaneo; revisa que no contengan secretos.

## Prioridad media

### 4. Dependencias y versión de Python

- `paramiko` no está en `requirements.txt` (cPanel `logs` falla sin él).
- `app/backfill_sentinel.py` y `scripts/check_env.sh` usan `psycopg` (v3); el
  resto usa `psycopg2`.
- `app/modules/nmap` importa `UTC` de `datetime`, lo que exige **Python 3.11 o
  superior**. En 3.10 el registry cae en silencio al fallback de Nmap.
- No existe `.env.example` aunque `setup.sh` lo menciona.

### 5. Valores por defecto inconsistentes

| Elemento | Valores encontrados |
|---|---|
| `DB_NAME` | `soc_db` (`db.py`), `soc` (`server.py`, `config.py`) |
| Puerto publicado de Postgres | `5434` (`docker-compose.yml`), `5433` (`start_db.sh`) |
| Puerto de pgAdmin | `8081` (compose), `8080` (`start_db.sh`, texto anterior de CLAUDE.md) |
| Puerto del dashboard | `8888` (código), `8889` (descripción de la unidad systemd) |
| Contraseña por defecto de DB | `soc_pass` (`config.py`), `soc_pass_local` (`run_sentinel_dashboard.py`) |

### 6. Retención incompleta y duplicada

- `fortinet_raw_snapshots`, `fortinet_log_raw`, `cpanel_*` e
  `ip_reputation_cache` no tienen política de retención.
- `dashboard/server.py` borra `fortinet_threats` de más de 1 año de forma fija
  (`cleanup_fortinet_threats`), en paralelo a `RETENTION_FORTINET_DAYS` del
  scheduler.
- La migración 023 documenta que `fortinet_threats` tenía ~17 millones de
  filas con duplicados históricos que no se limpiaron.

### 7. Alertas: cobertura y configuración

- No hay consultas de alerta ni entrada en `MODULE_NAMES` para `cpanel`.
- `alert_rules.device_filter` solo se puede establecer por SQL; la API y el
  panel no lo exponen.
- El cooldown de alertas de fallo de pipeline vive en memoria y se pierde al
  reiniciar.

### 8. Esquema de Snyk sin migración

`snyk_scan_runs` y `snyk_account_state` se crean en tiempo de ejecución
(`ensure_snyk_tables`), y `snyk_findings` se define en la migración 003 y otra
vez en `load.py`. `insert_snyk_findings` consulta las columnas reales de la
tabla, lo que sugiere que ya hubo desajustes de esquema. Conviene mover todo
a migraciones.

### 9. CLI incompleto

`python -m app.cli` no acepta `--mode threats` (`choices` solo incluye
`config`, `logs`, `stats`, `security`, `accounts`), aunque Fortinet lo
soporta. El CLI también pasa `mode="config"` por defecto a todos los módulos.

## Prioridad baja

### 10. Código y archivos sin uso

- `dashboard/server_patch_threats.py`: parche suelto.
- `app/backfill_sentinel.py`: por el nombre parece de Sentinel, pero es un
  pipeline **legado de Snyk** (depende de `DATABASE_URL`, `extract_snyk_raw`…).
- `app/pipeline/backfill_snyk.py`: útil, pero coexiste con el anterior.
- `proyectosaquitar.txt`: notas de repos a excluir; ya existe
  `SNYK_EXCLUDE_REPOS`.
- Tablas `collector_runs` y `assets` (migración 001): sin uso en el código.
- Migración 004: `job_config` original, reconstruida por la 025.
- Variables `NMAP_DEFAULT_TARGETS` y `ZEEK_LOG_DIR`: declaradas y sin uso.

### 11. Pruebas

Solo existe `tests/test_smoke.py`, que comprueba que cuatro módulos estén en
`MODULES` (no incluye `cpanel` ni valida que dejen de ser `_Fallback`). No hay
pruebas de clasificación (`_classify_*`), de deduplicación de alertas, de
`validate_schedule` ni de los parsers de Nmap y de logs de cPanel, que son
funciones puras fáciles de cubrir.

### 12. Otros

- El scheduler usa `print` en lugar del logger `soc-platform`.
- Migraciones sin runner ni tabla de versiones: no hay forma de saber qué
  migraciones se aplicaron a una base concreta.

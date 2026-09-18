# Arquitectura

## Visión general

Dos procesos Python independientes comparten la misma base de datos:

| Proceso | Comando | Responsabilidad |
|---|---|---|
| Scheduler | `python -m app.pipeline.scheduler` | Ejecutar los pipelines de recolección, el motor de alertas y la limpieza |
| Dashboard | `python dashboard/server.py` | Generar los datos de los dashboards, servirlos por HTTP(S) y exponer la API de configuración |

Ambos leen y escriben en PostgreSQL 16, que es lo único que corre en Docker
(junto con pgAdmin). La aplicación corre en un venv local.

```
                 ┌──────────────────────────── scheduler ────────────────────────────┐
 APIs externas   │  APScheduler (BlockingScheduler, America/Mexico_City)              │
 y CLIs  ───────▶│  execute_job → runner → registry → <modulo>.service                │
                 │  alert_engine_job (5 min) · config_watcher_job (30 s) · cleanup 3am│
                 └───────────────────────────────┬────────────────────────────────────┘
                                                 │ escribe
                                          ┌──────▼──────┐
                                          │ PostgreSQL  │
                                          └──────┬──────┘
                                                 │ lee
                 ┌──────────────────────────── dashboard ────────────────────────────┐
 Navegador ◀────▶│  ThreadingHTTPServer :8888 · un hilo de refresh por módulo         │
                 │  genera *.json / *.html · API REST /api/*                          │
                 └────────────────────────────────────────────────────────────────────┘
```

## Patrón ETL

Cada módulo bajo `app/modules/<nombre>/` sigue la misma estructura:

| Archivo | Rol |
|---|---|
| `extract.py` | Obtiene datos crudos de la fuente externa |
| `transform.py` | Normaliza, clasifica y enriquece |
| `load.py` | Escribe en PostgreSQL |
| `service.py` | Orquesta `extract → transform → load` y devuelve un resumen |

Las excepciones son Nmap (que separa el pipeline en `run_nmap_scan.py`,
`parse_nmap_xml.py`, `enrich_nmap_findings.py`, `pipeline_nmap.py`), Snyk (que
añade `snyk_error_classifier.py`) y `ip_intel` (que no es un pipeline sino un
enriquecedor invocado por el dashboard). Detalles en [modulos.md](modulos.md).

## Registry y runner

`app/pipeline/registry.py` importa cada módulo dentro de un `try/except`.
Si el import falla (dependencia ausente, error de sintaxis) registra un
`warning` en el log y coloca una clase `_Fallback<Modulo>` que devuelve
`{"ok": False, "error": "no disponible"}`. El resultado es que **un módulo
roto no impide el arranque, pero tampoco hace nada**: ante un job que
"no hace nada", lo primero es buscar `[registry] <modulo> no disponible` en
el log.

`MODULES` expone cinco entradas: `sentinel`, `snyk`, `nmap`, `fortinet`,
`cpanel`. `app/pipeline/runner.py::run_module(nombre, **kwargs)` resuelve el
módulo y llama a `execute(**kwargs)`. Lo usan el scheduler y el CLI
(`python -m app.cli`).

## Scheduler

`app/pipeline/scheduler.py` usa `BlockingScheduler` con zona horaria
`America/Mexico_City`. Cada ejecución de un módulo pasa por `execute_job`,
que registra inicio y fin en `job_runs`. Un pipeline que lanza una excepción
**o devuelve `ok: False`** queda como `failed`; el resto como `success`
(estado `running`, `success` o
`failed`; el mensaje se trunca a 5000 caracteres).

### Jobs de recolección (configurables)

Se definen en `app/pipeline/job_config.py::JOB_DEFINITIONS`. Lo fijo (qué
módulo ejecutar y con qué argumentos) está en código; **la frecuencia y el
estado habilitado viven en la tabla `job_config`** y se editan desde el panel
de configuración.

| job_id | Ejecuta | Frecuencia por defecto |
|---|---|---|
| `sentinel_job` | `sentinel` | cada 5 min |
| `fortinet_config_job` | `fortinet` modo `config` | cada 15 min |
| `fortinet_logs_job` | `fortinet` modo `logs` | cada 15 min, desfase de +7 min |
| `fortinet_threats_job` | `fortinet` modo `threats` | cada 5 min |
| `nmap_quick_job` | `nmap` perfil `quick` | cada 360 min (6 h) |
| `nmap_deep_job` | `nmap` perfil `full_tcp` | cron `0 2 * * 0` (domingos 2:00) |
| `snyk_job` | `snyk` | cron `0 1 * * *` (diario 1:00) |
| `cpanel_stats_job` | `cpanel` modo `stats` | cada 15 min |
| `cpanel_security_job` | `cpanel` modo `security` | cada 15 min, desfase de +5 min |
| `cpanel_accounts_job` | `cpanel` modo `accounts` | cada 60 min |
| `cpanel_logs_job` | `cpanel` modo `logs` | cada 30 min |

Todos se registran con `max_instances=1` y `coalesce=True`: si una ejecución
tarda más que el intervalo, no se solapa y las ejecuciones perdidas se
funden en una.

Los tipos de horario válidos son `interval` (minutos enteros, entre 1 y
10080) y `cron` (expresión crontab de cinco campos, validada con
`CronTrigger.from_crontab`).

### Cambios en caliente

`config_watcher_job` corre cada 30 s, lee `job_config` y compara con la caché
en memoria `_applied_schedules`. Si cambió el intervalo hace
`reschedule_job`; si cambió `enabled` hace `pause_job` o `resume_job`. No hace
falta reiniciar el scheduler. Si un `job_id` no tiene fila,
`get_all_schedules()` la crea con los valores por defecto de
`JOB_DEFINITIONS`.

### Jobs fijos

| job_id | Frecuencia | Qué hace |
|---|---|---|
| `config_watcher_job` | 30 s | Aplica cambios de `job_config` |
| `alert_engine_job` | 5 min | `evaluate_and_send()` y `evaluate_job_failures()` |
| `cleanup_job` | diario 03:00 | Borra registros según la política de retención |

## Tablas de control

- `job_runs`: una fila por ejecución. `job_name` guarda el **nombre del
  módulo** (`sentinel`, `fortinet`…), no el `job_id` de APScheduler, así que
  los tres jobs de Fortinet comparten historial. La vista `v_job_runs_latest`
  entrega la última ejecución por módulo.
- `job_config`: horario y estado de cada job (ver arriba).

## Retención de datos

`app/pipeline/cleanup.py` borra filas antiguas de las tablas principales.
Detalle y variables en [base-de-datos.md](base-de-datos.md#retención).

## Dashboard

`dashboard/server.py` arranca un hilo por módulo (`sentinel`, `nmap`,
`fortinet`, `fortinet-threats`, `snyk`, `cpanel`), cada uno con su intervalo
de refresh (`DASH_REFRESH_*`). Cada hilo consulta la DB y escribe un JSON o un
HTML en `dashboard/`, y actualiza `MODULE_STATUS`. Un hilo aparte vuelca
`soc_status.json` cada 5 s, que el `index.html` usa como semáforo de salud.
Los archivos `dashboard/*.json` están en `.gitignore`. Más en
[dashboard-api.md](dashboard-api.md).

## Decisiones de diseño relevantes

- **Sin ORM.** Se usa `psycopg2` directo, con `RealDictCursor` y helpers en
  `app/core/db.py` (`get_connection`, `db_connection`, `db_cursor`,
  `bulk_upsert`).
- **Datos crudos conservados.** Fortinet guarda el `payload` JSONB original
  junto a los campos extraídos, lo que permite reclasificar sin volver a la
  API.
- **Deduplicación por contenido.** cPanel usa `line_hash` (sha256 de la línea
  de log); Fortinet usa claves de tiempo de evento; las alertas usan
  `dedup_key`.
- **Dónde vive la lógica de clasificación.** Está en
  `transform.py` de cada módulo (por ejemplo `_classify_traffic` en Fortinet),
  no en el dashboard ni en la DB.

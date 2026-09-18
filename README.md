# SOC Platform 1 (Leviathan SOC)

Plataforma de agregación de datos de seguridad. Recolecta información de
varias herramientas (SentinelOne, Snyk, Nmap, FortiGate y WHM/cPanel), la
centraliza en PostgreSQL, la muestra en dashboards web y envía alertas por
correo y Slack cuando se cumplen reglas configurables.

```
 Fuentes                    Pipelines ETL              Salida
┌─────────────┐          ┌──────────────────┐      ┌───────────────────┐
│ SentinelOne │──┐       │                  │      │ Dashboards web    │
│ Snyk (CLI)  │──┤       │  APScheduler     │      │ (puerto 8888)     │
│ Nmap        │──┼──────▶│  extract         │─────▶│                   │
│ FortiGate×5 │──┤       │  → transform     │  DB  │ Motor de alertas  │
│ WHM/cPanel  │──┘       │  → load          │      │ (email + Slack)   │
└─────────────┘          └──────────────────┘      └───────────────────┘
                                   │
                            PostgreSQL 16 (Docker)
```

## Componentes

| Componente | Qué hace | Documentación |
|---|---|---|
| Módulos `app/modules/*` | Extraen, normalizan y cargan datos de cada fuente | [docs/modulos.md](docs/modulos.md) |
| Scheduler `app/pipeline/scheduler.py` | Ejecuta cada pipeline con su propia frecuencia (editable en caliente) | [docs/arquitectura.md](docs/arquitectura.md) |
| Motor de alertas `app/alerts/engine.py` | Evalúa reglas de la DB, deduplica y notifica | [docs/alertas.md](docs/alertas.md) |
| Dashboard `dashboard/server.py` | Sirve los dashboards, publica el estado de salud y expone la API de configuración | [docs/dashboard-api.md](docs/dashboard-api.md) |
| Base de datos `sql/` | 25 migraciones, sin runner | [docs/base-de-datos.md](docs/base-de-datos.md) |

Toda la documentación está en [docs/](docs/README.md).

## Requisitos

- Linux (Ubuntu, Kali o WSL) para el setup automatizado. En Windows se puede
  trabajar manualmente con Python y Docker Desktop.
- Python 3.11 o superior (el módulo Nmap usa `datetime.UTC`).
- Docker con Compose v2 (solo para PostgreSQL y pgAdmin).
- Paquetes del sistema: `python3`, `python3-venv`, `python3-pip`, `git`,
  `curl`, `jq`, `net-tools`, `build-essential`, `libpq-dev`.
- Opcionales según el módulo: `nmap` (módulo Nmap), CLI de `snyk` (módulo
  Snyk), `zeek`.

## Inicio rápido

```bash
# 1. Preparar venv, dependencias y dashboards iniciales
bash scripts/setup.sh
pip install paramiko   # solo si usarás cPanel por SSH (falta en requirements.txt)

# 2. Crear el .env (ver docs/variables-entorno.md; nunca se sube a git)
#    Mínimo: DB_*  y las credenciales de los módulos que vayas a usar.

# 3. Levantar PostgreSQL + pgAdmin
bash scripts/start_db.sh up

# 4. Migraciones: en una base nueva Docker ya las aplicó al crear el volumen.
#    Solo es necesario aplicarlas a mano en una base existente (ver nota abajo).

# 5. Probar un módulo
source venv/bin/activate
python -m app.cli sentinel

# 6. Arrancar el scheduler (bloqueante) y el dashboard
python -m app.pipeline.scheduler
python dashboard/server.py
```

Después abre `http://localhost:8888/index.html`. Cualquier página exige
iniciar sesión en `/config.html` con `CONFIG_USER` y `CONFIG_PASSWORD`; si esas
variables no están definidas el panel queda deshabilitado.

> **Migraciones.** Docker ejecuta `sql/*.sql` automáticamente solo cuando
> crea el volumen de datos por primera vez. Una base ya existente necesita
> aplicar a mano las migraciones nuevas, en orden:
>
> ```bash
> docker compose exec -T postgres psql -U "$DB_USER" -d "$DB_NAME" < sql/026_nueva.sql
> ```
>
> El modo `threats` de Fortinet lo ejecuta el scheduler; el CLI no lo expone
> (ver [docs/problemas-conocidos.md](docs/problemas-conocidos.md)).

## Comandos habituales

```bash
# Base de datos
bash scripts/start_db.sh up|down|restart|reset|logs|status|psql

# Ejecutar un módulo una vez
python -m app.cli <sentinel|snyk|nmap|fortinet|cpanel> [--mode ...]

# Ejemplos por modo (el CLI acepta: config, logs, stats, security, accounts)
python -m app.cli fortinet --mode logs
python -m app.cli cpanel   --mode logs

# Sincronizar repos de GitHub para Snyk
python -m app.pipeline.sync_repos --list-only

# Prueba mínima
pytest tests/test_smoke.py
```

## Estructura del repositorio

```
app/
  cli.py, main.py        Entrada por línea de comandos
  core/                  config, conexión a DB, logging, excepciones
  modules/<nombre>/      extract.py · transform.py · load.py · service.py
  pipeline/              registry, runner, scheduler, job_config, cleanup, sync_repos
  alerts/engine.py       Motor de alertas (email y Slack)
dashboard/
  server.py              Servidor único (dashboards + API de configuración)
  *.html                 Dashboards y plantilla de correo
  run_*_dashboard.py     Generadores individuales por módulo
sql/                     Migraciones 001 a 025
scripts/                 setup, gestión de DB, servicios systemd, utilidades Fortinet
tests/                   Prueba de humo
docs/                    Documentación detallada
```

## Operación en producción

El repositorio incluye dos unidades systemd en `scripts/`
(`soc-platform1.service` para el scheduler y `soc-platform1-dashboard.service`
para el dashboard). Los pasos de instalación, monitoreo y resolución de
problemas están en [docs/operacion.md](docs/operacion.md).

## Seguridad

- El `.env` contiene tokens y contraseñas: no se versiona.
- Los datos que la plataforma recolecta (correos de empleados, configuración
  del firewall, IPs) son sensibles. Revisa
  [docs/problemas-conocidos.md](docs/problemas-conocidos.md) antes de subir
  archivos generados al repositorio.
- Define `SSL_CERT_FILE` y `SSL_KEY_FILE` para servir el dashboard por HTTPS.

# Operación

## Instalación en un servidor Linux

1. **Sistema y venv.** `bash scripts/setup.sh` instala los paquetes del
   sistema, crea `venv/`, instala `requirements.txt` y genera dashboards
   iniciales. Está pensado para Ubuntu, Kali o WSL.
2. **Dependencias que faltan en `requirements.txt`.** Instálalas a mano si vas
   a usar cPanel por SSH:

   ```bash
   source venv/bin/activate
   pip install paramiko
   ```

3. **`.env`.** Créalo a partir de la plantilla de
   [variables-entorno.md](variables-entorno.md). Usa `chmod 600 .env`.
4. **Base de datos.** `bash scripts/start_db.sh up`. En un volumen vacío
   Docker aplica las 25 migraciones.
5. **Herramientas externas** (según los módulos que actives):
   - Nmap: `sudo apt install nmap` (los perfiles `perimeter` requieren root).
   - Snyk: CLI instalada y autenticada por token; `git` para clonar.
6. **Archivos de entrada** (no están en git, o no deberían):
   - `targets_nmap_batch.txt`: `nombre|target|perfil|enabled`.
   - `repos_snyk_batch.txt`: rutas de repos. Se regenera con
     `python -m app.pipeline.sync_repos`.
7. **Prueba manual** antes de programar nada:

   ```bash
   python -m app.cli sentinel
   python -m app.cli fortinet --mode config
   ```

## Servicios systemd

El repositorio trae dos unidades en `scripts/`:

| Unidad | Ejecuta |
|---|---|
| `soc-platform1.service` | `venv/bin/python -m app.pipeline.scheduler` |
| `soc-platform1-dashboard.service` | `venv/bin/python dashboard/server.py` (depende del anterior) |

Ambas están escritas para el usuario `zidane` y la ruta
`/home/zidane/soc-platform1`; **edita `User`, `WorkingDirectory`,
`EnvironmentFile` y `ExecStart`** si tu instalación es distinta.

```bash
sudo cp scripts/soc-platform1.service scripts/soc-platform1-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now soc-platform1 soc-platform1-dashboard
```

Ambas reinician solas ante un fallo (`Restart=on-failure`, 15 s). La unidad
del scheduler carga el `.env` con `EnvironmentFile`; la del dashboard no, pero
`server.py` lo carga con `python-dotenv`.

Comandos frecuentes:

```bash
systemctl status soc-platform1 soc-platform1-dashboard
journalctl -u soc-platform1 -f
journalctl -u soc-platform1-dashboard -f
sudo systemctl restart soc-platform1
```

El scheduler escribe con `print` (`[OK]`, `[ERROR]`, `[config]`, `[alerts]`,
`[cleanup]`) y los módulos con el logger `soc-platform`. Ambos llegan a
`journalctl`.

## Tareas habituales

### Cambiar cada cuánto corre un módulo

Desde el panel `config.html`, pestaña de intervalos, o con la API
(`PUT /api/config/schedules/<job_id>`). Se aplica en unos 30 s sin reiniciar.
También se puede editar `job_config` directamente en SQL.

### Ejecutar un pipeline a mano

```bash
python -m app.cli fortinet --mode logs
python -m app.cli cpanel --mode logs
python -m app.cli sentinel --date-from 2026-09-01T00:00:00Z --date-to 2026-09-10T00:00:00Z
```

El modo `threats` de Fortinet no está en las opciones del CLI; para
ejecutarlo:

```bash
python -c "from app.pipeline.runner import run_module; print(run_module('fortinet', mode='threats'))"
```

### Actualizar los repos y escanear con Snyk

```bash
python -m app.pipeline.sync_repos            # clona o actualiza y regenera repos_snyk_batch.txt
python -m app.pipeline.backfill_snyk --status   # estado de las cuentas Snyk
python -m app.pipeline.backfill_snyk --repos-file repos_snyk_batch.txt
```

Para excluir repos permanentemente usa `SNYK_EXCLUDE_REPOS` en el `.env`.

### Aplicar una migración nueva

```bash
docker compose exec -T postgres psql -U "$DB_USER" -d "$DB_NAME" < sql/026_algo.sql
```

Para tablas grandes como `fortinet_threats` (millones de filas), aplica los
`ALTER` en una ventana tranquila; la migración 024 usa `lock_timeout` para no
bloquear la tabla.

### Rotar credenciales

1. Cambia el valor en `.env`.
2. `sudo systemctl restart soc-platform1 soc-platform1-dashboard`.
3. Las sesiones del dashboard se cierran al reiniciar.

### Respaldo y restauración

```bash
docker compose exec -T postgres pg_dump -U "$DB_USER" "$DB_NAME" | gzip > soc_$(date +%F).sql.gz
gunzip -c soc_2026-09-18.sql.gz | docker compose exec -T postgres psql -U "$DB_USER" -d "$DB_NAME"
```

## Diagnóstico

| Síntoma | Causa probable | Qué revisar |
|---|---|---|
| Un job aparece como `failed` con `"error": "no disponible"` | El módulo cayó al `_Fallback` del registry (import fallido) | Buscar `[registry] … no disponible` en el log y el campo `message` de `job_runs` |
| Un job de Fortinet o Nmap sale `failed` pero recolecta datos | Falló solo uno de varios equipos o targets (fallo parcial) | El campo `message` de `job_runs` trae el detalle por equipo o target |
| Nmap no arranca en Python 3.10 | `from datetime import UTC` exige Python 3.11 o superior | Versión de Python y log del registry |
| cPanel `logs` falla | Falta `paramiko`, o credenciales/llave SSH | `pip list \| grep paramiko`, `WHM_SSH_*` |
| Fortinet sin datos de un equipo | Falta URL o token en `FORTI_<n>_*` | El equipo solo se activa con ambos |
| Fortinet falla con SSL | Certificado autofirmado | `FORTI_<n>_VERIFY_SSL=false` |
| No llegan alertas | SMTP sin configurar, regla en cooldown o sin consulta para ese campo | Log `[alerts]`, `alert_log`, `SMTP_HOST` y `SMTP_USER` |
| No llega ninguna alerta aunque el dashboard funciona | El scheduler no corre: es el único que evalúa reglas | `systemctl status soc-platform1` |
| El panel responde 503 al iniciar sesión | Faltan `CONFIG_USER` o `CONFIG_PASSWORD` | `.env` del proceso del dashboard |
| Todas las páginas redirigen a `/config.html` | No hay sesión activa | Iniciar sesión; las sesiones duran 8 h |
| Snyk marca `skipped_quota_guard` | Todas las cuentas bloqueadas por cuota, límite o autenticación | `python -m app.pipeline.backfill_snyk --status` |
| El intervalo del panel no se aplica | El scheduler no corre, o `job_id` desconocido | `journalctl -u soc-platform1`, líneas `[config]` |
| Tráfico Fortinet demasiado ruidoso | Destinos legítimos no reconocidos | Ampliar `trusted_orgs.py` |
| "connection refused" a la DB | Puerto equivocado | `DB_PORT` debe ser el puerto publicado por Docker (`DB_PORT_HOST`, 5434 por defecto) |

Consultas útiles en `psql`:

```sql
-- Última ejecución de cada módulo
SELECT * FROM v_job_runs_latest;

-- Fallos recientes
SELECT job_name, started_at, left(message, 200)
FROM job_runs WHERE status = 'failed' ORDER BY started_at DESC LIMIT 20;

-- Estado de los intervalos
SELECT job_name, enabled, schedule_type, schedule_value FROM job_config ORDER BY job_name;

-- Cuánto ocupa cada tabla
SELECT relname, pg_size_pretty(pg_total_relation_size(relid))
FROM pg_catalog.pg_statio_user_tables ORDER BY pg_total_relation_size(relid) DESC LIMIT 10;
```

## Desarrollo en Windows

`setup.sh` y `start_db.sh` son scripts de bash para Linux. En Windows se
puede trabajar con Git Bash o WSL para los scripts, y con Docker Desktop para
PostgreSQL. Los módulos Nmap y Snyk necesitan sus binarios instalados en la
misma máquina que el scheduler.

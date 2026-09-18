# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SOC Platform 1 (Leviathan SOC) is a security data aggregation platform. It pulls data from five sources — **SentinelOne**, **Snyk** (CLI), **Nmap**, **FortiGate** (up to 5 devices) and **WHM/cPanel** — into PostgreSQL, runs scheduled ETL pipelines, serves web dashboards and sends email/Slack alerts.

Detailed documentation (in Spanish) lives in `docs/`; start at `docs/README.md`. Keep it in sync when you change a module, env var or migration:
`arquitectura.md`, `modulos.md`, `variables-entorno.md`, `base-de-datos.md`, `alertas.md`, `dashboard-api.md`, `operacion.md`, `problemas-conocidos.md`.

## Architecture

Two independent processes share one database:

- **Scheduler** (`python -m app.pipeline.scheduler`) — APScheduler `BlockingScheduler`, timezone `America/Mexico_City`. Runs collection jobs, the alert engine and data cleanup.
- **Dashboard** (`python dashboard/server.py`) — single `ThreadingHTTPServer` on port 8888. One refresh thread per module writes JSON/HTML into `dashboard/`, and it exposes the REST API under `/api/*`.

**ETL pattern** — every module under `app/modules/<name>/` follows:
- `extract.py` → pulls raw data from the external source
- `transform.py` → normalizes/classifies/enriches
- `load.py` → writes to PostgreSQL (uses `RealDictCursor`; rows are dicts, not tuples)
- `service.py` → orchestrates extract → transform → load

Exceptions: Nmap splits the pipeline across `run_nmap_scan.py`, `parse_nmap_xml.py`, `enrich_nmap_findings.py`, `pipeline_nmap.py`; Snyk adds `snyk_error_classifier.py`; `ip_intel` is an enricher used by the dashboard, not a pipeline.

**Module registry** (`app/pipeline/registry.py`) — wraps each module import in try/except and substitutes a `_Fallback<Module>` class that returns `{"ok": False, "error": "no disponible"}` if the import fails. This hides missing-dependency errors at startup; check the log for `[registry] <module> no disponible` if a module silently does nothing. `MODULES` = `sentinel`, `snyk`, `nmap`, `fortinet`, `cpanel`. `app/pipeline/runner.py::run_module` dispatches to it (used by the scheduler and the CLI).

**Configurable schedules** — collection frequencies are NOT hardcoded. `app/pipeline/job_config.py::JOB_DEFINITIONS` holds the fixed part (module, kwargs, misfire grace, start offset, defaults); the interval/cron and `enabled` flag live in the `job_config` table. `config_watcher_job` polls that table every 30 s and reschedules/pauses/resumes jobs live. Default schedules:
- `sentinel_job` every 5 min
- `fortinet_config_job` every 15 min; `fortinet_logs_job` every 15 min (+7 min offset); `fortinet_threats_job` every 5 min (the FortiGate memory-log buffer rotates fast)
- `nmap_quick_job` every 360 min (`profile_override="quick"`); `nmap_deep_job` cron `0 2 * * 0` (`full_tcp`)
- `snyk_job` cron `0 1 * * *`
- `cpanel_stats_job` 15 min, `cpanel_security_job` 15 min (+5 offset), `cpanel_accounts_job` 60 min, `cpanel_logs_job` 30 min

Fixed jobs: `alert_engine_job` (every 5 min), `cleanup_job` (daily 03:00), `config_watcher_job` (30 s). `job_runs` stores the **module name** (not the APScheduler job id) with status `running|success|failed`; messages truncated to 5000 chars. `execute_job` records `failed` when a pipeline raises **or returns `ok: False`** (Fortinet/Nmap return `ok: False` if any single device/target fails).

**Alerts** (`app/alerts/engine.py`) — rules in `alert_rules`, per-entity dedup via `alert_log.dedup_key` within `cooldown_minutes`, one email per rule evaluation, optional Slack webhook. Queries exist for sentinel, fortinet (`classification`, `source`, `antivirus`), snyk and nmap only — not cpanel. The engine runs only in the scheduler (`alert_engine_job`); the dashboard has no alert thread, so no alerts are sent if the scheduler is down.

**Database** — PostgreSQL 16 (Docker). The app runs in a local venv; only Postgres and pgAdmin are containerized.

## Setup

One-time setup (Linux only; use Git Bash/WSL on Windows):
```bash
bash scripts/setup.sh
```

Requires system packages: `python3`, `python3-venv`, `python3-pip`, `git`, `curl`, `jq`, `net-tools`, `build-essential`, `libpq-dev`. Optionally `nmap`, the `snyk` CLI and `zeek`. **Python 3.11+** is required (Nmap code uses `datetime.UTC`). `paramiko` is needed for cPanel SSH logs but is missing from `requirements.txt`.

## Key Commands

**Database management:**
```bash
bash scripts/start_db.sh up       # start PostgreSQL + pgAdmin
bash scripts/start_db.sh down     # stop
bash scripts/start_db.sh reset    # wipe and restart
bash scripts/start_db.sh logs     # tail container logs
bash scripts/start_db.sh psql     # open psql shell
```
pgAdmin is published on `http://localhost:8081` by `docker-compose.yml` (`start_db.sh` prints 8080, which is wrong). Postgres is published on `DB_PORT_HOST` (compose default 5434, `start_db.sh` default 5433).

**Run a single module (in venv):**
```bash
python -m app.cli sentinel
python -m app.cli snyk
python -m app.cli nmap
python -m app.cli fortinet --mode config|logs   # CLI has no `threats` choice; use run_module('fortinet', mode='threats')
python -m app.cli cpanel --mode stats|security|accounts|logs
```

**Scheduler and dashboard:**
```bash
python -m app.pipeline.scheduler   # blocking
python dashboard/server.py         # http(s)://localhost:8888/index.html, login at /config.html
```

**Snyk repo sync / backfill:**
```bash
python -m app.pipeline.sync_repos --list-only
python -m app.pipeline.backfill_snyk --status
```

**Smoke test:**
```bash
pytest tests/test_smoke.py
```

## Environment Variables

Create a `.env` in the project root (never commit it). There is no `.env.example`. The full list with defaults is in `docs/variables-entorno.md`. Summary by area:

| Area | Variables |
|---|---|
| PostgreSQL | `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_PORT_HOST` |
| SentinelOne | `S1_BASE_URL`, `S1_API_TOKEN` |
| Snyk / GitHub | `SNYK_TOKEN` or `SNYK_ACCOUNT_<n>_TOKEN/_ALIAS/_ENABLED`, `SNYK_ORG_ID`, `SNYK_REPOS_DIR`, `SNYK_RAW_DIR`, `SNYK_MAX_REPOS`, `SNYK_EXCLUDE_REPOS`, `GITHUB_ORG`, `GITHUB_ORG_TOKEN` |
| FortiGate (1–5) | `FORTI_<n>_BASE_URL`, `FORTI_<n>_API_TOKEN`, `FORTI_<n>_DEVICE_NAME`, `FORTI_<n>_VDOM`, `FORTI_<n>_VERIFY_SSL`, `FORTI_<n>_TIMEOUT` (device 1 also accepts the legacy un-numbered `FORTI_*`) |
| WHM/cPanel | `WHM_BASE_URL`, `WHM_API_TOKEN`, `WHM_VERIFY_SSL`, `WHM_SSH_HOST/_PORT/_USER/_PASSWORD/_KEY_FILE` |
| Nmap | targets come from `targets_nmap_batch.txt`; `NMAP_DEFAULT_TARGETS` and `ZEEK_LOG_DIR` are declared but unused |
| Alerts | `SMTP_HOST/_PORT/_USER/_PASSWORD/_FROM/_TLS`, `SLACK_WEBHOOK_URL`, `SOC_URL`, `PIPELINE_ALERT_RECIPIENTS`, `PIPELINE_ALERT_COOLDOWN` |
| Dashboard | `DASHBOARD_HOST`, `DASHBOARD_PORT`, `CONFIG_USER`, `CONFIG_PASSWORD` (panel disabled without them), `CORS_ORIGIN`, `SSL_CERT_FILE`, `SSL_KEY_FILE`, `DASH_REFRESH_<MODULE>` |
| Retention | `RETENTION_{SENTINEL,SNYK,NMAP,NMAP_ASSETS,FORTINET,JOB_RUNS,ALERT_LOG}_DAYS` |
| Other | `IP_INTEL_CACHE_TTL_HOURS`, `PGADMIN_EMAIL`, `PGADMIN_PASSWORD` |

## Code Conventions

- Comments and docstrings are written in **Spanish**.
- All modules use `from __future__ import annotations` and Python 3.10+ type hints.
- Custom logger name: `"soc-platform"` (via `app/core/logging.py`). The scheduler itself still uses `print`.
- DB cursor: always `RealDictCursor` — rows are dicts. Helpers in `app/core/db.py` (`get_connection`, `db_connection`, `db_cursor`, `bulk_upsert`).
- No ORM, no linter or formatter configured; maintain existing style manually.
- Fortinet classification rules (`HIGH_RISK_COUNTRIES`, `HIGH_RISK_APPS`, …) live in `app/modules/fortinet/transform.py`; trusted-org lists for IP reputation in `app/modules/ip_intel/trusted_orgs.py`.

## Database Migrations

SQL migrations are in `sql/`, numbered `001_` through `025_`. There is no migration runner: Docker applies them only when the data volume is first created (`./sql` is mounted in `docker-entrypoint-initdb.d`); on an existing database apply new ones manually, in order, via psql or pgAdmin. Make new migrations idempotent and use the next free number. Note: `snyk_scan_runs` and `snyk_account_state` are created at runtime by `ensure_snyk_tables()` in `app/modules/snyk/load.py`, not by a migration.

## Gotchas

- Snyk does **not** use the Snyk API: it runs `snyk test --all-projects` on local clones. `sync_repos.py` clones/pulls org repos and rewrites `repos_snyk_batch.txt`; the `snyk` pipeline reads that file.
- The Nmap scheduler jobs pass `profile_override`, so the profile column in `targets_nmap_batch.txt` is ignored by them.
- `app/backfill_sentinel.py` is misnamed — it is a legacy **Snyk** pipeline. `dashboard/server_patch_threats.py` is a stray patch file.
- All dashboard pages (not only `/api/*`) require a session; `/config.html` and `/favicon.ico` are the only public paths.
- Generated dashboard files (`dashboard/*_output.html`, `fortinet_dashboard_<device>.html`), `virus_bloqueados_*.csv`, `targets_nmap_batch.txt` and `repos_snyk_batch.txt` contain sensitive data and are git-ignored (untracked but still present in git history). Never `git add -f` them; copy `targets_nmap_batch.example.txt` to create your own targets file.
- Known issues and cleanup candidates are tracked in `docs/problemas-conocidos.md`.

## Data Batch Files

- `repos_snyk_batch.txt` — repo paths for Snyk scans (regenerated by `sync_repos.py`; git-ignored)
- `targets_nmap_batch.txt` — Nmap targets, format `nombre|target|perfil|enabled` (`#` for comments); git-ignored, template in `targets_nmap_batch.example.txt`

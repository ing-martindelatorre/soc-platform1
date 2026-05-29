# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SOC Platform 1 is a security data aggregation platform that pulls data from four security tools (Azure Sentinel, Snyk, Nmap, FortiGate) into a central PostgreSQL database, with scheduled ETL pipelines, web dashboards, and email alerting.

## Architecture

**ETL Pattern** — every module under `app/modules/<name>/` strictly follows:
- `extract.py` → pulls raw data from external API
- `transform.py` → normalizes/enriches data
- `load.py` → writes to PostgreSQL (uses `RealDictCursor`; rows are dicts, not tuples)
- `service.py` → orchestrates extract → transform → load

**Module Registry** (`app/pipeline/registry.py`) — wraps each module import in try/except and substitutes a `_Fallback<Module>` class if the import fails. This hides missing-dependency errors at startup; check logs if a module silently does nothing.

**Scheduler** (`app/pipeline/scheduler.py`) — APScheduler in blocking mode, timezone hardcoded to `America/Mexico_City`. Schedule:
- Sentinel: every 5 min
- Fortinet config: every 15 min; Fortinet logs: +7 min offset; Fortinet threats: +3 min offset
- Nmap quick: every 6 h; Nmap deep: Sundays 2 am
- Snyk: Sundays 1 am

**Database** — PostgreSQL 16 (Docker). App runs in a local venv; only the DB is containerized.

## Setup

One-time setup (Linux only):
```bash
bash scripts/setup.sh
```

Requires system packages: `python3`, `python3-venv`, `python3-pip`, `git`, `curl`, `jq`, `net-tools`, `build-essential`, `libpq-dev`. Optionally `nmap` and `zeek`.

## Key Commands

**Database management:**
```bash
bash scripts/start_db.sh up       # start PostgreSQL + pgAdmin
bash scripts/start_db.sh down     # stop
bash scripts/start_db.sh reset    # wipe and restart
bash scripts/start_db.sh logs     # tail container logs
bash scripts/start_db.sh psql     # open psql shell
```
pgAdmin available at `http://localhost:8080`.

**Run a single module (in venv):**
```bash
python -m app.cli sentinel
python -m app.cli snyk
python -m app.cli nmap
python -m app.cli fortinet
```

**Run full scheduler (blocking):**
```bash
python app/pipeline/scheduler.py
```

**Run a dashboard:**
```bash
python dashboard/run_sentinel_dashboard.py
python dashboard/run_snyk_dashboard.py
python dashboard/run_nmap_dashboard.py
python dashboard/run_fortinet_dashboard.py
```

**Smoke test:**
```bash
pytest tests/test_smoke.py
```

## Required Environment Variables

Create a `.env` file in the project root (never commit it):

| Variable | Purpose |
|---|---|
| `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD` | PostgreSQL connection |
| `S1_BASE_URL`, `S1_API_TOKEN` | Azure Sentinel |
| `SNYK_API_TOKEN`, `SNYK_ORG_ID` | Snyk |
| `FORTI_BASE_URL`, `FORTI_API_TOKEN` | FortiGate |
| `NMAP_DEFAULT_TARGETS` | Comma-separated hosts for Nmap |
| `ZEEK_LOG_DIR` | Path to Zeek log directory |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TLS` | Alert emails |
| `PGADMIN_EMAIL`, `PGADMIN_PASSWORD` | pgAdmin web login |

## Code Conventions

- Comments and docstrings are written in **Spanish**.
- All modules use `from __future__ import annotations` and Python 3.10+ type hints.
- Custom logger name: `"soc-platform"` (via `app/core/logging.py`).
- DB cursor: always `RealDictCursor` — rows are dicts.
- Job run outcomes are tracked in the `job_runs` table; messages are truncated to 5000 chars.
- No linter or formatter is configured; maintain existing style manually.

## Database Migrations

SQL migrations are in `sql/` numbered `001_` through `011_`. Run them in order against the database. There is no migration runner — apply manually via psql or pgAdmin.

## Data Batch Files (not in git)

- `repos_snyk_batch.txt` — list of repo paths for Snyk batch scans (populate manually)
- `targets_nmap_batch.txt` — list of Nmap targets (populate manually)

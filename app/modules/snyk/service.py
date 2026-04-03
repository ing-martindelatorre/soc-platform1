from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

from .extract import load_raw_json, run_snyk_test
from .load import (
    delete_previous_findings_for_repo,
    ensure_snyk_tables,
    finalize_scan_run,
    get_accounts_status,
    insert_scan_run_start,
    insert_snyk_findings,
    is_account_blocked,
    mark_account_failure,
    mark_account_success,
    touch_account,
)
from .snyk_error_classifier import build_error_signature, is_valid_scan_status
from .transform import parse_snyk_sca_findings


@dataclass
class SnykAccount:
    alias: str
    token: str
    enabled: bool = True


def _to_bool(value: str | None, default: bool = True) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def load_snyk_accounts_from_env() -> list[SnykAccount]:
    accounts: list[SnykAccount] = []

    single = os.getenv("SNYK_TOKEN")
    if single:
        accounts.append(
            SnykAccount(
                alias=os.getenv("SNYK_ACCOUNT_ALIAS", "default"),
                token=single,
                enabled=True,
            )
        )

    idx = 1
    while True:
        token = os.getenv(f"SNYK_ACCOUNT_{idx}_TOKEN")
        alias = os.getenv(f"SNYK_ACCOUNT_{idx}_ALIAS")
        enabled = os.getenv(f"SNYK_ACCOUNT_{idx}_ENABLED")

        if token is None and alias is None and enabled is None:
            break

        if token:
            accounts.append(
                SnykAccount(
                    alias=alias or f"account_{idx}",
                    token=token,
                    enabled=_to_bool(enabled, default=True),
                )
            )
        idx += 1

    dedup: dict[str, SnykAccount] = {}
    for account in accounts:
        dedup[account.alias] = account

    return list(dedup.values())


def pick_available_account(org_id: str | None = None) -> SnykAccount | None:
    accounts = load_snyk_accounts_from_env()
    if not accounts:
        raise RuntimeError("No encontré cuentas Snyk en el entorno.")

    for account in accounts:
        touch_account(account.alias, org_id, is_enabled=account.enabled)

    for account in accounts:
        if not account.enabled:
            continue
        if is_account_blocked(account.alias):
            continue
        return account

    return None


def run_snyk_scan_for_repo(repo_path: str) -> dict:
    ensure_snyk_tables()

    org_id = os.getenv("SNYK_ORG_ID")
    account = pick_available_account(org_id=org_id)

    repo = Path(repo_path).resolve()
    if not repo.exists():
        return {
            "repo_name": repo.name,
            "repo_path": str(repo),
            "status": "failed_cli_error",
            "message": f"El repositorio no existe: {repo}",
        }

    if not account:
        return {
            "repo_name": repo.name,
            "repo_path": str(repo),
            "status": "skipped_quota_guard",
            "message": "No hay cuentas Snyk disponibles. Todas están bloqueadas o deshabilitadas.",
        }

    scan_run_id = insert_scan_run_start(
        repo_name=repo.name,
        repo_path=str(repo),
        account_alias=account.alias,
        org_id=org_id,
        started_at=datetime.now(timezone.utc),
        scan_type="sca",
    )

    result = None
    findings_count = 0
    error_signature = ""

    try:
        result = run_snyk_test(
            repo_path=str(repo),
            account_alias=account.alias,
            token=account.token,
            org_id=org_id,
        )

        error_signature = build_error_signature(result.stdout, result.stderr)

        if is_valid_scan_status(result.status):
            raw_json = load_raw_json(result.json_path)

            if raw_json is None:
                result.status = "failed_cli_error"
                extra = f"json missing/empty at {result.json_path}"
                error_signature = f"{error_signature} | {extra}".strip(" |")
                mark_account_failure(account.alias, org_id, result.status, block_minutes=0)
            else:
                rows = parse_snyk_sca_findings(
                    raw_json=raw_json,
                    repo_name=result.repo_name,
                    repo_path=result.repo_path,
                    scan_run_id=scan_run_id,
                )

                delete_previous_findings_for_repo(result.repo_name, scan_type="sca")
                findings_count = insert_snyk_findings(rows)
                mark_account_success(account.alias, org_id)
        else:
            if result.status == "failed_rate_limit":
                mark_account_failure(account.alias, org_id, result.status, block_minutes=60)
            elif result.status == "failed_quota":
                mark_account_failure(account.alias, org_id, result.status, block_minutes=720)
            elif result.status == "failed_auth":
                mark_account_failure(account.alias, org_id, result.status, block_minutes=1440)
            else:
                mark_account_failure(account.alias, org_id, result.status, block_minutes=0)

        finalize_scan_run(
            scan_run_id=scan_run_id,
            finished_at=result.finished_at,
            exit_code=result.exit_code,
            status=result.status,
            findings_count=findings_count,
            raw_json_path=result.json_path,
            stdout_log=result.stdout[-10000:],
            stderr_log=result.stderr[-10000:],
            error_signature=error_signature,
        )

        return {
            "scan_run_id": scan_run_id,
            "repo_name": result.repo_name,
            "repo_path": result.repo_path,
            "account_alias": result.account_alias,
            "status": result.status,
            "exit_code": result.exit_code,
            "findings_count": findings_count,
            "json_path": result.json_path,
            "error_signature": error_signature,
        }

    except Exception as e:
        finalize_scan_run(
            scan_run_id=scan_run_id,
            finished_at=datetime.now(timezone.utc),
            exit_code=getattr(result, "exit_code", 2) if result else 2,
            status="failed_cli_error",
            findings_count=0,
            raw_json_path=getattr(result, "json_path", "") if result else "",
            stdout_log=(getattr(result, "stdout", "") or "")[-10000:] if result else "",
            stderr_log=(getattr(result, "stderr", "") or "")[-10000:] if result else "",
            error_signature=f"exception: {type(e).__name__}: {e}",
        )
        mark_account_failure(account.alias, org_id, "failed_cli_error", block_minutes=0)
        raise

def run_snyk_scan_for_repos(repo_paths: list[str]) -> list[dict]:
    results = []
    for repo_path in repo_paths:
        results.append(run_snyk_scan_for_repo(repo_path))
    return results


def get_snyk_accounts_status() -> list[dict]:
    ensure_snyk_tables()
    accounts = load_snyk_accounts_from_env()

    if accounts:
        org_id = os.getenv("SNYK_ORG_ID")
        for account in accounts:
            touch_account(account.alias, org_id, is_enabled=account.enabled)

    return get_accounts_status()
from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .snyk_error_classifier import classify_snyk_result


@dataclass
class SnykExecutionResult:
    repo_name: str
    repo_path: str
    account_alias: str
    json_path: str
    exit_code: int
    status: str
    stdout: str
    stderr: str
    started_at: datetime
    finished_at: datetime
    org_id: str | None = None


def _slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9._-]+", "_", value)
    return value.strip("_") or "repo"


def _ensure_output_dir() -> Path:
    # Respeta lo que pongas en .env; si no existe usa data/raw/snyk
    base = Path(os.getenv("SNYK_RAW_DIR", "data/raw/snyk")).resolve()
    base.mkdir(parents=True, exist_ok=True)
    return base


def run_snyk_test(repo_path: str, account_alias: str, token: str, org_id: str | None = None) -> SnykExecutionResult:
    repo = Path(repo_path).resolve()
    repo_name = repo.name
    out_dir = _ensure_output_dir()

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_path = out_dir / f"{_slugify(repo_name)}_{timestamp}.json"

    env = os.environ.copy()
    env["SNYK_TOKEN"] = token

    cmd = [
        "snyk",
        "test",
        "--all-projects",
        f"--json-file-output={json_path}",
    ]

    if org_id:
        cmd.append(f"--org={org_id}")

    started_at = datetime.now(timezone.utc)
    proc = subprocess.run(
        cmd,
        cwd=str(repo),
        env=env,
        capture_output=True,
        text=True,
    )
    finished_at = datetime.now(timezone.utc)

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    status = classify_snyk_result(proc.returncode, stdout, stderr)

    return SnykExecutionResult(
        repo_name=repo_name,
        repo_path=str(repo),
        account_alias=account_alias,
        json_path=str(json_path),
        exit_code=proc.returncode,
        status=status,
        stdout=stdout,
        stderr=stderr,
        started_at=started_at,
        finished_at=finished_at,
        org_id=org_id,
    )


def load_raw_json(json_path: str):
    path = Path(json_path).resolve()

    if not path.exists():
        return None

    if path.stat().st_size == 0:
        return None

    with path.open("r", encoding="utf-8") as f:
        return json.load(f)
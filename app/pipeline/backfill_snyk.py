from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.modules.snyk.service import get_snyk_accounts_status, run_snyk_scan_for_repos


def _load_repos_from_file(file_path: str) -> list[str]:
    repos: list[str] = []
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"No existe el archivo de repos: {file_path}")

    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        repos.append(line)

    return repos


def main():
    parser = argparse.ArgumentParser(description="Backfill/controlado de Snyk SCA por repositorio")
    parser.add_argument("--repos-file", help="Archivo con rutas de repos, una por línea")
    parser.add_argument("--repo", action="append", help="Ruta de repo individual; se puede repetir")
    parser.add_argument("--status", action="store_true", help="Muestra estado de cuentas Snyk")
    parser.add_argument("--pretty", action="store_true", help="Imprime JSON bonito")

    args = parser.parse_args()

    if args.status:
        data = get_snyk_accounts_status()
        print(json.dumps(data, indent=2 if args.pretty else None, default=str, ensure_ascii=False))
        return

    repo_paths: list[str] = []

    if args.repos_file:
        repo_paths.extend(_load_repos_from_file(args.repos_file))

    if args.repo:
        repo_paths.extend(args.repo)

    if not repo_paths:
        raise SystemExit("Debes indicar --repos-file o al menos un --repo")

    results = run_snyk_scan_for_repos(repo_paths)
    print(json.dumps(results, indent=2 if args.pretty else None, default=str, ensure_ascii=False))


if __name__ == "__main__":
    main()
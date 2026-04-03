import os
import psycopg

from app.modules.snyk.extract import extract_snyk_raw, summarize_extraction
from app.modules.snyk.transform import transform_snyk_runs
from app.modules.snyk.load import load_snyk_data


REQUIRED_ENV_VARS = [
    "SNYK_REPOS_DIR",
    "SNYK_RAW_DIR",
    "SNYK_LOGS_DIR",
    "DATABASE_URL",
]


def require_env(name: str) -> None:
    if not os.environ.get(name):
        raise RuntimeError(f"Falta variable de entorno requerida: {name}")


def run() -> None:
    for name in REQUIRED_ENV_VARS:
        require_env(name)

    repos_dir = os.environ["SNYK_REPOS_DIR"]
    raw_dir = os.environ["SNYK_RAW_DIR"]
    logs_dir = os.environ["SNYK_LOGS_DIR"]
    database_url = os.environ["DATABASE_URL"]

    sync_from_github = os.environ.get("SNYK_SYNC_FROM_GITHUB", "true").lower() in {"1", "true", "yes"}
    github_org = os.environ.get("GITHUB_ORG")
    github_clone_protocol = os.environ.get("GH_CLONE_PROTOCOL", "https")

    max_repos = os.environ.get("SNYK_MAX_REPOS")
    snyk_timeout_seconds = int(os.environ.get("SNYK_TIMEOUT_SECONDS", "900"))

    if max_repos:
        max_repos = int(max_repos)

    print("\n========== PIPELINE SNYK ==========\n")

    print("[INFO] Configuración:")
    print(f"[INFO] sync_from_github = {sync_from_github}")
    print(f"[INFO] github_org = {github_org}")
    print(f"[INFO] repos_dir = {repos_dir}")
    print(f"[INFO] raw_dir = {raw_dir}")
    print(f"[INFO] logs_dir = {logs_dir}")
    print(f"[INFO] max_repos = {max_repos}")
    print(f"[INFO] timeout = {snyk_timeout_seconds}s")

    print("\n[INFO] Paso 1/3: Extracción\n")
    payload = extract_snyk_raw(
        repos_dir=repos_dir,
        raw_dir=raw_dir,
        logs_dir=logs_dir,
        include_code=True,
        include_sca=True,
        sync_from_github=sync_from_github,
        github_org=github_org,
        github_clone_protocol=github_clone_protocol,
        max_repos=max_repos,
        snyk_timeout_seconds=snyk_timeout_seconds,
    )

    scan_runs = payload["scan_runs"]
    summary = summarize_extraction(payload)

    print("\n[INFO] Resumen de extracción:")
    print(summary)

    print("\n[INFO] Paso 2/3: Transformación\n")
    findings, transform_errors = transform_snyk_runs(scan_runs)

    print(f"[INFO] scan_runs = {len(scan_runs)}")
    print(f"[INFO] findings = {len(findings)}")
    print(f"[INFO] transform_errors = {len(transform_errors)}")

    if transform_errors:
        print("[WARN] Errores de transformación:")
        for err in transform_errors[:20]:
            print(err)

    print("\n[INFO] Paso 3/3: Carga en base de datos\n")
    with psycopg.connect(database_url) as conn:
        result = load_snyk_data(conn, scan_runs, findings)
        print(result)

    print("\n========== FIN PIPELINE ==========\n")


if __name__ == "__main__":
    run()
"""
app/pipeline/sync_repos.py

Clona o actualiza repositorios de una organización de GitHub
antes de pasarlos al pipeline de Snyk.

Uso:
    # Clonar todos los repos de la org
    python3 -m app.pipeline.sync_repos

    # Clonar repos específicos desde archivo
    python3 -m app.pipeline.sync_repos --repos-file repos_snyk_batch.txt

    # Ver qué repos hay en la org sin clonar
    python3 -m app.pipeline.sync_repos --list-only

Variables de entorno requeridas:
    GITHUB_ORG          Nombre de la organización (ej: uwipes-com)
    GITHUB_ORG_TOKEN    Token con permisos repo/read:org de esa org
    SNYK_REPOS_DIR      Directorio donde se clonan los repos (ej: ./data/repos)
    SNYK_MAX_REPOS      Límite de repos a clonar (opcional)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path


# =============================================================================
# Config
# =============================================================================

def _get_required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Falta variable de entorno: {name}")
    return value


def _repos_dir() -> Path:
    path = Path(os.getenv("SNYK_REPOS_DIR", "./data/repos")).resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


# =============================================================================
# GitHub API — listar repos de la org
# =============================================================================

def list_org_repos(org: str, token: str, max_repos: int | None = None) -> list[dict]:
    """
    Lista repos de una org usando la GitHub API REST.
    Pagina automáticamente hasta traer todos o hasta max_repos.
    """
    import urllib.request
    import urllib.error

    repos = []
    page = 1
    per_page = 100

    while True:
        url = f"https://api.github.com/user/repos?per_page={per_page}&page={page}&sort=updated&affiliation=owner,collaborator,organization_member"
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                batch = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"GitHub API error {e.code}: {e.reason} — verifica el token y org")

        if not batch:
            break

        repos.extend(batch)

        if max_repos and len(repos) >= max_repos:
            repos = repos[:max_repos]
            break

        if len(batch) < per_page:
            break

        page += 1

    return repos


# =============================================================================
# Clonado / actualización
# =============================================================================

def clone_or_pull(repo: dict, token: str, repos_dir: Path) -> dict:
    """
    Clona un repo si no existe, o hace git pull si ya está clonado.
    Retorna un dict con el resultado.
    """
    repo_name  = repo["name"]
    clone_url  = repo["clone_url"]
    repo_path  = repos_dir / repo_name

    # Inyectar token en la URL para autenticación
    # https://TOKEN@github.com/org/repo.git
    auth_url = clone_url.replace("https://", f"https://{token}@")

    started_at = datetime.now(timezone.utc)

    try:
        if repo_path.exists() and (repo_path / ".git").exists():
            # Ya existe — hacer pull
            result = subprocess.run(
                ["git", "pull", "--ff-only"],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                timeout=120,
            )
            action = "pulled"
        else:
            # No existe — clonar
            result = subprocess.run(
                ["git", "clone", "--depth=1", auth_url, str(repo_path)],
                capture_output=True,
                text=True,
                timeout=300,
            )
            action = "cloned"

        success = result.returncode == 0
        return {
            "repo_name":  repo_name,
            "repo_path":  str(repo_path),
            "action":     action,
            "success":    success,
            "returncode": result.returncode,
            "stderr":     result.stderr.strip()[:500] if not success else "",
            "started_at": started_at.isoformat(),
            "finished_at": datetime.now(timezone.utc).isoformat(),
        }

    except subprocess.TimeoutExpired:
        return {
            "repo_name":  repo_name,
            "repo_path":  str(repo_path),
            "action":     "timeout",
            "success":    False,
            "returncode": -1,
            "stderr":     "Timeout al clonar",
            "started_at": started_at.isoformat(),
            "finished_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        return {
            "repo_name":  repo_name,
            "repo_path":  str(repo_path),
            "action":     "error",
            "success":    False,
            "returncode": -1,
            "stderr":     str(e),
            "started_at": started_at.isoformat(),
            "finished_at": datetime.now(timezone.utc).isoformat(),
        }


# =============================================================================
# Cargar repos desde archivo (rutas locales o nombres)
# =============================================================================

def load_repos_from_file(file_path: str) -> list[str]:
    """
    Lee nombres de repos desde un archivo, uno por línea.
    Acepta rutas completas (extrae el nombre) o solo nombres.
    """
    names = []
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"No existe el archivo: {file_path}")

    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Si es una ruta, tomar solo el nombre del directorio
        names.append(Path(line).name)

    return names


# =============================================================================
# Main
# =============================================================================

def sync_repos(
    repos_file: str | None = None,
    list_only: bool = False,
    max_repos: int | None = None,
) -> dict:
    org   = _get_required("GITHUB_ORG")
    token = _get_required("GITHUB_ORG_TOKEN")
    repos_dir = _repos_dir()

    if max_repos is None:
        env_max = os.getenv("SNYK_MAX_REPOS")
        max_repos = int(env_max) if env_max else None

    print(f"[sync] Org:       {org}")
    print(f"[sync] Repos dir: {repos_dir}")
    print(f"[sync] Max repos: {max_repos or 'sin límite'}")
    print(f"[sync] Listando repos de {org}...")

    all_repos = list_org_repos(org, token, max_repos=None)
    print(f"[sync] Total repos en org: {len(all_repos)}")

    # Filtrar por archivo si se proporcionó
    if repos_file:
        filter_names = set(load_repos_from_file(repos_file))
        print(f"[sync] Filtrando por {len(filter_names)} repos del archivo")
        all_repos = [r for r in all_repos if r["name"] in filter_names]
        print(f"[sync] Repos a procesar: {len(all_repos)}")

    # Aplicar límite
    if max_repos:
        all_repos = all_repos[:max_repos]

    if list_only:
        print("\nRepositorios disponibles:")
        for r in all_repos:
            exists = "✓" if (repos_dir / r["name"]).exists() else " "
            print(f"  [{exists}] {r['name']} — {r.get('language','?')} — {r.get('updated_at','')[:10]}")
        return {"repos": [r["name"] for r in all_repos]}

    # Clonar / actualizar
    results   = []
    successes = 0
    failures  = 0

    for i, repo in enumerate(all_repos, 1):
        print(f"[{i}/{len(all_repos)}] {repo['name']}...", end=" ", flush=True)
        result = clone_or_pull(repo, token, repos_dir)
        results.append(result)

        if result["success"]:
            successes += 1
            print(f"✓ {result['action']}")
        else:
            failures += 1
            print(f"✗ {result['stderr'][:80]}")

    # Generar lista de rutas para pasar a Snyk
    cloned_paths = [r["repo_path"] for r in results if r["success"]]

    # Actualizar repos_snyk_batch.txt con las rutas reales
    batch_file = Path("repos_snyk_batch.txt")
    batch_file.write_text(
        "# Generado automáticamente por sync_repos.py\n"
        + "\n".join(cloned_paths)
        + "\n",
        encoding="utf-8",
    )

    summary = {
        "org":          org,
        "total":        len(all_repos),
        "success":      successes,
        "failed":       failures,
        "cloned_paths": cloned_paths,
        "finished_at":  datetime.now(timezone.utc).isoformat(),
    }

    print(f"\n[sync] Completado: {successes} OK, {failures} fallidos")
    print(f"[sync] repos_snyk_batch.txt actualizado con {len(cloned_paths)} rutas")

    return summary


def main():
    parser = argparse.ArgumentParser(description="Clona repos de GitHub org para Snyk")
    parser.add_argument("--repos-file", help="Archivo con nombres/rutas de repos a clonar")
    parser.add_argument("--list-only",  action="store_true", help="Solo listar repos sin clonar")
    parser.add_argument("--max-repos",  type=int, help="Límite de repos a procesar")
    args = parser.parse_args()

    result = sync_repos(
        repos_file=args.repos_file,
        list_only=args.list_only,
        max_repos=args.max_repos,
    )

    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
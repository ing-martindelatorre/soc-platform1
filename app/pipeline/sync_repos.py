"""
app/pipeline/sync_repos.py

Clona o actualiza repositorios de una organización de GitHub
antes de pasarlos al pipeline de Snyk.

El scope lo define GitHub: solo se procesan los repos cuya custom property
`ambiente` vale `produccion`. No se usan listas locales de inclusión/exclusión.

Variables de entorno:
    GITHUB_ORG          Nombre de la organización (ej: uwipes-com)
    GITHUB_ORG_TOKEN    Token con permisos repo/read:org (y lectura de
                        custom properties de la organización)
    SNYK_REPOS_DIR      Directorio donde se clonan los repos
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def _get_required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Falta variable de entorno: {name}")
    return value


def _repos_dir() -> Path:
    path = Path(os.getenv("SNYK_REPOS_DIR", "./data/repos")).resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


# Custom property de GitHub que define el scope de Snyk
SCOPE_PROPERTY = "ambiente"
SCOPE_VALUE    = "produccion"

BATCH_FILE = Path("repos_snyk_batch.txt")


def _github_get(url: str, token: str):
    import urllib.request
    import urllib.error

    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"GitHub API error {e.code}: {e.reason}")


def list_repo_properties(org: str, token: str) -> dict[str, str | None]:
    """
    Devuelve {repo_name: valor de SCOPE_PROPERTY} para todos los repos de la
    org, usando GET /orgs/{org}/properties/values (paginado).
    """
    values: dict[str, str | None] = {}
    page = 1
    while True:
        batch = _github_get(
            f"https://api.github.com/orgs/{org}/properties/values"
            f"?per_page=100&page={page}",
            token,
        )
        if not batch:
            break
        for item in batch:
            value = None
            for prop in item.get("properties") or []:
                if prop.get("property_name") == SCOPE_PROPERTY:
                    value = prop.get("value")
            values[item["repository_name"]] = value
        if len(batch) < 100:
            break
        page += 1
    return values


def list_org_repos(org: str, token: str) -> list[dict]:
    repos    = []
    page     = 1
    per_page = 100

    while True:
        url = (
            f"https://api.github.com/user/repos"
            f"?per_page={per_page}&page={page}&sort=updated"
            f"&affiliation=owner,collaborator,organization_member"
        )
        batch = _github_get(url, token)

        if not batch:
            break

        repos.extend(batch)

        if len(batch) < per_page:
            break

        page += 1

    return repos


def clone_or_pull(repo: dict, token: str, repos_dir: Path) -> dict:
    repo_name  = repo["name"]
    clone_url  = repo["clone_url"]
    repo_path  = repos_dir / repo_name
    auth_url   = clone_url.replace("https://", f"https://{token}@")
    started_at = datetime.now(timezone.utc)

    try:
        if repo_path.exists() and (repo_path / ".git").exists():
            # Refrescar el token del remote: si GITHUB_ORG_TOKEN se rotó, el
            # pull con la URL guardada en el clon falla con 401.
            subprocess.run(
                ["git", "remote", "set-url", "origin", auth_url],
                cwd=str(repo_path),
                capture_output=True, text=True, timeout=30,
            )
            result = subprocess.run(
                ["git", "pull", "--ff-only"],
                cwd=str(repo_path),
                capture_output=True, text=True, timeout=120,
            )
            action = "pulled"
        else:
            result = subprocess.run(
                ["git", "clone", "--depth=1", auth_url, str(repo_path)],
                capture_output=True, text=True, timeout=300,
            )
            action = "cloned"

        success = result.returncode == 0
        return {
            "repo_name":   repo_name,
            "repo_path":   str(repo_path),
            "action":      action,
            "success":     success,
            "returncode":  result.returncode,
            "stderr":      result.stderr.strip()[:500] if not success else "",
            "started_at":  started_at.isoformat(),
            "finished_at": datetime.now(timezone.utc).isoformat(),
        }

    except subprocess.TimeoutExpired:
        return {
            "repo_name": repo_name, "repo_path": str(repo_path),
            "action": "timeout", "success": False, "returncode": -1,
            "stderr": "Timeout al clonar",
            "started_at": started_at.isoformat(),
            "finished_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        return {
            "repo_name": repo_name, "repo_path": str(repo_path),
            "action": "error", "success": False, "returncode": -1,
            "stderr": str(e),
            "started_at": started_at.isoformat(),
            "finished_at": datetime.now(timezone.utc).isoformat(),
        }


def sync_repos(list_only: bool = False) -> dict:
    org       = _get_required("GITHUB_ORG")
    token     = _get_required("GITHUB_ORG_TOKEN")
    repos_dir = _repos_dir()

    print(f"[sync] Org:       {org}")
    print(f"[sync] Repos dir: {repos_dir}")
    print(f"[sync] Scope:     {SCOPE_PROPERTY}={SCOPE_VALUE}")

    print(f"[sync] Leyendo custom properties de {org}...")
    properties = list_repo_properties(org, token)
    in_scope   = {name for name, value in properties.items() if value == SCOPE_VALUE}
    print(f"[sync] Repos con {SCOPE_PROPERTY}={SCOPE_VALUE}: {len(in_scope)} de {len(properties)}")
    if not in_scope:
        # No sobrescribir el batch con una lista vacía
        raise RuntimeError(f"Ningún repo de {org} tiene {SCOPE_PROPERTY}={SCOPE_VALUE}")

    print(f"[sync] Listando repos de {org}...")
    org_repos = list_org_repos(org, token)
    all_repos = [
        r for r in org_repos
        if r["name"] in in_scope
        and (r.get("owner") or {}).get("login", "").lower() == org.lower()
    ]

    # Repos marcados como producción a los que el token no tiene acceso
    missing = sorted(in_scope - {r["name"] for r in all_repos})
    if missing:
        print(f"[sync] AVISO: sin acceso a {len(missing)} repos de producción: {', '.join(missing)}")

    if list_only:
        print("\nRepositorios en producción:")
        for r in all_repos:
            exists = "✓" if (repos_dir / r["name"]).exists() else " "
            print(f"  [{exists}] {r['name']} — {r.get('language','?')} — {r.get('updated_at','')[:10]}")
        return {"repos": [r["name"] for r in all_repos], "missing": missing}

    # ── Clonar / actualizar ──────────────────────────────────────────────────
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

    cloned_paths = [r["repo_path"] for r in results if r["success"]]

    # Actualizar repos_snyk_batch.txt
    BATCH_FILE.write_text(
        f"# Generado automáticamente por sync_repos.py ({SCOPE_PROPERTY}={SCOPE_VALUE})\n"
        + "\n".join(cloned_paths)
        + "\n",
        encoding="utf-8",
    )

    summary = {
        "org":          org,
        "total":        len(all_repos),
        "success":      successes,
        "failed":       failures,
        "missing":      missing,
        "cloned_paths": cloned_paths,
        "finished_at":  datetime.now(timezone.utc).isoformat(),
    }

    print(f"\n[sync] Completado: {successes} OK, {failures} fallidos")
    print(f"[sync] repos_snyk_batch.txt actualizado con {len(cloned_paths)} rutas")

    return summary


def main():
    parser = argparse.ArgumentParser(
        description=f"Clona los repos de GitHub org con {SCOPE_PROPERTY}={SCOPE_VALUE} para Snyk"
    )
    parser.add_argument("--list-only", action="store_true", help="Solo listar repos sin clonar")
    args = parser.parse_args()

    result = sync_repos(list_only=args.list_only)
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()

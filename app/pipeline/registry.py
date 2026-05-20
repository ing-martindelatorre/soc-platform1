"""
app/pipeline/registry.py

Registro central de módulos del SOC.
Todos los módulos deben exponer una clase con método execute(**kwargs)
o una función run_<modulo>_pipeline(**kwargs).
"""
from __future__ import annotations

import logging

logger = logging.getLogger("soc-platform")

# ---------------------------------------------------------------------------
# Sentinel
# ---------------------------------------------------------------------------
try:
    from app.modules.sentinel.service import SentinelPipeline
    _sentinel = SentinelPipeline()
except Exception as e:
    logger.warning(f"[registry] Sentinel no disponible: {e}")
    class _FallbackSentinel:
        name = "sentinel"
        def execute(self, **kwargs):
            return {"ok": False, "module": "sentinel", "error": "no disponible"}
    _sentinel = _FallbackSentinel()

# ---------------------------------------------------------------------------
# Snyk
# ---------------------------------------------------------------------------
try:
    from app.modules.snyk.service import run_snyk_scan_for_repos
    from pathlib import Path

    class _SnykPipeline:
        name = "snyk"
        def execute(self, **kwargs):
            batch_file = kwargs.get("repos_file", "repos_snyk_batch.txt")
            batch_path = Path(batch_file)
            if not batch_path.exists():
                return {"ok": False, "module": "snyk", "error": f"batch file no encontrado: {batch_file}"}
            repo_paths = [
                line.strip() for line in batch_path.read_text().splitlines()
                if line.strip() and not line.startswith("#")
            ]
            if not repo_paths:
                return {"ok": True, "module": "snyk", "message": "No hay repos en el batch file"}
            results = run_snyk_scan_for_repos(repo_paths)
            total   = sum(r.get("findings_count", 0) for r in results)
            failed  = sum(1 for r in results if r.get("status") == "failed_cli_error")
            return {
                "ok":      True,
                "module":  "snyk",
                "message": f"Snyk completado: {len(results)} repos, {total} findings",
                "results": results,
                "total_findings": total,
                "failed": failed,
            }

    _snyk = _SnykPipeline()
except Exception as e:
    logger.warning(f"[registry] Snyk no disponible: {e}")
    class _FallbackSnyk:
        name = "snyk"
        def execute(self, **kwargs):
            return {"ok": False, "module": "snyk", "error": "no disponible"}
    _snyk = _FallbackSnyk()

# ---------------------------------------------------------------------------
# Nmap
# ---------------------------------------------------------------------------
try:
    from app.modules.nmap.service import NmapPipeline
    _nmap = NmapPipeline()
except Exception as e:
    logger.warning(f"[registry] Nmap no disponible: {e}")
    class _FallbackNmap:
        name = "nmap"
        def execute(self, **kwargs):
            return {"ok": False, "module": "nmap", "error": "no disponible"}
    _nmap = _FallbackNmap()

# ---------------------------------------------------------------------------
# Fortinet
# ---------------------------------------------------------------------------
try:
    from app.modules.fortinet.service import run_fortinet_pipeline

    class _FortinetPipeline:
        name = "fortinet"
        def execute(self, **kwargs):
            return run_fortinet_pipeline(**kwargs)

    _fortinet = _FortinetPipeline()
except Exception as e:
    logger.warning(f"[registry] Fortinet no disponible: {e}")
    class _FallbackFortinet:
        name = "fortinet"
        def execute(self, **kwargs):
            return {"ok": False, "module": "fortinet", "error": "no disponible"}
    _fortinet = _FallbackFortinet()

# ---------------------------------------------------------------------------
# Registro central
# ---------------------------------------------------------------------------
MODULES = {
    "sentinel": _sentinel,
    "snyk":     _snyk,
    "nmap":     _nmap,
    "fortinet": _fortinet,
}


def get_module(name: str):
    if name not in MODULES:
        raise ValueError(f"Módulo no registrado: '{name}'. Disponibles: {list(MODULES)}")
    return MODULES[name]

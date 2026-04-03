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
    from app.modules.snyk.service import run_snyk_scan_for_repo

    class _SnykPipeline:
        name = "snyk"
        def execute(self, **kwargs):
            repo_path = kwargs.get("repo_path", "")
            return run_snyk_scan_for_repo(repo_path)

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

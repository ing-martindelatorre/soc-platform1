"""
app/pipeline/runner.py

Runner principal: punto de entrada para ejecutar cualquier módulo del SOC
por nombre. Usado por el scheduler y el CLI.
"""
from __future__ import annotations

import logging
from typing import Any

from app.pipeline.registry import MODULES, get_module

logger = logging.getLogger("soc-platform")


def run_module(name: str, **kwargs) -> dict[str, Any]:
    """
    Ejecuta el pipeline de un módulo por nombre.
    Delega en el registry central.
    """
    module = get_module(name)
    logger.info(f"[runner] Ejecutando módulo: {name}")
    result = module.execute(**kwargs)
    logger.info(f"[runner] Módulo {name} completado: ok={result.get('ok', '?')}")
    return result


# Alias para compatibilidad con código existente
def run_pipeline(name: str, **kwargs) -> dict[str, Any]:
    return run_module(name, **kwargs)


# Funciones individuales para importación directa (compatibilidad)
def run_sentinel_pipeline(**kwargs) -> dict[str, Any]:
    return run_module("sentinel", **kwargs)


def run_snyk_pipeline(**kwargs) -> dict[str, Any]:
    return run_module("snyk", **kwargs)


def run_nmap_pipeline(**kwargs) -> dict[str, Any]:
    return run_module("nmap", **kwargs)


def run_fortinet_pipeline(**kwargs) -> dict[str, Any]:
    return run_module("fortinet", **kwargs)

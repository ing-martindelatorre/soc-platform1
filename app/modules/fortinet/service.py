"""
app/modules/fortinet/service.py

Servicio principal del módulo Fortinet.
Orquesta extract → transform → load para los modos config, logs y threats.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

from app.modules.fortinet.extract import extract
from app.modules.fortinet.transform import transform
from app.modules.fortinet.load import load

logger = logging.getLogger("soc-platform")


def run_fortinet_pipeline(**kwargs) -> Dict[str, Any]:
    mode = kwargs.get("mode", "config")

    logger.info(f"Fortinet pipeline started — mode={mode}")

    raw  = extract(**kwargs)
    data = transform(raw)
    load(data)

    return {
        "ok":      True,
        "module":  "fortinet",
        "mode":    mode,
        "meta":    data.get("meta", {}),
        "summary": data.get("summary", {}),
        "errors":  data.get("errors", []),
    }


def run(**kwargs) -> Dict[str, Any]:
    return run_fortinet_pipeline(**kwargs)

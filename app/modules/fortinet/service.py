from __future__ import annotations

import logging
from typing import Any, Dict

from app.modules.fortinet.extract import extract
from app.modules.fortinet.transform import transform
from app.modules.fortinet.load import load

logger = logging.getLogger("soc-platform")


def run_fortinet_pipeline(**kwargs) -> Dict[str, Any]:
    mode = kwargs.get("mode", "config")

    logger.info("Fortinet pipeline started")
    logger.info(f"Fortinet mode: {mode}")
    logger.info(f"Fortinet kwargs received: {kwargs}")

    raw = extract(**kwargs)
    logger.info("Fortinet extraction completed")

    data = transform(raw)
    logger.info("Fortinet transformation completed")

    load(data)
    logger.info("Fortinet load completed")

    return {
        "ok": True,
        "module": "fortinet",
        "mode": mode,
        "meta": data.get("meta", {}),
        "summary": data.get("summary", {}),
        "errors": data.get("errors", []),
    }


def run(**kwargs) -> Dict[str, Any]:
    return run_fortinet_pipeline(**kwargs)
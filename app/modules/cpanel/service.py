"""
app/modules/cpanel/service.py

Servicio principal del módulo WHM/cPanel.
Orquesta extract → transform → load.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

from app.modules.cpanel.extract import extract
from app.modules.cpanel.transform import transform
from app.modules.cpanel.load import load

logger = logging.getLogger("soc-platform")


def run_cpanel_pipeline(**kwargs) -> Dict[str, Any]:
    mode = kwargs.get("mode", "stats")

    try:
        logger.info(f"cPanel pipeline started — mode={mode}")
        kw   = {k: v for k, v in kwargs.items() if k != "mode"}
        raw  = extract(mode=mode, **kw)
        data = transform(raw)
        load(data)

        summary = data.get("summary", {})
        logger.info(f"cPanel pipeline OK — mode={mode} | {summary}")

        return {
            "ok":      True,
            "module":  "cpanel",
            "mode":    mode,
            "summary": summary,
            "message": f"cPanel {mode}: {summary}",
            "errors":  data.get("errors", []),
        }

    except Exception as exc:
        logger.error(f"cPanel pipeline failed — mode={mode}: {exc}")
        return {
            "ok":     False,
            "module": "cpanel",
            "mode":   mode,
            "error":  str(exc),
        }


def run(**kwargs) -> Dict[str, Any]:
    return run_cpanel_pipeline(**kwargs)

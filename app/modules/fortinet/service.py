"""
app/modules/fortinet/service.py

Servicio principal del módulo Fortinet.
Orquesta extract → transform → load para todos los dispositivos activos
en los modos config, logs y threats.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from app.modules.fortinet.extract import extract, get_active_device_ids
from app.modules.fortinet.transform import transform
from app.modules.fortinet.load import load

logger = logging.getLogger("soc-platform")


def run_fortinet_pipeline(**kwargs) -> Dict[str, Any]:
    mode      = kwargs.get("mode", "config")
    device_id = kwargs.pop("device_id", None)  # None = todos los activos

    device_ids: List[int] = [device_id] if device_id is not None else get_active_device_ids()

    all_results = []
    for did in device_ids:
        try:
            logger.info(f"Fortinet pipeline started — mode={mode}, device_id={did}")
            raw  = extract(device_id=did, **kwargs)
            data = transform(raw)
            load(data)
            all_results.append({
                "device_id":   did,
                "device_name": data.get("device_name", f"fortigate-{did}"),
                "ok":          True,
                "meta":        data.get("meta", {}),
                "summary":     data.get("summary", {}),
                "errors":      data.get("errors", []),
            })
        except Exception as exc:
            logger.error(f"Fortinet pipeline failed — mode={mode}, device_id={did}: {exc}")
            all_results.append({
                "device_id": did,
                "ok":        False,
                "error":     str(exc),
            })

    first = all_results[0] if all_results else {}
    return {
        "ok":      all(r["ok"] for r in all_results),
        "module":  "fortinet",
        "mode":    mode,
        "devices": all_results,
        # Compatibilidad con el formato anterior (primer dispositivo)
        "meta":    first.get("meta", {}),
        "summary": first.get("summary", {}),
        "errors":  first.get("errors", []),
    }


def run(**kwargs) -> Dict[str, Any]:
    return run_fortinet_pipeline(**kwargs)

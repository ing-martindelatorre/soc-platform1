"""
app/modules/fortinet/extract.py

Extractor de datos desde la API REST de FortiGate.
Soporta múltiples dispositivos (FORTI_1_* … FORTI_5_*) y tres modos:
  - config:   snapshots de configuración (políticas, interfaces, objetos, rutas, admins)
  - logs:     logs de tráfico / sistema desde disco del equipo
  - threats:  logs de amenazas en memoria (tráfico, webfilter, sistema, VPN)
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import requests
import urllib3


FORTINET_CONFIG_ENDPOINTS = {
    "system_status":      "/api/v2/monitor/system/status",
    "ha_status":          "/api/v2/monitor/system/ha-status",
    "interfaces":         "/api/v2/cmdb/system/interface",
    "firewall_addresses": "/api/v2/cmdb/firewall/address",
    "firewall_policies":  "/api/v2/cmdb/firewall/policy",
    "router_static":      "/api/v2/cmdb/router/static",
    "system_admins":      "/api/v2/cmdb/system/admin",
}

FORTINET_THREAT_ENDPOINTS = {
    "traffic_forward": "/api/v2/log/memory/traffic/forward",
    "event_system":    "/api/v2/log/memory/event/system",
    "webfilter":       "/api/v2/log/memory/webfilter",
    "event_vpn":       "/api/v2/log/memory/event/vpn",
    "ips":             "/api/v2/log/memory/ips",
    "virus":           "/api/v2/log/memory/virus",
    "virus_disk":      "/api/v2/log/disk/virus",
}

# Número máximo de dispositivos soportados
_MAX_DEVICES = 5


def _get_device_cfg(device_id: int) -> Dict[str, Any]:
    """
    Carga la configuración de un FortiGate desde variables de entorno numeradas.
    Para device_id=1 hace fallback a las vars legadas sin número (FORTI_BASE_URL, etc.)
    """
    prefix = f"FORTI_{device_id}"
    legacy = device_id == 1

    def _env(*keys: str) -> Optional[str]:
        for k in keys:
            v = os.getenv(k)
            if v:
                return v
        return None

    host = _env(
        f"{prefix}_BASE_URL",
        f"{prefix}_HOST",
        *( ("FORTI_BASE_URL", "FORTI_HOST") if legacy else () ),
    )
    token = _env(
        f"{prefix}_API_TOKEN",
        f"{prefix}_TOKEN",
        *( ("FORTI_API_TOKEN", "FORTI_TOKEN") if legacy else () ),
    )
    device_name = _env(
        f"{prefix}_DEVICE_NAME",
        *( ("FORTI_DEVICE_NAME",) if legacy else () ),
    ) or f"fortigate-{device_id}"

    vdom = _env(f"{prefix}_VDOM", "FORTI_VDOM") or "root"

    verify_ssl_raw = _env(f"{prefix}_VERIFY_SSL", "FORTI_VERIFY_SSL") or "true"
    verify_ssl = verify_ssl_raw.strip().lower() in {"1", "true", "yes", "on"}

    timeout = int(_env(f"{prefix}_TIMEOUT", "FORTI_TIMEOUT") or "30")

    return {
        "device_id":   device_id,
        "host":        host.rstrip("/") if host else None,
        "token":       token,
        "device_name": device_name,
        "vdom":        vdom,
        "verify_ssl":  verify_ssl,
        "timeout":     timeout,
    }


def get_active_device_ids() -> List[int]:
    """Retorna los IDs de dispositivos con host y token configurados en el .env."""
    active = []
    for i in range(1, _MAX_DEVICES + 1):
        cfg = _get_device_cfg(i)
        if cfg["host"] and cfg["token"]:
            active.append(i)
    return active if active else [1]


def _build_session_for(cfg: Dict[str, Any]) -> requests.Session:
    if not cfg["verify_ssl"]:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {cfg['token']}",
        "Content-Type": "application/json",
    })
    return session


def fetch(
    path: str,
    cfg: Dict[str, Any],
    extra_params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    params: Dict[str, Any] = {"vdom": cfg["vdom"]}
    if extra_params:
        params.update(extra_params)

    url     = f"{cfg['host']}{path}"
    session = _build_session_for(cfg)

    response = session.get(
        url,
        params=params,
        verify=cfg["verify_ssl"],
        timeout=cfg["timeout"],
    )
    response.raise_for_status()
    return response.json()


def _extract_meta_from_response(result: Dict[str, Any], vdom: str = "root") -> Dict[str, Any]:
    return {
        "serial":      result.get("serial"),
        "version":     result.get("version"),
        "build":       str(result.get("build")) if result.get("build") is not None else None,
        "vdom":        result.get("vdom", vdom),
        "status":      result.get("status"),
        "http_status": result.get("http_status"),
    }


# =============================================================================
# CONFIG
# =============================================================================
def extract_config(device_id: int = 1, **kwargs) -> Dict[str, Any]:
    cfg = _get_device_cfg(device_id)
    if not cfg["host"] or not cfg["token"]:
        raise EnvironmentError(
            f"Dispositivo {device_id}: FORTI_{device_id}_BASE_URL o "
            f"FORTI_{device_id}_API_TOKEN no configurados en .env"
        )

    data: Dict[str, Any] = {
        "mode":        "config",
        "device_name": cfg["device_name"],
        "meta":        {},
        "sections":    {},
        "errors":      [],
    }

    for section_name, path in FORTINET_CONFIG_ENDPOINTS.items():
        try:
            result = fetch(path, cfg)
            data["sections"][section_name] = result

            if not data["meta"]:
                data["meta"] = _extract_meta_from_response(result, cfg["vdom"])

        except Exception as exc:
            error_text = str(exc)

            if section_name == "ha_status" and "404" in error_text:
                data["sections"][section_name] = {
                    "status": "not_supported",
                    "results": [],
                }
                continue

            data["errors"].append({
                "section": section_name,
                "path":    path,
                "error":   error_text,
            })

    return data


# =============================================================================
# LOGS (modo legacy)
# =============================================================================
def _slice_results(payload: Dict[str, Any], limit: int) -> Dict[str, Any]:
    copied  = dict(payload)
    results = copied.get("results", [])
    if isinstance(results, list):
        copied["results"] = results[:limit]
    return copied


def extract_logs(device_id: int = 1, **kwargs) -> Dict[str, Any]:
    cfg = _get_device_cfg(device_id)
    if not cfg["host"] or not cfg["token"]:
        raise EnvironmentError(
            f"Dispositivo {device_id}: FORTI_{device_id}_BASE_URL o "
            f"FORTI_{device_id}_API_TOKEN no configurados en .env"
        )

    endpoint  = kwargs.get("endpoint") or "/api/v2/log/disk/traffic/forward/system"
    limit     = int(kwargs.get("limit") or 100)
    date_from = kwargs.get("date_from")
    date_to   = kwargs.get("date_to")

    data: Dict[str, Any] = {
        "mode":        "logs",
        "device_name": cfg["device_name"],
        "meta": {
            "requested_endpoint": endpoint,
            "requested_limit":    limit,
            "date_from":          date_from,
            "date_to":            date_to,
        },
        "sections": {},
        "errors":   [],
    }

    try:
        result = fetch(endpoint, cfg)
        result = _slice_results(result, limit)

        response_meta = _extract_meta_from_response(result, cfg["vdom"])
        data["meta"].update(response_meta)
        data["sections"]["logs"] = result

    except Exception as exc:
        data["errors"].append({
            "section": "logs",
            "path":    endpoint,
            "error":   str(exc),
        })

    return data


# =============================================================================
# THREATS — logs de amenazas en memoria
# =============================================================================
def extract_threats(device_id: int = 1, **kwargs) -> Dict[str, Any]:
    """
    Extrae logs de amenazas desde la memoria del FortiGate.
    Consulta múltiples endpoints en paralelo y consolida los resultados.

    Parámetros opcionales:
        rows: int   — número de registros por endpoint (default 200)
        endpoints: list — lista de nombres de endpoints a consultar
                          (default: todos los de FORTINET_THREAT_ENDPOINTS)
    """
    cfg = _get_device_cfg(device_id)
    if not cfg["host"] or not cfg["token"]:
        raise EnvironmentError(
            f"Dispositivo {device_id}: FORTI_{device_id}_BASE_URL o "
            f"FORTI_{device_id}_API_TOKEN no configurados en .env"
        )

    rows      = int(kwargs.get("rows", 200))
    endpoints = kwargs.get("endpoints") or list(FORTINET_THREAT_ENDPOINTS.keys())

    data: Dict[str, Any] = {
        "mode":        "threats",
        "device_name": cfg["device_name"],
        "meta":        {},
        "sections":    {},
        "errors":      [],
        "summary":     {},
    }

    total_records = 0

    for name in endpoints:
        path = FORTINET_THREAT_ENDPOINTS.get(name)
        if not path:
            continue

        try:
            result = fetch(path, cfg, extra_params={"rows": rows})

            if not data["meta"]:
                data["meta"] = _extract_meta_from_response(result, cfg["vdom"])

            records = result.get("results", [])
            if not isinstance(records, list):
                records = []

            data["sections"][name] = {
                "endpoint":    path,
                "total_lines": result.get("total_lines", len(records)),
                "completed":   result.get("completed", 100),
                "results":     records,
            }
            total_records += len(records)

        except Exception as exc:
            error_text = str(exc)
            if "404" in error_text:
                data["sections"][name] = {
                    "endpoint":      path,
                    "total_lines":   0,
                    "completed":     100,
                    "results":       [],
                    "not_available": True,
                }
            else:
                data["errors"].append({
                    "section": name,
                    "path":    path,
                    "error":   error_text,
                })

    data["summary"] = {
        "total_records": total_records,
        "endpoints_ok":  len([s for s in data["sections"].values() if not s.get("not_available")]),
        "errors_count":  len(data["errors"]),
    }

    return data


# =============================================================================
# Entry point
# =============================================================================
def extract(device_id: int = 1, **kwargs) -> Dict[str, Any]:
    mode = kwargs.get("mode", "config")
    if mode == "logs":
        return extract_logs(device_id=device_id, **kwargs)
    if mode == "threats":
        return extract_threats(device_id=device_id, **kwargs)
    return extract_config(device_id=device_id, **kwargs)

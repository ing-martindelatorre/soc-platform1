from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import requests
import urllib3


FORTINET_CONFIG_ENDPOINTS = {
    "system_status": "/api/v2/monitor/system/status",
    "ha_status": "/api/v2/monitor/system/ha-status",
    "interfaces": "/api/v2/cmdb/system/interface",
    "firewall_addresses": "/api/v2/cmdb/firewall/address",
    "firewall_policies": "/api/v2/cmdb/firewall/policy",
    "router_static": "/api/v2/cmdb/router/static",
    "system_admins": "/api/v2/cmdb/system/admin",
}


def _bool_env(name: str, default: bool = True) -> bool:
    value = os.getenv(name, str(default)).strip().lower()
    return value in {"1", "true", "yes", "on"}


def _build_session() -> requests.Session:
    verify_ssl = _bool_env("FORTI_VERIFY_SSL", True)
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    token = os.environ["FORTI_TOKEN"]

    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    })
    return session


def fetch(
        path: str,
        extra_params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    host = os.environ["FORTI_HOST"].rstrip("/")
    vdom = os.getenv("FORTI_VDOM", "root")
    verify_ssl = _bool_env("FORTI_VERIFY_SSL", True)
    timeout = int(os.getenv("FORTI_TIMEOUT", "30"))

    params: Dict[str, Any] = {"vdom": vdom}
    if extra_params:
        params.update(extra_params)

    url = f"{host}{path}"
    session = _build_session()

    response = session.get(
        url,
        params=params,
        verify=verify_ssl,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


def _extract_meta_from_response(result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "serial": result.get("serial"),
        "version": result.get("version"),
        "build": str(result.get("build")) if result.get("build") is not None else None,
        "vdom": result.get("vdom", os.getenv("FORTI_VDOM", "root")),
        "status": result.get("status"),
        "http_status": result.get("http_status"),
    }


def extract_config(**kwargs) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "mode": "config",
        "meta": {},
        "sections": {},
        "errors": [],
    }

    for section_name, path in FORTINET_CONFIG_ENDPOINTS.items():
        try:
            result = fetch(path)
            data["sections"][section_name] = result

            if not data["meta"]:
                data["meta"] = _extract_meta_from_response(result)

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
                "path": path,
                "error": error_text,
            })

    return data


def _slice_results(payload: Dict[str, Any], limit: int) -> Dict[str, Any]:
    copied = dict(payload)
    results = copied.get("results", [])

    if isinstance(results, list):
        copied["results"] = results[:limit]

    return copied


def extract_logs(**kwargs) -> Dict[str, Any]:
    endpoint = kwargs.get("endpoint") or "/api/v2/log/disk/traffic/forward/system"
    limit = int(kwargs.get("limit") or 100)
    date_from = kwargs.get("date_from")
    date_to = kwargs.get("date_to")

    data: Dict[str, Any] = {
        "mode": "logs",
        "meta": {
            "requested_endpoint": endpoint,
            "requested_limit": limit,
            "date_from": date_from,
            "date_to": date_to,
        },
        "sections": {},
        "errors": [],
    }

    try:
        result = fetch(endpoint)
        result = _slice_results(result, limit)

        response_meta = _extract_meta_from_response(result)
        data["meta"].update(response_meta)

        data["sections"]["logs"] = result

    except Exception as exc:
        data["errors"].append({
            "section": "logs",
            "path": endpoint,
            "error": str(exc),
        })

    return data


def extract(**kwargs) -> Dict[str, Any]:
    mode = kwargs.get("mode", "config")

    if mode == "logs":
        return extract_logs(**kwargs)

    return extract_config(**kwargs)
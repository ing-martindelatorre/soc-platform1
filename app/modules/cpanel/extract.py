"""
app/modules/cpanel/extract.py

Extractor de datos desde la API JSON de WHM/cPanel.
Modos:
  - stats:    estadísticas del servidor + cola de correo (cada 15 min)
  - security: eventos de fuerza bruta de cPHulk (cada 15 min)
  - accounts: lista de cuentas cPanel (cada hora)
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import requests
import urllib3


def _get_cfg() -> Dict[str, Any]:
    host       = os.getenv("WHM_BASE_URL", "").rstrip("/")
    token      = os.getenv("WHM_API_TOKEN", "")
    verify_raw = os.getenv("WHM_VERIFY_SSL", "true").strip().lower()
    verify_ssl = verify_raw in {"1", "true", "yes", "on"}
    timeout    = int(os.getenv("WHM_TIMEOUT", "30"))
    return {
        "host":       host,
        "token":      token,
        "verify_ssl": verify_ssl,
        "timeout":    timeout,
    }


def _build_session(cfg: Dict[str, Any]) -> requests.Session:
    if not cfg["verify_ssl"]:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    session = requests.Session()
    session.headers.update({
        "Authorization": f"whm root:{cfg['token']}",
        "Accept":        "application/json",
    })
    return session


def _get(
    cfg: Dict[str, Any],
    path: str,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    url     = f"{cfg['host']}{path}"
    session = _build_session(cfg)
    resp    = session.get(
        url,
        params=params or {},
        verify=cfg["verify_ssl"],
        timeout=cfg["timeout"],
    )
    resp.raise_for_status()
    return resp.json()


# =============================================================================
# STATS
# =============================================================================
def extract_stats(**kwargs) -> Dict[str, Any]:
    cfg = _get_cfg()
    if not cfg["host"] or not cfg["token"]:
        raise EnvironmentError("WHM_BASE_URL o WHM_API_TOKEN no configurados en .env")

    data: Dict[str, Any] = {
        "mode":        "stats",
        "server_host": cfg["host"],
        "sections":    {},
        "errors":      [],
    }

    for section, path, params in [
        ("loadavg",   "/json-api/loadavg",   {}),
        ("version",   "/json-api/version",   {"api.version": "1"}),
        ("hostname",  "/json-api/gethostname", {"api.version": "1"}),
        ("bandwidth", "/json-api/showbw",    {"api.version": "1"}),
    ]:
        try:
            data["sections"][section] = _get(cfg, path, params or None)
        except Exception as exc:
            data["errors"].append({"section": section, "error": str(exc)})

    return data


# =============================================================================
# SECURITY — cPHulk
# =============================================================================
def extract_security(**kwargs) -> Dict[str, Any]:
    cfg = _get_cfg()
    if not cfg["host"] or not cfg["token"]:
        raise EnvironmentError("WHM_BASE_URL o WHM_API_TOKEN no configurados en .env")

    data: Dict[str, Any] = {
        "mode":        "security",
        "server_host": cfg["host"],
        "sections":    {},
        "errors":      [],
    }

    # IPs bloqueadas por cPHulk
    cphulk_endpoints: List[Dict[str, Any]] = [
        {
            "name":   "blocked_ips",
            "path":   "/json-api/cpanel",
            "params": {
                "api.version":            "1",
                "cpanel_jsonapi_user":    "root",
                "cpanel_jsonapi_apiversion": "2",
                "cpanel_jsonapi_module":  "cPHulk",
                "cpanel_jsonapi_func":    "list_blocked_ips",
            },
        },
        {
            "name":   "brutes_by_ip",
            "path":   "/json-api/list_cphulk_ip_brute_force_stats",
            "params": {"api.version": "1"},
        },
    ]

    # Cuentas suspendidas (indicador de compromiso o abuso)
    try:
        data["sections"]["suspended"] = _get(cfg, "/json-api/listsuspended", {"api.version": "1"})
    except Exception as exc:
        data["errors"].append({"section": "suspended", "error": str(exc)})

    # Validación de configuración de Exim (detecta manipulación)
    try:
        data["sections"]["exim_check"] = _get(cfg, "/json-api/exim_configuration_check", {"api.version": "1"})
    except Exception as exc:
        data["errors"].append({"section": "exim_check", "error": str(exc)})

    return data


# =============================================================================
# ACCOUNTS
# =============================================================================
def extract_accounts(**kwargs) -> Dict[str, Any]:
    cfg = _get_cfg()
    if not cfg["host"] or not cfg["token"]:
        raise EnvironmentError("WHM_BASE_URL o WHM_API_TOKEN no configurados en .env")

    data: Dict[str, Any] = {
        "mode":        "accounts",
        "server_host": cfg["host"],
        "sections":    {},
        "errors":      [],
    }

    try:
        data["sections"]["accounts"] = _get(cfg, "/json-api/listaccts")
    except Exception as exc:
        data["errors"].append({"section": "accounts", "error": str(exc)})

    try:
        data["sections"]["acctcounts"] = _get(cfg, "/json-api/acctcounts", {"api.version": "1"})
    except Exception as exc:
        data["errors"].append({"section": "acctcounts", "error": str(exc)})

    return data


# =============================================================================
# Entry point
# =============================================================================
def extract(mode: str = "stats", **kwargs) -> Dict[str, Any]:
    if mode == "security":
        return extract_security(**kwargs)
    if mode == "accounts":
        return extract_accounts(**kwargs)
    if mode == "logs":
        from app.modules.cpanel.ssh_extract import extract_logs
        return extract_logs(**kwargs)
    return extract_stats(**kwargs)

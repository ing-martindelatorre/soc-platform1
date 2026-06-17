"""
Consultas a fuentes públicas de reputación de IPs.

Fuentes usadas (sin API key):
  - Shodan InternetDB: hostnames, tags CDN/cloud, CVEs conocidos
  - ipinfo.io:         ASN, nombre de organización, país
"""
from __future__ import annotations

import logging
from ipaddress import ip_address
from typing import Any

import requests

logger = logging.getLogger("soc-platform")

_TIMEOUT = 6
_SESSION = requests.Session()
_SESSION.headers["User-Agent"] = "SOC-Platform-IPIntel/1.0"


def _is_public(ip: str) -> bool:
    try:
        return not ip_address(ip).is_private
    except ValueError:
        return False


def _query_shodan(ip: str) -> dict[str, Any]:
    try:
        r = _SESSION.get(f"https://internetdb.shodan.io/{ip}", timeout=_TIMEOUT)
        if r.status_code == 200:
            d = r.json()
            return {
                "hostnames": d.get("hostnames", []),
                "tags":      d.get("tags", []),
                "vulns":     list(d.get("vulns", {}).keys()) if isinstance(d.get("vulns"), dict) else d.get("vulns", []),
            }
        if r.status_code == 404:
            # IP sin datos en Shodan — normal para muchas IPs legítimas
            return {"hostnames": [], "tags": [], "vulns": []}
    except Exception as exc:
        logger.debug(f"[ip_intel] Shodan error para {ip}: {exc}")
    return {"hostnames": [], "tags": [], "vulns": []}


def _query_ipinfo(ip: str) -> dict[str, Any]:
    try:
        r = _SESSION.get(f"https://ipinfo.io/{ip}/json", timeout=_TIMEOUT)
        if r.status_code == 200:
            d = r.json()
            org = d.get("org", "")
            parts = org.split(" ", 1)
            asn      = parts[0] if parts and parts[0].startswith("AS") else None
            org_name = parts[1] if len(parts) > 1 else org
            return {
                "asn":     asn,
                "org":     org_name,
                "country": d.get("country"),
            }
    except Exception as exc:
        logger.debug(f"[ip_intel] ipinfo error para {ip}: {exc}")
    return {"asn": None, "org": None, "country": None}


def lookup_ip(ip: str) -> dict[str, Any]:
    """
    Consulta Shodan + ipinfo para una IP.
    Para IPs privadas retorna inmediatamente sin hacer peticiones externas.
    """
    if not _is_public(ip):
        return {
            "asn": None, "org": "Red privada", "country": None,
            "hostnames": [], "tags": [], "vulns": [],
            "source": "private",
        }

    shodan = _query_shodan(ip)
    ipinfo = _query_ipinfo(ip)

    return {
        "asn":       ipinfo.get("asn"),
        "org":       ipinfo.get("org"),
        "country":   ipinfo.get("country"),
        "hostnames": shodan.get("hostnames", []),
        "tags":      shodan.get("tags", []),
        "vulns":     shodan.get("vulns", []),
        "source":    "shodan+ipinfo",
    }

"""
app/modules/nmap/kev.py

Catálogo CISA KEV (Known Exploited Vulnerabilities): CVEs con explotación
activa confirmada en el mundo real. Se usa para marcar qué CVEs detectados por
Nmap representan un peligro inmediato.

Se descarga como mucho una vez al día y se cachea en data/cisa_kev.json.
Si la descarga falla se usa la copia en caché (aunque esté vieja); si tampoco
hay caché, se devuelve un catálogo vacío y el pipeline sigue sin marcar KEV.
"""
from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path

import requests

logger = logging.getLogger("soc-platform")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_PATH = Path(__file__).resolve().parents[3] / "data" / "cisa_kev.json"
MAX_AGE_SECONDS = 24 * 3600

# Memo en proceso: (mtime de la caché, catálogo parseado)
_memo: tuple[float, dict[str, dict]] | None = None


def _download() -> None:
    resp = requests.get(KEV_URL, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("Formato KEV inesperado")
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = CACHE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    tmp.replace(CACHE_PATH)


def load_kev() -> dict[str, dict]:
    """Devuelve {CVE-ID: {"date_added", "ransomware", "name"}}."""
    global _memo

    stale = not CACHE_PATH.exists() or (time.time() - CACHE_PATH.stat().st_mtime) > MAX_AGE_SECONDS
    if stale:
        try:
            _download()
        except Exception as exc:
            logger.warning(f"KEV: no se pudo descargar el catálogo CISA ({exc}); se usa la caché si existe")

    if not CACHE_PATH.exists():
        return {}

    mtime = CACHE_PATH.stat().st_mtime
    if _memo is not None and _memo[0] == mtime:
        return _memo[1]

    try:
        data = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning(f"KEV: caché ilegible ({exc})")
        return {}

    catalog = {
        v["cveID"].upper(): {
            "date_added": v.get("dateAdded"),
            "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
            "name": v.get("vulnerabilityName", ""),
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
        }
        for v in data.get("vulnerabilities", [])
        if v.get("cveID")
    }
    _memo = (mtime, catalog)
    return catalog


# Palabras que no identifican un producto (no sirven para cruzar KEV ↔ servicio)
_GENERIC_TOKENS = {
    "server", "servers", "http", "httpd", "https", "service", "services", "web",
    "and", "the", "for", "multiple", "products", "product", "daemon", "client",
}


def _tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", (text or "").lower()) if len(t) >= 3}


def kev_matches_service(entry: dict, service_product: str) -> bool:
    """
    vulners asocia CVEs de avisos de distribución (RHEL/CentOS) que mezclan
    paquetes: p. ej. a "ISC BIND" le lista Shellshock (bash) o Dirty COW
    (kernel). Sólo se considera KEV si el producto de CISA coincide con el
    servicio detectado; si el producto KEV es genérico ("HTTP Server") se
    compara contra el vendor ("Apache").
    """
    svc = _tokens(service_product)
    if not svc:
        return False
    product_tokens = _tokens(entry.get("product", "")) - _GENERIC_TOKENS
    if product_tokens:
        return bool(product_tokens & svc)
    return bool(_tokens(entry.get("vendor", "")) & svc)


def annotate_kev(vulnerabilities: list[dict]) -> None:
    """
    Agrega in_kev / kev_ransomware a cada vulnerabilidad (in-place).
    Las confirmadas por un script NSE no necesitan cruce de producto.
    """
    kev = load_kev() if vulnerabilities else {}
    for v in vulnerabilities:
        entry = kev.get(v.get("vuln_id", "").upper())
        if entry and v.get("detection") == "version" and not kev_matches_service(entry, v.get("product", "")):
            entry = None
        v["in_kev"] = entry is not None
        v["kev_ransomware"] = bool(entry and entry["ransomware"])

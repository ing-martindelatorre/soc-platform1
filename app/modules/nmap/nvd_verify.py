"""
app/modules/nmap/nvd_verify.py

Verifica contra NVD (rangos de versión afectados) los CVEs "por versión" que
salieron en el catálogo KEV, para no reportar como prioridad un falso positivo
de vulners. Caso real: vulners compara "Exim 4.100" como texto y lo trata como
anterior a 4.90.1, listando CVE-2018-6789 (sólo afecta < 4.90.1).

Sólo se consultan los CVEs KEV (pocos) y las respuestas se cachean 30 días en
data/nvd_cve_cache.json. La API pública de NVD sin API key admite ~5
peticiones / 30 s, por eso se espera entre peticiones no cacheadas.

Resultado por CVE:
  True  → la versión del servicio está en un rango afectado
  False → NVD lista el producto pero la versión NO está afectada (falso positivo)
  None  → no se pudo determinar (sin CPE, NVD no lista el producto, error de red)
"""
from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger("soc-platform")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_PATH = Path(__file__).resolve().parents[3] / "data" / "nvd_cve_cache.json"
CACHE_TTL_SECONDS = 30 * 24 * 3600
REQUEST_INTERVAL_SECONDS = 6.5
MAX_LOOKUPS_PER_RUN = 60


def _version_key(version: str) -> tuple:
    """Clave comparable: '4.100' > '4.90.1', '9.11.4-P2' > '9.11.4'."""
    parts = re.findall(r"\d+|[a-zA-Z]+", version or "")
    return tuple((0, int(p)) if p.isdigit() else (1, p.lower()) for p in parts)


def _parse_cpe(cpe: str) -> tuple[str, str, str] | None:
    """cpe:/a:exim:exim:4.100 o cpe:2.3:a:exim:exim:4.100:... → (vendor, product, version)."""
    if not cpe:
        return None
    body = cpe[len("cpe:2.3:"):] if cpe.startswith("cpe:2.3:") else cpe[len("cpe:/"):] if cpe.startswith("cpe:/") else ""
    fields = body.split(":")
    if len(fields) < 3:
        return None
    vendor, product = fields[1].lower(), fields[2].lower()
    version = fields[3] if len(fields) > 3 else ""
    return vendor, product, version


def _in_range(version: str, m: dict[str, Any], criteria_version: str) -> bool:
    v = _version_key(version)
    if criteria_version not in ("*", "-", ""):
        return v == _version_key(criteria_version)
    checks = (
        ("versionStartIncluding", lambda b: v >= b),
        ("versionStartExcluding", lambda b: v > b),
        ("versionEndIncluding",   lambda b: v <= b),
        ("versionEndExcluding",   lambda b: v < b),
    )
    has_bound = False
    for key, fn in checks:
        if m.get(key):
            has_bound = True
            if not fn(_version_key(m[key])):
                return False
    # "*" sin límites = todas las versiones
    return True if has_bound or criteria_version == "*" else False


def _load_cache() -> dict[str, Any]:
    try:
        return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_cache(cache: dict[str, Any]) -> None:
    try:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = CACHE_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(cache), encoding="utf-8")
        tmp.replace(CACHE_PATH)
    except Exception as exc:
        logger.warning(f"NVD: no se pudo guardar la caché ({exc})")


def _fetch_matches(cve_id: str) -> list[dict[str, Any]] | None:
    resp = requests.get(NVD_URL, params={"cveId": cve_id}, timeout=30)
    resp.raise_for_status()
    vulns = resp.json().get("vulnerabilities", [])
    if not vulns:
        return []
    matches = []
    for conf in vulns[0].get("cve", {}).get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable"):
                    matches.append({k: m[k] for k in (
                        "criteria", "versionStartIncluding", "versionStartExcluding",
                        "versionEndIncluding", "versionEndExcluding") if k in m})
    return matches


def check_affected(matches: list[dict[str, Any]], cpe: str) -> bool | None:
    parsed = _parse_cpe(cpe)
    if not parsed or not parsed[2]:
        return None
    vendor, product, version = parsed
    seen_product = False
    for m in matches:
        crit = _parse_cpe(m.get("criteria", ""))
        if not crit or (crit[0], crit[1]) != (vendor, product):
            continue
        seen_product = True
        if _in_range(version, m, crit[2]):
            return True
    return False if seen_product else None


def verify_kev_versions(vulnerabilities: list[dict[str, Any]]) -> None:
    """
    In-place: para cada CVE KEV detectado "por versión" agrega nvd_affected
    (True/False/None). Si NVD confirma que la versión no está afectada se
    quita la marca KEV y se marca nvd_affected=False para descartarlo.
    """
    targets = [v for v in vulnerabilities if v.get("in_kev") and v.get("detection") == "version"]
    if not targets:
        return

    cache = _load_cache()
    now = time.time()
    lookups = 0
    last_request = 0.0

    for v in targets:
        cve = v["vuln_id"]
        entry = cache.get(cve)
        if entry is None or now - entry.get("ts", 0) > CACHE_TTL_SECONDS:
            if lookups >= MAX_LOOKUPS_PER_RUN:
                v["nvd_affected"] = None
                continue
            wait = REQUEST_INTERVAL_SECONDS - (time.time() - last_request)
            if wait > 0 and last_request:
                time.sleep(wait)
            try:
                last_request = time.time()
                lookups += 1
                entry = {"ts": now, "matches": _fetch_matches(cve)}
                cache[cve] = entry
            except Exception as exc:
                logger.warning(f"NVD: no se pudo consultar {cve} ({exc})")
                v["nvd_affected"] = None
                continue

        affected = check_affected(entry["matches"], v.get("cpe", ""))
        v["nvd_affected"] = affected
        if affected is False:
            v["in_kev"] = False
            v["kev_ransomware"] = False

    if lookups:
        _save_cache(cache)

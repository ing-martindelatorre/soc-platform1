"""
app/modules/nmap/cve_extract.py

Extrae vulnerabilidades reales (con CVE o confirmadas por un script NSE) de la
salida estructurada de los scripts de Nmap, separándolas de los hallazgos de
simple exposición de puertos.

Dos fuentes, con distinto nivel de certeza (columna `detection`):

- "confirmed" / "likely": scripts de la librería vulns de NSE
  (http-slowloris-check, ssl-dh-params, smb-vuln-ms17-010, …) que probaron
  activamente el fallo y reportan State: VULNERABLE / LIKELY VULNERABLE.
- "version": script `vulners`, que sólo cruza producto+versión (CPE) del
  banner contra la base de vulners.com. NO prueba nada: puede dar falsos
  positivos por parches backporteados (RHEL/CentOS) o por comparaciones de
  versión erróneas (p. ej. Exim 4.100 tratado como anterior a 4.92).
"""
from __future__ import annotations

import re
from typing import Any

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# Estados de la librería vulns de NSE que cuentan como vulnerable.
_CONFIRMED_STATES = ("VULNERABLE", "VULNERABLE (DOS)", "VULNERABLE (EXPLOITABLE)")
_LIKELY_STATES = ("LIKELY VULNERABLE",)


def cvss_to_severity(cvss: float | None) -> str:
    if cvss is None:
        return "medium"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def _elems(table: dict[str, Any]) -> dict[str, str]:
    return {e.get("key", ""): (e.get("text") or "").strip() for e in table.get("elements", []) if e.get("key")}


def _to_float(value: str | None) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except ValueError:
        return None


def _from_vulners(script: dict[str, Any]) -> list[dict[str, Any]]:
    """Cada <table key="cpe:..."> contiene una <table> por referencia (CVE, exploit, CNVD…)."""
    best: dict[str, dict[str, Any]] = {}
    for cpe_table in script.get("tables", []):
        cpe = cpe_table.get("key", "")
        for ref in cpe_table.get("tables", []):
            e = _elems(ref)
            if e.get("type", "").lower() != "cve":
                continue
            vuln_id = e.get("id", "").upper()
            if not CVE_RE.fullmatch(vuln_id):
                continue
            cvss = _to_float(e.get("cvss"))
            has_exploit = e.get("is_exploit", "").lower() == "true"
            prev = best.get(vuln_id)
            if prev is None or (cvss or 0) > (prev["cvss"] or 0):
                best[vuln_id] = {
                    "vuln_id": vuln_id,
                    "is_cve": True,
                    "cvss": cvss,
                    "severity": cvss_to_severity(cvss),
                    "detection": "version",
                    "has_exploit": has_exploit or bool(prev and prev["has_exploit"]),
                    "title": vuln_id,
                    "cpe": cpe,
                    "reference_url": f"https://vulners.com/cve/{vuln_id}",
                }
            elif has_exploit:
                prev["has_exploit"] = True
    return list(best.values())


def _from_vulns_library(script: dict[str, Any]) -> list[dict[str, Any]]:
    """Tablas de la librería vulns: key = id (CVE-… o NMAP-n), elems title/state, tabla ids/refs."""
    out: list[dict[str, Any]] = []
    for table in script.get("tables", []):
        e = _elems(table)
        state = e.get("state", "").upper()
        if state in _CONFIRMED_STATES or state.startswith("VULNERABLE"):
            detection, severity = "confirmed", "high"
        elif state in _LIKELY_STATES:
            detection, severity = "likely", "medium"
        else:
            continue

        sub = {t.get("key", ""): t for t in table.get("tables", [])}
        ids_text = " ".join(x.get("text", "") for x in sub.get("ids", {}).get("elements", []))
        cves = sorted({c.upper() for c in CVE_RE.findall(f"{table.get('key', '')} {ids_text}")})
        refs = [x.get("text", "") for x in sub.get("refs", {}).get("elements", []) if x.get("text")]
        cvss = _to_float(e.get("cvss"))
        if cvss is not None:
            severity = cvss_to_severity(cvss)

        base = {
            "is_cve": bool(cves),
            "cvss": cvss,
            "severity": severity,
            "detection": detection,
            "has_exploit": False,
            "title": e.get("title") or script.get("id", ""),
            "cpe": "",
            "reference_url": refs[0] if refs else "",
        }
        if cves:
            out.extend({**base, "vuln_id": c} for c in cves)
        else:
            # Vulnerabilidad confirmada sin CVE asignado (ej. NMAP-46 ssl-dh-params)
            out.append({**base, "vuln_id": f"{script.get('id', '')}:{table.get('key') or e.get('title', '')}"[:100]})
    return out


def extract_vulnerabilities(script: dict[str, Any]) -> list[dict[str, Any]]:
    """Devuelve las vulnerabilidades encontradas en un script NSE (lista vacía si ninguna)."""
    script_id = script.get("id", "")
    if script_id == "vulners":
        vulns = _from_vulners(script)
    else:
        vulns = _from_vulns_library(script)
    for v in vulns:
        v["script_name"] = script_id
    return vulns


# Salidas NSE que no aportan nada: el script corrió y no encontró nada, o falló.
_NEGATIVE_MARKERS = (
    "not vulnerable",
    "couldn't find",
    "script execution failed",
    "no reply from server",
)


def is_negative_nse_output(script: dict[str, Any]) -> bool:
    """True si la salida del script es un resultado negativo/vacío que no debe ser hallazgo."""
    output = (script.get("output") or "").strip().lower()
    if not output:
        return True
    # La salida de vulners es enorme y queda en nmap_vulnerabilities
    if script.get("id") == "vulners":
        return True
    has_vulnerable_state = any(
        _elems(t).get("state", "").upper().startswith(("VULNERABLE", "LIKELY VULNERABLE"))
        for t in script.get("tables", [])
    )
    if has_vulnerable_state:
        return False
    return output == "false" or any(marker in output for marker in _NEGATIVE_MARKERS)


_SCRIPT_CVE_RE = re.compile(r"cve(\d{4})-(\d{4,})", re.IGNORECASE)


def refuted_cves(scripts: list[dict[str, Any]]) -> set[str]:
    """
    CVEs que un script específico (smtp-vuln-cve2010-4344, http-vuln-cve2017-5638…)
    probó y reportó NOT VULNERABLE. Sirven para descartar el mismo CVE cuando
    vulners lo lista sólo por versión (vulners compara mal versiones como
    Exim 4.100 < 4.92).
    """
    out: set[str] = set()
    for script in scripts:
        m = _SCRIPT_CVE_RE.search(script.get("id", ""))
        if m and "not vulnerable" in (script.get("output") or "").lower():
            out.add(f"CVE-{m.group(1)}-{m.group(2)}")
    return out

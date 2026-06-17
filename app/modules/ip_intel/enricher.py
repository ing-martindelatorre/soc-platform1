"""
Enriquecedor de registros de tráfico con inteligencia de reputación de IPs.

Flujo por registro:
  1. Busca la IP destino en caché local (ip_reputation_cache, TTL 7 días)
  2. Si no está en caché, consulta Shodan InternetDB + ipinfo.io
  3. Evalúa si la IP pertenece a una organización de confianza (trusted_orgs)
  4. Marca el registro:
       - "known_service"  → IP de org legítima (Google, Dropbox, Akamai, etc.)
       - "suspicious"     → se mantiene o se eleva si la IP tiene CVEs conocidos
       - "normal"/"blocked" → sin cambios
  5. Agrega campos intel_org, intel_verdict, intel_vulns al registro
  6. Con filter_known=True (defecto), filtra los known_service del resultado
     para que el dashboard solo muestre tráfico verdaderamente sospechoso.
"""
from __future__ import annotations

import logging
from collections import Counter
from typing import Any

from .cache import ensure_table, get_cached, save_cache
from .lookup import lookup_ip
from .trusted_orgs import is_trusted

logger = logging.getLogger("soc-platform")


def _resolve_ip(ip: str) -> dict[str, Any]:
    """Retorna datos de reputación para una IP, usando caché persistente."""
    cached = get_cached(ip)
    if cached:
        return cached

    raw = lookup_ip(ip)
    trusted, reason = is_trusted(
        asn=raw.get("asn"),
        org=raw.get("org"),
        hostnames=raw.get("hostnames", []),
        tags=raw.get("tags", []),
    )

    data = {**raw, "is_trusted": trusted, "trust_reason": reason}
    save_cache(ip, data)
    return data


def enrich_traffic_records(
    records: list[dict[str, Any]],
    filter_known: bool = True,
) -> list[dict[str, Any]]:
    """
    Enriquece y filtra registros de tráfico de red.

    Parámetros:
      records      Lista de registros con al menos los campos: dstip, classification
      filter_known Si True (defecto), elimina del resultado los registros cuya
                   IP destino pertenece a una organización de confianza conocida.

    Retorna la lista de registros enriquecidos (y filtrados si filter_known=True).
    Cada registro recibe tres campos adicionales:
      intel_org     Nombre de la organización dueña de la IP
      intel_verdict "trusted" | "unknown"
      intel_vulns   Número de CVEs conocidos en Shodan
    """
    if not records:
        return []

    ensure_table()

    # Resolver IPs únicas para minimizar consultas externas
    unique_ips = {r["dstip"] for r in records if r.get("dstip")}
    logger.info(f"[ip_intel] Resolviendo reputación de {len(unique_ips)} IPs únicas")

    ip_data: dict[str, dict[str, Any]] = {}
    for ip in unique_ips:
        ip_data[ip] = _resolve_ip(ip)

    enriched: list[dict[str, Any]] = []
    for rec in records:
        dstip = rec.get("dstip", "")
        intel = ip_data.get(dstip, {})
        trusted   = bool(intel.get("is_trusted"))
        vulns     = intel.get("vulns") or []
        org_label = intel.get("trust_reason") or intel.get("org") or ""

        r = {**rec}
        r["intel_org"]     = org_label
        r["intel_verdict"] = "trusted" if trusted else "unknown"
        r["intel_vulns"]   = len(vulns)

        cls = r.get("classification", "normal")

        if trusted and cls in ("suspicious", "normal"):
            # IP de infraestructura legítima → no es una amenaza
            r["classification"] = "known_service"
        elif vulns and cls == "normal":
            # IP desconocida con CVEs activos → escalar a sospechoso
            r["classification"] = "suspicious"
            r["intel_verdict"]  = "risky"

        enriched.append(r)

    if filter_known:
        before = len(enriched)
        enriched = [r for r in enriched if r["classification"] != "known_service"]
        discarded = before - len(enriched)
        logger.info(
            f"[ip_intel] {discarded} registros descartados (infraestructura conocida), "
            f"{len(enriched)} permanecen"
        )

    return enriched


def summarize_enriched(records: list[dict[str, Any]]) -> dict[str, int]:
    """Calcula conteos de clasificación desde registros ya enriquecidos."""
    c = Counter(r.get("classification", "normal") for r in records)
    return {
        "suspicious":   c.get("suspicious", 0),
        "blocked":      c.get("blocked", 0),
        "normal":       c.get("normal", 0),
        "known_service": c.get("known_service", 0),
    }

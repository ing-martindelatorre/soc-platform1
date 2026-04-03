"""
app/modules/nmap/service.py

Punto de entrada unificado para el módulo Nmap.
Orquesta el pipeline completo: scan → parse → enrich → load a PostgreSQL.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

from app.modules.nmap.pipeline_nmap import (
    load_nmap_targets,
    run_nmap_for_target,
    ensure_output_dir,
)
from app.modules.nmap.parse_nmap_xml import parse_xml
from app.modules.nmap.enrich_nmap_findings import enrich
from app.modules.nmap.load import load_to_db

logger = logging.getLogger("soc-platform")


class NmapPipeline:
    """
    Clase compatible con el registry de pipelines.
    Expone el método execute(**kwargs) como interfaz estándar.
    """

    name = "nmap"

    def execute(self, **kwargs) -> dict[str, Any]:
        return run_nmap_pipeline(**kwargs)


def run_nmap_pipeline(targets_file: str | Path | None = None, **kwargs) -> dict[str, Any]:
    """
    Pipeline completo de Nmap:
      1. Carga targets desde archivo
      2. Ejecuta nmap por cada target → XML
      3. Parsea XML a estructura normalizada
      4. Enriquece con hallazgos (severity, categoría, recomendaciones)
      5. Carga a PostgreSQL (nmap_assets, nmap_services, nmap_findings)
      6. Guarda resumen JSON en disco

    Retorna un dict con el resumen de la ejecución.
    """
    targets = load_nmap_targets(targets_file)

    if not targets:
        logger.info("Nmap: no hay targets habilitados")
        return {
            "ok": True,
            "message": "No hay targets habilitados para Nmap",
            "scanned": 0,
            "results": [],
        }

    output_dir = ensure_output_dir()
    results: list[dict] = []
    failures: list[dict] = []

    for item in targets:
        name    = item["name"]
        target  = item["target"]
        profile = item["profile"]

        logger.info(f"Nmap: iniciando scan para {name} ({target}) perfil={profile}")

        try:
            # 1. Ejecutar nmap → XML
            scan_result = run_nmap_for_target(
                target=target,
                profile_name=profile,
                asset_name=name,
            )

            xml_path = Path(scan_result["xml_path"])

            # 2. Parsear XML
            parsed = parse_xml(xml_path)

            # 3. Enriquecer hallazgos
            enriched = enrich(parsed)

            # 4. Cargar a PostgreSQL
            load_to_db(enriched)

            # 5. Guardar JSON enriquecido en disco (para auditoría / debug)
            ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
            enriched_path = output_dir / f"{name}_{ts}_enriched.json"
            enriched_path.write_text(
                json.dumps(enriched, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

            results.append({
                "name":          name,
                "target":        target,
                "profile":       profile,
                "status":        "success",
                "assets_found":  enriched["summary"]["total_assets"],
                "findings_found": enriched["summary"]["total_findings"],
                "xml_path":      str(xml_path),
                "enriched_path": str(enriched_path),
            })

            logger.info(
                f"Nmap OK: {name} | assets={enriched['summary']['total_assets']} "
                f"findings={enriched['summary']['total_findings']}"
            )

        except Exception as exc:
            logger.error(f"Nmap ERROR para {name} ({target}): {exc}", exc_info=True)
            failures.append({
                "name":    name,
                "target":  target,
                "profile": profile,
                "status":  "failed",
                "error":   str(exc),
            })

    payload = {
        "ok":          len(failures) == 0,
        "message":     "Nmap batch finalizado",
        "scanned":     len(targets),
        "success":     len(results),
        "failed":      len(failures),
        "results":     results,
        "failures":    failures,
        "finished_at": datetime.now(UTC).isoformat(),
    }

    # Guardar resumen general
    summary_path = output_dir / "nmap_batch_last_summary.json"
    summary_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    logger.info(
        f"Nmap batch: {len(results)} OK, {len(failures)} fallidos "
        f"de {len(targets)} targets"
    )

    return payload

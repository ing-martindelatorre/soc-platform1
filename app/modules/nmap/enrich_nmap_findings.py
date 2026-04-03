# app/modules/nmap/enrich_nmap_findings.py

import argparse
import json
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

from app.modules.nmap.service_mapper import (
    build_service_tags,
    classify_service,
    maybe_flag_legacy_version,
    normalize_service_name,
    port_risk,
)


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def build_finding(
        asset_ip: str,
        hostname: str,
        port: int,
        protocol: str,
        service_name: str,
        severity: str,
        title: str,
        description: str,
        recommendation: str,
        category: str,
        evidence: dict[str, Any] | None = None,
        source: str = "nmap",
        script_name: str = "",
) -> dict[str, Any]:
    return {
        "asset_ip": asset_ip,
        "hostname": hostname,
        "port": port,
        "protocol": protocol,
        "service_name": normalize_service_name(service_name),
        "severity": severity,
        "title": title,
        "description": description,
        "recommendation": recommendation,
        "category": category,
        "evidence": evidence or {},
        "source": source,
        "script_name": script_name,
        "first_seen": utc_now(),
        "last_seen": utc_now(),
        "status": "open",
    }


def enrich(parsed_data: dict[str, Any]) -> dict[str, Any]:
    assets = []
    findings = []

    for host in parsed_data.get("hosts", []):
        addresses = host.get("addresses", {})
        ip = addresses.get("ipv4") or addresses.get("ipv6") or "unknown"
        hostnames = host.get("hostnames", [])
        hostname = hostnames[0] if hostnames else ""

        os_guess = host.get("os", {}).get("best_guess", {}).get("name", "")

        asset = {
            "ip": ip,
            "hostname": hostname,
            "mac": addresses.get("mac", ""),
            "os_guess": os_guess,
            "status": host.get("status", ""),
            "services": [],
        }

        for port_data in host.get("ports", []):
            if port_data.get("state") != "open":
                continue

            port = port_data.get("port", 0)
            protocol = port_data.get("protocol", "")
            service_name = port_data.get("service_name", "")
            product = port_data.get("product", "")
            version = port_data.get("version", "")
            extrainfo = port_data.get("extrainfo", "")
            scripts = port_data.get("scripts", [])

            tags = build_service_tags(
                port=port,
                service_name=service_name,
                product=product,
                version=version,
            )

            asset["services"].append({
                "port": port,
                "protocol": protocol,
                "service_name": normalize_service_name(service_name),
                "product": product,
                "version": version,
                "extrainfo": extrainfo,
                "tags": tags,
                "scripts": scripts,
            })

            pr = port_risk(port)
            if pr:
                sev, desc = pr
                findings.append(build_finding(
                    asset_ip=ip,
                    hostname=hostname,
                    port=port,
                    protocol=protocol,
                    service_name=service_name,
                    severity=sev,
                    title=f"Puerto sensible detectado: {port}/{protocol}",
                    description=desc,
                    recommendation="Validar necesidad del servicio, segmentación de red, ACLs y endurecimiento.",
                    category="exposure",
                    evidence={
                        "product": product,
                        "version": version,
                        "extrainfo": extrainfo,
                    },
                ))

            sr = classify_service(service_name)
            if sr:
                sev, desc = sr
                findings.append(build_finding(
                    asset_ip=ip,
                    hostname=hostname,
                    port=port,
                    protocol=protocol,
                    service_name=service_name,
                    severity=sev,
                    title=f"Servicio sensible detectado: {normalize_service_name(service_name)}",
                    description=desc,
                    recommendation="Revisar exposición, autenticación, cifrado, endurecimiento y necesidad operativa.",
                    category="service-risk",
                    evidence={
                        "product": product,
                        "version": version,
                        "extrainfo": extrainfo,
                    },
                ))

            legacy = maybe_flag_legacy_version(service_name, product, version)
            if legacy:
                findings.append(build_finding(
                    asset_ip=ip,
                    hostname=hostname,
                    port=port,
                    protocol=protocol,
                    service_name=service_name,
                    severity=legacy["severity"],
                    title=legacy["title"],
                    description=legacy["description"],
                    recommendation=legacy["recommendation"],
                    category=legacy["category"],
                    evidence={
                        "product": product,
                        "version": version,
                        "extrainfo": extrainfo,
                    },
                ))

            for script in scripts:
                script_id = script.get("id", "")
                output = script.get("output", "")

                if not output:
                    continue

                sev = "medium" if "vuln" in script_id.lower() else "info"
                if any(word in output.lower() for word in ["vulnerable", "critical", "high", "exploitable"]):
                    sev = "high"

                findings.append(build_finding(
                    asset_ip=ip,
                    hostname=hostname,
                    port=port,
                    protocol=protocol,
                    service_name=service_name,
                    severity=sev,
                    title=f"Resultado NSE: {script_id}",
                    description=output[:1200],
                    recommendation="Revisar salida NSE y validar manualmente impacto real.",
                    category="nse-script",
                    evidence={
                        "script_output": output,
                        "script_elements": script.get("elements", []),
                        "product": product,
                        "version": version,
                    },
                    script_name=script_id,
                ))

        assets.append(asset)

    return {
        "generated_at": utc_now(),
        "summary": {
            "total_assets": len(assets),
            "total_findings": len(findings),
        },
        "assets": assets,
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Enriquece JSON parseado de Nmap y genera hallazgos.")
    parser.add_argument("--infile", required=True, help="JSON parseado por parse_nmap_xml.py")
    parser.add_argument("--out", required=True, help="JSON enriquecido de salida")
    args = parser.parse_args()

    in_path = Path(args.infile)
    out_path = Path(args.out)

    parsed_data = json.loads(in_path.read_text(encoding="utf-8"))
    enriched = enrich(parsed_data)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(enriched, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[OK] Hallazgos enriquecidos guardados en: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
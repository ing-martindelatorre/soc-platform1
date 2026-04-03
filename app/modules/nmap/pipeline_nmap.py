from __future__ import annotations

import json
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from app.modules.nmap.profiles import get_profile_args

BASE_DIR = Path(__file__).resolve().parents[3]
DEFAULT_TARGETS_FILE = BASE_DIR / "targets_nmap_batch.txt"
DEFAULT_OUTPUT_DIR = BASE_DIR / "data" / "nmap_scans"


def load_nmap_targets(file_path: str | Path | None = None) -> list[dict]:
    path = Path(file_path) if file_path else DEFAULT_TARGETS_FILE

    if not path.exists():
        raise FileNotFoundError(f"No existe el archivo de targets Nmap: {path}")

    targets: list[dict] = []

    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        parts = [part.strip() for part in line.split("|")]

        if len(parts) != 4:
            print(f"[WARN] Línea inválida en {path}:{line_number} -> {line}")
            continue

        name, target, profile, enabled = parts
        enabled_bool = enabled.lower() in {"true", "1", "yes", "si"}

        if not enabled_bool:
            continue

        targets.append(
            {
                "name": name,
                "target": target,
                "profile": profile,
            }
        )

    return targets


def ensure_output_dir() -> Path:
    DEFAULT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    return DEFAULT_OUTPUT_DIR


def sanitize_filename(value: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in value)
    return safe.strip("_") or "target"


def run_nmap_for_target(target: str, profile_name: str, asset_name: str) -> dict:
    output_dir = ensure_output_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = sanitize_filename(asset_name)
    xml_path = output_dir / f"{safe_name}_{timestamp}.xml"

    args = ["nmap", *get_profile_args(profile_name), "-oX", str(xml_path), target]

    started_at = datetime.now()
    print(f"[INFO] Ejecutando Nmap para {asset_name} ({target}) con perfil {profile_name}")
    print(f"[DEBUG] Comando: {' '.join(args)}")

    process = subprocess.run(
        args,
        capture_output=True,
        text=True,
        check=False,
    )

    finished_at = datetime.now()

    if process.returncode != 0:
        raise RuntimeError(
            f"Nmap falló para {asset_name} ({target}). "
            f"returncode={process.returncode} stderr={process.stderr.strip()}"
        )

    summary = parse_nmap_xml(xml_path)
    summary["asset_name"] = asset_name
    summary["target"] = target
    summary["profile"] = profile_name
    summary["xml_path"] = str(xml_path)
    summary["started_at"] = started_at.isoformat()
    summary["finished_at"] = finished_at.isoformat()
    summary["stdout"] = process.stdout.strip()

    return summary


def parse_nmap_xml(xml_path: str | Path) -> dict:
    xml_file = Path(xml_path)
    if not xml_file.exists():
        raise FileNotFoundError(f"No existe el XML de salida de Nmap: {xml_file}")

    tree = ET.parse(xml_file)
    root = tree.getroot()

    hosts_summary: list[dict] = []
    total_hosts = 0
    total_up = 0
    total_open_ports = 0

    for host in root.findall("host"):
        total_hosts += 1

        status_el = host.find("status")
        status = status_el.get("state") if status_el is not None else "unknown"
        if status == "up":
            total_up += 1

        address_el = host.find("address")
        address = address_el.get("addr") if address_el is not None else "unknown"

        hostnames = []
        hostnames_el = host.find("hostnames")
        if hostnames_el is not None:
            for hostname_el in hostnames_el.findall("hostname"):
                hostname_name = hostname_el.get("name")
                if hostname_name:
                    hostnames.append(hostname_name)

        ports: list[dict] = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                port_id = port_el.get("portid", "")
                protocol = port_el.get("protocol", "")
                state_el = port_el.find("state")
                service_el = port_el.find("service")

                state = state_el.get("state") if state_el is not None else "unknown"
                service_name = service_el.get("name") if service_el is not None else None
                product = service_el.get("product") if service_el is not None else None
                version = service_el.get("version") if service_el is not None else None

                if state == "open":
                    total_open_ports += 1

                ports.append(
                    {
                        "port": port_id,
                        "protocol": protocol,
                        "state": state,
                        "service": service_name,
                        "product": product,
                        "version": version,
                    }
                )

        os_matches: list[str] = []
        os_el = host.find("os")
        if os_el is not None:
            for osmatch in os_el.findall("osmatch"):
                name = osmatch.get("name")
                if name:
                    os_matches.append(name)

        hosts_summary.append(
            {
                "address": address,
                "status": status,
                "hostnames": hostnames,
                "ports": ports,
                "os_matches": os_matches,
            }
        )

    return {
        "total_hosts": total_hosts,
        "total_up": total_up,
        "total_open_ports": total_open_ports,
        "hosts": hosts_summary,
    }


def run_nmap_pipeline(targets_file: str | Path | None = None) -> dict:
    targets = load_nmap_targets(targets_file)

    if not targets:
        return {
            "ok": True,
            "message": "No hay targets habilitados para Nmap",
            "scanned": 0,
            "results": [],
        }

    results: list[dict] = []
    failures: list[dict] = []

    for item in targets:
        name = item["name"]
        target = item["target"]
        profile = item["profile"]

        try:
            result = run_nmap_for_target(
                target=target,
                profile_name=profile,
                asset_name=name,
            )
            results.append(
                {
                    "name": name,
                    "target": target,
                    "profile": profile,
                    "status": "success",
                    "summary": result,
                }
            )
            print(f"[OK] Nmap completado para {name} ({target})")
        except Exception as exc:
            failures.append(
                {
                    "name": name,
                    "target": target,
                    "profile": profile,
                    "status": "failed",
                    "error": str(exc),
                }
            )
            print(f"[ERROR] Falló Nmap para {name} ({target}): {exc}")

    payload = {
        "ok": len(failures) == 0,
        "message": "Nmap batch finalizado",
        "scanned": len(targets),
        "success": len(results),
        "failed": len(failures),
        "results": results,
        "failures": failures,
        "finished_at": datetime.now().isoformat(),
    }

    output_dir = ensure_output_dir()
    summary_path = output_dir / "nmap_batch_last_summary.json"
    summary_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    return payload


if __name__ == "__main__":
    result = run_nmap_pipeline()
    print(json.dumps(result, indent=2, ensure_ascii=False))
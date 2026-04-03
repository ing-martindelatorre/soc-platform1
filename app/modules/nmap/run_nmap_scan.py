# app/modules/nmap/run_nmap_scan.py

import argparse
import json
import shlex
import subprocess
import sys
from datetime import datetime, UTC
from pathlib import Path

from app.modules.nmap.profiles import get_profile


def utc_now_str() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def build_command(target: str, output_xml: Path, profile_name: str, extra_args: list[str] | None = None) -> list[str]:
    profile = get_profile(profile_name)
    cmd = ["nmap", *profile.args]

    if extra_args:
        cmd.extend(extra_args)

    cmd.extend(["-oX", str(output_xml), target])
    return cmd


def main() -> int:
    parser = argparse.ArgumentParser(description="Ejecuta un escaneo Nmap y guarda XML + metadata.")
    parser.add_argument("--target", required=True, help="Objetivo: IP, CIDR, hostname o archivo con targets")
    parser.add_argument("--profile", default="safe", help="Perfil de escaneo")
    parser.add_argument("--output-dir", default="data/nmap/raw", help="Directorio de salida")
    parser.add_argument("--name", default=None, help="Nombre lógico del escaneo")
    parser.add_argument("--extra-args", default="", help='Argumentos extra para Nmap, ej: "--max-rate 500"')
    args = parser.parse_args()

    scan_name = args.name or f"{args.profile}_{utc_now_str()}"
    output_dir = Path(args.output_dir)
    ensure_dir(output_dir)

    xml_path = output_dir / f"{scan_name}.xml"
    meta_path = output_dir / f"{scan_name}.meta.json"

    extra_args = shlex.split(args.extra_args) if args.extra_args else []
    command = build_command(
        target=args.target,
        output_xml=xml_path,
        profile_name=args.profile,
        extra_args=extra_args,
    )

    print(f"[INFO] Ejecutando: {' '.join(command)}")

    started_at = datetime.now(UTC).isoformat()
    proc = subprocess.run(command, capture_output=True, text=True)
    finished_at = datetime.now(UTC).isoformat()

    metadata = {
        "scan_name": scan_name,
        "profile": args.profile,
        "target": args.target,
        "command": command,
        "returncode": proc.returncode,
        "started_at": started_at,
        "finished_at": finished_at,
        "xml_path": str(xml_path),
        "stdout": proc.stdout[-5000:],
        "stderr": proc.stderr[-5000:],
    }

    meta_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")

    if proc.returncode != 0:
        print("[ERROR] Nmap falló.")
        if proc.stderr:
            print(proc.stderr)
        return proc.returncode

    print(f"[OK] XML guardado en: {xml_path}")
    print(f"[OK] Metadata guardada en: {meta_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
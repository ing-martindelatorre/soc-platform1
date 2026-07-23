"""
scripts/fortinet_policy_export.py

Exporta la configuración completa (interfaces, direcciones, políticas de
firewall, rutas estáticas y admins) de todos los FortiGate activos
(FORTI_1_* … FORTI_5_*) a un único archivo JSON consolidado.

Pensado para pasar el archivo resultante a otra IA que dibuje la topología
de red y proponga qué reglas de firewall conviene eliminar o ajustar.

Uso:
    python scripts/fortinet_policy_export.py [ruta_salida.json]

Si no se indica ruta de salida, se guarda en:
    data/fortinet_export/fortinet_config_export_<timestamp>.json

El archivo generado puede contener información sensible de red (rangos IP,
nombres de host, cuentas admin, VPNs). No se sube a git: vive bajo data/,
que ya está en .gitignore.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.modules.fortinet.extract import extract_config, get_active_device_ids


def build_export() -> dict:
    device_ids = get_active_device_ids()
    export = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "device_count": len(device_ids),
        "devices": [],
    }

    for device_id in device_ids:
        print(f"[fortinet_policy_export] Extrayendo configuración del dispositivo {device_id}...")
        try:
            data = extract_config(device_id=device_id)
        except Exception as exc:
            export["devices"].append({
                "device_id": device_id,
                "error": str(exc),
            })
            print(f"  -> ERROR: {exc}")
            continue

        sections = data.get("sections", {})
        device_entry = {
            "device_id":   device_id,
            "device_name": data.get("device_name"),
            "meta":        data.get("meta", {}),
            "interfaces":         sections.get("interfaces", {}).get("results", []),
            "firewall_addresses": sections.get("firewall_addresses", {}).get("results", []),
            "firewall_policies":  sections.get("firewall_policies", {}).get("results", []),
            "router_static":      sections.get("router_static", {}).get("results", []),
            "system_admins":      sections.get("system_admins", {}).get("results", []),
            "ha_status":          sections.get("ha_status", {}),
            "errors": data.get("errors", []),
        }
        export["devices"].append(device_entry)

        n_policies = len(device_entry["firewall_policies"])
        n_errors   = len(device_entry["errors"])
        print(f"  -> OK: {n_policies} políticas, {n_errors} errores de sección")

    return export


def main() -> None:
    if len(sys.argv) > 1:
        out_path = Path(sys.argv[1])
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = Path(__file__).resolve().parent.parent / "data" / "fortinet_export" / f"fortinet_config_export_{ts}.json"

    out_path.parent.mkdir(parents=True, exist_ok=True)

    export = build_export()

    with out_path.open("w", encoding="utf-8") as f:
        json.dump(export, f, indent=2, ensure_ascii=False, default=str)

    print(f"\nArchivo generado: {out_path}")
    print(f"Dispositivos exportados: {export['device_count']}")


if __name__ == "__main__":
    main()

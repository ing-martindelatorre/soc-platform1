"""
scripts/fortinet_policy_analysis.py

Analiza el JSON generado por fortinet_policy_export.py y produce un informe
en Markdown con hallazgos y recomendaciones sobre las políticas de firewall
de cada FortiGate: reglas demasiado permisivas, duplicadas, sin log, sin
perfiles de seguridad, objetos de dirección huérfanos e interfaces con
acceso de administración expuesto.

Es un análisis propio (basado solo en la configuración, sin ver tráfico real
ni la topología física), pensado como complemento del archivo crudo que se
pasa a otra IA para dibujar la topología.

Uso:
    python scripts/fortinet_policy_analysis.py <export.json> [salida.md]
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path


def _names(field) -> list[str]:
    if not field:
        return []
    return [item.get("name") for item in field if isinstance(item, dict)]


def analyze_device(dev: dict) -> dict:
    policies  = dev.get("firewall_policies", [])
    addresses = dev.get("firewall_addresses", [])
    interfaces = dev.get("interfaces", [])

    findings = {
        "full_open":        [],
        "disabled":         [],
        "no_logging":       [],
        "no_security_profile": [],
        "copy_paste":       [],
        "duplicates":       [],
        "orphan_addresses": [],
        "exposed_mgmt":     [],
    }

    used_addr_names = set()
    dup_groups: dict[tuple, list] = defaultdict(list)

    for p in policies:
        pid    = p.get("policyid")
        name   = p.get("name") or f"policy-{pid}"
        status = p.get("status")
        action = p.get("action")
        src    = sorted(_names(p.get("srcaddr")))
        dst    = sorted(_names(p.get("dstaddr")))
        svc    = sorted(_names(p.get("service")))
        srcintf = sorted(_names(p.get("srcintf")))
        dstintf = sorted(_names(p.get("dstintf")))
        comment = p.get("comments") or ""

        used_addr_names.update(src)
        used_addr_names.update(dst)

        if status == "disable":
            findings["disabled"].append((pid, name))
            continue  # el resto de checks solo aplica a reglas activas

        if action == "accept" and src == ["all"] and dst == ["all"] and svc == ["ALL"]:
            findings["full_open"].append((pid, name, srcintf, dstintf))

        if action == "accept" and p.get("logtraffic") == "disable":
            findings["no_logging"].append((pid, name))

        if action == "accept" and p.get("utm-status") == "disable":
            findings["no_security_profile"].append((pid, name, dstintf))

        if "copy of" in comment.lower() or "(copy" in comment.lower():
            findings["copy_paste"].append((pid, name, comment))

        key = (tuple(srcintf), tuple(dstintf), tuple(src), tuple(dst), tuple(svc), action)
        dup_groups[key].append((pid, name))

    for key, members in dup_groups.items():
        if len(members) > 1:
            findings["duplicates"].append(members)

    all_addr_names = {a.get("name") for a in addresses}
    orphan = all_addr_names - used_addr_names
    findings["orphan_addresses"] = sorted(orphan)

    for i in interfaces:
        aa = (i.get("allowaccess") or "").split()
        exposed = [a for a in aa if a in ("http", "telnet", "https", "ssh")]
        if exposed:
            findings["exposed_mgmt"].append((i.get("name"), i.get("ip"), exposed))

    return findings


def render_device_report(dev: dict, findings: dict) -> str:
    name = dev.get("device_name", f"device-{dev.get('device_id')}")
    meta = dev.get("meta", {})
    lines = [f"## {name}", ""]
    lines.append(f"- Serie: `{meta.get('serial')}` — FortiOS `{meta.get('version')} build {meta.get('build')}`")
    lines.append(f"- Políticas totales: {len(dev.get('firewall_policies', []))}")
    lines.append("")

    if findings["full_open"]:
        lines.append("### 🔴 Reglas any-any-ALL activas (candidatas a eliminar o restringir ya)")
        for pid, pname, srcintf, dstintf in findings["full_open"]:
            lines.append(f"- Policy **{pid}** `{pname}` — {srcintf} → {dstintf}, acepta cualquier origen/destino/servicio.")
        lines.append("")

    if findings["duplicates"]:
        lines.append("### 🟠 Reglas duplicadas / solapadas (mismo origen-destino-servicio-acción)")
        for group in findings["duplicates"]:
            ids = ", ".join(f"{pid} ({pname})" for pid, pname in group)
            lines.append(f"- {ids} — considerar dejar solo una y borrar el resto.")
        lines.append("")

    if findings["copy_paste"]:
        lines.append("### 🟠 Reglas creadas por copia (sprawl de copy-paste)")
        for pid, pname, comment in findings["copy_paste"]:
            lines.append(f"- Policy **{pid}** `{pname}` — comentario: \"{comment.strip()}\". Revisar si sigue siendo necesaria o es un resabio de otra regla.")
        lines.append("")

    if findings["no_security_profile"]:
        lines.append("### 🟡 Reglas `accept` sin ningún perfil de seguridad (utm-status disable)")
        for pid, pname, dstintf in findings["no_security_profile"]:
            lines.append(f"- Policy **{pid}** `{pname}` → {dstintf}: sin AV/IPS/webfilter aplicado.")
        lines.append("")

    if findings["no_logging"]:
        lines.append("### 🟡 Reglas `accept` sin logging (logtraffic disable)")
        for pid, pname in findings["no_logging"]:
            lines.append(f"- Policy **{pid}** `{pname}` — sin logging, no queda rastro del tráfico permitido.")
        lines.append("")

    if findings["disabled"]:
        lines.append("### ⚪ Reglas deshabilitadas (candidatas a limpieza de configuración)")
        for pid, pname in findings["disabled"]:
            lines.append(f"- Policy **{pid}** `{pname}` — deshabilitada; si no se va a reactivar, eliminarla reduce ruido.")
        lines.append("")

    if findings["orphan_addresses"]:
        lines.append("### ⚪ Objetos de dirección sin usar en ninguna política")
        lines.append(", ".join(f"`{n}`" for n in findings["orphan_addresses"]))
        lines.append("")

    if findings["exposed_mgmt"]:
        lines.append("### 🟡 Interfaces con acceso de administración habilitado")
        for iname, ip, exposed in findings["exposed_mgmt"]:
            lines.append(f"- `{iname}` ({ip}) — permite: {', '.join(exposed)}. Confirmar que esta interfaz no da directamente a Internet.")
        lines.append("")

    if not any(findings[k] for k in findings if k != "orphan_addresses") and not findings["orphan_addresses"]:
        lines.append("Sin hallazgos relevantes con las heurísticas aplicadas.")
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    if len(sys.argv) < 2:
        print("Uso: python scripts/fortinet_policy_analysis.py <export.json> [salida.md]")
        sys.exit(1)

    export_path = Path(sys.argv[1])
    with export_path.open(encoding="utf-8") as f:
        export = json.load(f)

    if len(sys.argv) > 2:
        out_path = Path(sys.argv[2])
    else:
        out_path = export_path.with_name(export_path.stem.replace("config_export", "recommendations") + ".md")

    report = [
        "# Recomendaciones de políticas Fortinet",
        "",
        f"Generado a partir de: `{export_path.name}` ({export.get('generated_at')})",
        "",
        "Análisis automático basado únicamente en la configuración exportada vía API "
        "(no incluye tráfico real ni la topología física de red). Úsalo como punto de "
        "partida, no como decisión final: cada regla marcada debe confirmarse con el "
        "dueño del sitio antes de tocarla.",
        "",
    ]

    def _is_unreachable(d: dict) -> bool:
        if d.get("error"):
            return True
        return not d.get("meta") and bool(d.get("errors"))

    unreachable = [d for d in export["devices"] if _is_unreachable(d)]
    reachable   = [d for d in export["devices"] if not _is_unreachable(d)]

    if unreachable:
        report.append("## Dispositivos no analizados (no se pudo conectar)")
        for d in unreachable:
            name = d.get("device_name", f"device-{d.get('device_id')}")
            if d.get("error"):
                report.append(f"- **{name}** (device_id {d.get('device_id')}): {d.get('error')}")
            else:
                first_err = d.get("errors", [{}])[0].get("error", "sin detalle")
                report.append(f"- **{name}** (device_id {d.get('device_id')}): no respondió a ninguna sección — {first_err}")
        report.append("")

    total_full_open = 0
    for dev in reachable:
        findings = analyze_device(dev)
        total_full_open += len(findings["full_open"])
        report.append(render_device_report(dev, findings))

    report.insert(6, f"**Nota:** no fue posible leer cuentas de administrador (`system_admins`) en ningún dispositivo — "
                      f"la API no devolvió datos (probablemente el perfil del token no tiene permiso sobre esa sección). "
                      f"Revisar manualmente `trusthost` de los admins vía GUI/CLI.\n")

    out_path.write_text("\n".join(report), encoding="utf-8")
    print(f"Informe generado: {out_path}")
    print(f"Total reglas any-any-ALL activas encontradas: {total_full_open}")


if __name__ == "__main__":
    main()

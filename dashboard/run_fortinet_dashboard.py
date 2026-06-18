from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from html import escape
from ipaddress import ip_address, ip_network
from typing import Any, Dict, List, Optional, Tuple

import psycopg2
from dotenv import load_dotenv


OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "fortinet_dashboard_output.html")


def get_conn():
    load_dotenv()
    return psycopg2.connect(
        host=os.environ["DB_HOST"],
        port=os.environ["DB_PORT"],
        dbname=os.environ["DB_NAME"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
    )


def fetch_latest_sections(conn, device_name: Optional[str] = None) -> Tuple[str, Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
    with conn.cursor() as cur:
        if device_name:
            cur.execute(
                """
                WITH latest AS (
                    SELECT MAX(frs.collected_at) AS collected_at
                    FROM fortinet_raw_snapshots frs
                    WHERE frs.device_name = %s
                )
                SELECT frs.device_name, frs.section, frs.collected_at, frs.payload::text
                FROM fortinet_raw_snapshots frs
                JOIN latest l ON frs.collected_at = l.collected_at
                WHERE frs.device_name = %s
                ORDER BY frs.section
                """,
                (device_name, device_name),
            )
        else:
            cur.execute(
                """
                WITH latest_device AS (
                    SELECT frs.device_name, MAX(frs.collected_at) AS collected_at
                    FROM fortinet_raw_snapshots frs
                    GROUP BY frs.device_name
                    ORDER BY MAX(frs.collected_at) DESC
                    LIMIT 1
                )
                SELECT frs.device_name, frs.section, frs.collected_at, frs.payload::text
                FROM fortinet_raw_snapshots frs
                JOIN latest_device ld
                  ON frs.device_name = ld.device_name
                 AND frs.collected_at = ld.collected_at
                ORDER BY frs.section
                """
            )
        rows = cur.fetchall()

        if not rows:
            raise RuntimeError("No hay snapshots de Fortinet en fortinet_raw_snapshots")

        chosen_device = rows[0][0]
        sections: Dict[str, Dict[str, Any]] = {}
        for _, section, _, payload_text in rows:
            sections[section] = json.loads(payload_text)

        cur.execute(
            """
            SELECT section, error_message, collected_at
            FROM fortinet_collection_errors
            WHERE device_name = %s
            ORDER BY collected_at DESC
            LIMIT 20
            """,
            (chosen_device,),
        )
        errors = [
            {"section": row[0], "error_message": row[1], "collected_at": row[2]}
            for row in cur.fetchall()
        ]

    return chosen_device, sections, errors

def results_of(sections: Dict[str, Dict[str, Any]], key: str) -> List[Dict[str, Any]]:
    raw = sections.get(key, {})
    results = raw.get("results", []) if isinstance(raw, dict) else []
    return results if isinstance(results, list) else []


def scalar_of(sections: Dict[str, Dict[str, Any]], key: str) -> Dict[str, Any]:
    raw = sections.get(key, {})
    return raw if isinstance(raw, dict) else {}


def safe_get(item: Dict[str, Any], path: List[str], default: str = "") -> str:
    current: Any = item
    for part in path:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return default
    if current is None:
        return default
    if isinstance(current, (dict, list)):
        return json.dumps(current, ensure_ascii=False)
    return str(current)


def parse_subnet(subnet_value: str) -> Optional[str]:
    try:
        ip, mask = subnet_value.split()
        return str(ip_network(f"{ip}/{mask}", strict=False))
    except Exception:
        return None


def normalize_policy_member(member: Any) -> List[str]:
    if isinstance(member, list):
        out = []
        for item in member:
            if isinstance(item, dict):
                out.append(str(item.get("name") or item.get("q_origin_key") or ""))
            else:
                out.append(str(item))
        return [x for x in out if x]
    if isinstance(member, dict):
        return [str(member.get("name") or member.get("q_origin_key") or "")]
    if member is None:
        return []
    return [str(member)]


def compute_findings(sections: Dict[str, Dict[str, Any]], errors: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    policies = results_of(sections, "firewall_policies")
    addresses = results_of(sections, "firewall_addresses")
    interfaces = results_of(sections, "interfaces")
    system_status = scalar_of(sections, "system_status")

    any_any = []
    for p in policies:
        src = normalize_policy_member(p.get("srcaddr"))
        dst = normalize_policy_member(p.get("dstaddr"))
        svc = normalize_policy_member(p.get("service"))
        action = str(p.get("action", "")).lower()
        status = str(p.get("status", "enable")).lower()
        if status != "enable" or action != "accept":
            continue
        if "all" in src and "all" in dst:
            any_any.append({
                "id": safe_get(p, ["policyid"], "?"),
                "service": ", ".join(svc) if svc else "(sin dato)",
                "name": safe_get(p, ["name"], "(sin nombre)")
            })
    if any_any:
        top = any_any[:5]
        findings.append({
            "severity": "alta",
            "title": f"Políticas any-any permitidas: {len(any_any)}",
            "detail": "; ".join([f"ID {x['id']} / {x['service']} / {x['name']}" for x in top])
        })

    broad_addresses = []
    for a in addresses:
        name = safe_get(a, ["name"])
        subnet = safe_get(a, ["subnet"])
        cidr = parse_subnet(subnet) if subnet else None
        if name == "all":
            broad_addresses.append(f"{name} = 0.0.0.0/0")
        elif cidr in {"0.0.0.0/0", "0.0.0.0/32"}:
            broad_addresses.append(f"{name} = {cidr}")
    if broad_addresses:
        findings.append({
            "severity": "media",
            "title": f"Objetos de dirección muy amplios: {len(broad_addresses)}",
            "detail": "; ".join(broad_addresses[:6])
        })

    wan_like = []
    for itf in interfaces:
        name = safe_get(itf, ["name"])
        role = safe_get(itf, ["role"])
        allowaccess = safe_get(itf, ["allowaccess"])
        if role == "wan" or name.lower().startswith("wan"):
            if any(x in allowaccess.lower() for x in ["https", "http", "ssh", "telnet"]):
                wan_like.append(f"{name} ({allowaccess})")
    if wan_like:
        findings.append({
            "severity": "alta",
            "title": f"Interfaces WAN con acceso administrativo: {len(wan_like)}",
            "detail": "; ".join(wan_like[:6])
        })

    admin_count = len(results_of(sections, "system_admins"))
    if admin_count == 0:
        findings.append({
            "severity": "media",
            "title": "No se pudieron leer administradores",
            "detail": "La API devolvió 0 admins. Puede ser permiso insuficiente o endpoint sin acceso con ese perfil API."
        })

    version = safe_get(system_status, ["version"]) or safe_get(system_status, ["results", "version"])
    hostname = safe_get(system_status, ["hostname"]) or safe_get(system_status, ["results", "hostname"])
    if hostname or version:
        findings.append({
            "severity": "info",
            "title": "Identidad del equipo",
            "detail": f"Hostname: {hostname or 'N/D'} | Versión: {version or 'N/D'}"
        })

    recent_errors = [e for e in errors if "404" not in e.get("error_message", "")]
    if recent_errors:
        findings.append({
            "severity": "media",
            "title": f"Errores recientes de recolección: {len(recent_errors)}",
            "detail": "; ".join([f"{e['section']}: {e['error_message']}" for e in recent_errors[:3]])
        })

    return findings


def render_table(title: str, headers: List[str], rows: List[List[str]], max_rows: int = 10) -> str:
    body_rows = rows[:max_rows]
    if not body_rows:
        return f"<section class='panel'><h2>{escape(title)}</h2><p class='muted'>Sin datos.</p></section>"

    thead = "".join(f"<th>{escape(h)}</th>" for h in headers)
    tbody_parts = []
    for row in body_rows:
        tds = "".join(f"<td>{escape(str(cell))}</td>" for cell in row)
        tbody_parts.append(f"<tr>{tds}</tr>")
    return (
        f"<section class='panel'>"
        f"<h2>{escape(title)}</h2>"
        f"<div class='table-wrap'><table><thead><tr>{thead}</tr></thead><tbody>{''.join(tbody_parts)}</tbody></table></div>"
        f"</section>"
    )


def build_html(device_name: str, sections: Dict[str, Dict[str, Any]], errors: List[Dict[str, Any]]) -> str:
    system_status = scalar_of(sections, "system_status")
    addresses = results_of(sections, "firewall_addresses")
    policies = results_of(sections, "firewall_policies")
    interfaces = results_of(sections, "interfaces")
    admins = results_of(sections, "system_admins")
    routes = results_of(sections, "router_static")
    findings = compute_findings(sections, errors)

    serial = safe_get(system_status, ["serial"]) or safe_get(system_status, ["results", "serial"]) or safe_get(system_status, ["serial-number"])
    version = safe_get(system_status, ["version"]) or safe_get(system_status, ["results", "version"]) or scalar_of(sections, "firewall_addresses").get("version", "")
    build = safe_get(system_status, ["build"]) or safe_get(system_status, ["results", "build"]) or scalar_of(sections, "firewall_addresses").get("build", "")
    hostname = safe_get(system_status, ["hostname"]) or safe_get(system_status, ["results", "hostname"]) or device_name
    vdom = scalar_of(sections, "firewall_addresses").get("vdom", "root")
    collected_at = max(
        [
            datetime.now(timezone.utc)
        ]
    )

    cards = [
        ("Dispositivo", hostname),
        ("Serial", serial or "N/D"),
        ("Versión", version or "N/D"),
        ("Build", str(build or "N/D")),
        ("VDOM", vdom or "root"),
        ("Policies", str(len(policies))),
        ("Addresses", str(len(addresses))),
        ("Interfaces", str(len(interfaces))),
        ("Routes", str(len(routes))),
        ("Admins", str(len(admins))),
        ("Findings", str(len(findings))),
        ("Errors", str(len(errors))),
    ]

    cards_html = "".join(
        f"<div class='card'><div class='label'>{escape(k)}</div><div class='value'>{escape(v)}</div></div>"
        for k, v in cards
    )

    finding_html = "".join(
        f"<div class='finding {escape(item['severity'])}'>"
        f"<div class='finding-head'><span class='sev'>{escape(item['severity']).upper()}</span><h3>{escape(item['title'])}</h3></div>"
        f"<p>{escape(item['detail'])}</p></div>"
        for item in findings
    ) or "<p class='muted'>Sin hallazgos relevantes.</p>"

    policies_rows = []
    for p in policies:
        policies_rows.append([
            safe_get(p, ["policyid"], "?"),
            safe_get(p, ["name"], ""),
            safe_get(p, ["srcintf"], "")[:60],
            safe_get(p, ["dstintf"], "")[:60],
            ", ".join(normalize_policy_member(p.get("srcaddr")))[:60],
            ", ".join(normalize_policy_member(p.get("dstaddr")))[:60],
            ", ".join(normalize_policy_member(p.get("service")))[:60],
            safe_get(p, ["action"], ""),
            safe_get(p, ["status"], ""),
        ])

    interfaces_rows = []
    for itf in interfaces:
        interfaces_rows.append([
            safe_get(itf, ["name"]),
            safe_get(itf, ["ip"]),
            safe_get(itf, ["role"]),
            safe_get(itf, ["status"]),
            safe_get(itf, ["allowaccess"]),
            safe_get(itf, ["alias"]),
        ])

    addresses_rows = []
    for a in addresses:
        addresses_rows.append([
            safe_get(a, ["name"]),
            safe_get(a, ["type"]),
            safe_get(a, ["subnet"]) or f"{safe_get(a, ['start-ip'])} - {safe_get(a, ['end-ip'])}" or safe_get(a, ["fqdn"]),
            safe_get(a, ["associated-interface"]),
            safe_get(a, ["allow-routing"]),
            safe_get(a, ["comment"]),
        ])

    routes_rows = []
    for r in routes:
        routes_rows.append([
            safe_get(r, ["seq-num"]) or safe_get(r, ["id"]),
            safe_get(r, ["dst"]),
            safe_get(r, ["gateway"]),
            safe_get(r, ["device"]),
            safe_get(r, ["distance"]),
            safe_get(r, ["status"]),
        ])

    errors_rows = []
    for e in errors:
        when = e.get("collected_at")
        if hasattr(when, "isoformat"):
            when = when.isoformat()
        errors_rows.append([
            e.get("section", ""),
            str(when or ""),
            e.get("error_message", e.get("error", "")),
        ])

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Fortinet Dashboard - {escape(device_name)}</title>
  <style>
    :root {{
      --bg: #0b0f14;
      --panel: #121922;
      --panel-2: #0f141c;
      --text: #e8edf2;
      --muted: #96a2b4;
      --accent: #e53935;
      --accent-2: #ff6b6b;
      --border: #243041;
      --ok: #2ecc71;
      --warn: #f39c12;
      --bad: #ff5d5d;
      --info: #5dade2;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: Inter, Segoe UI, Arial, sans-serif; background: linear-gradient(180deg, #090c11, #0d1218); color: var(--text); }}
    .wrap {{ max-width: 1500px; margin: 0 auto; padding: 28px; }}
    .hero {{ display: flex; justify-content: space-between; align-items: end; gap: 16px; margin-bottom: 22px; }}
    .hero h1 {{ margin: 0; font-size: 34px; }}
    .subtitle {{ color: var(--muted); margin-top: 8px; }}
    .stamp {{ border: 1px solid var(--accent); color: var(--accent-2); padding: 10px 14px; border-radius: 999px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; margin-bottom: 22px; }}
    .card {{ background: linear-gradient(180deg, var(--panel), var(--panel-2)); border: 1px solid var(--border); border-radius: 18px; padding: 16px; box-shadow: 0 10px 30px rgba(0,0,0,.22); }}
    .label {{ color: var(--muted); font-size: 13px; text-transform: uppercase; letter-spacing: .08em; margin-bottom: 10px; }}
    .value {{ font-size: 28px; font-weight: 800; }}
    .layout {{ display: grid; grid-template-columns: 1.1fr .9fr; gap: 18px; margin-bottom: 18px; }}
    .panel {{ background: linear-gradient(180deg, var(--panel), var(--panel-2)); border: 1px solid var(--border); border-radius: 22px; padding: 18px; margin-bottom: 18px; box-shadow: 0 10px 30px rgba(0,0,0,.22); }}
    .panel h2 {{ margin: 0 0 12px; font-size: 20px; }}
    .muted {{ color: var(--muted); }}
    .finding {{ border: 1px solid var(--border); border-radius: 16px; padding: 14px; margin-bottom: 12px; background: rgba(255,255,255,0.015); }}
    .finding.alta {{ border-color: rgba(255,93,93,.35); }}
    .finding.media {{ border-color: rgba(243,156,18,.35); }}
    .finding.info {{ border-color: rgba(93,173,226,.35); }}
    .finding-head {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
    .finding-head h3 {{ margin: 0; font-size: 17px; }}
    .sev {{ font-size: 11px; padding: 5px 8px; border-radius: 999px; background: rgba(229,57,53,.13); color: var(--accent-2); font-weight: 800; letter-spacing: .08em; }}
    .table-wrap {{ overflow-x: auto; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
    th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid rgba(255,255,255,.07); vertical-align: top; }}
    th {{ color: #c8d1dc; font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }}
    tr:hover td {{ background: rgba(255,255,255,.02); }}
    .foot {{ color: var(--muted); font-size: 12px; padding: 4px 2px 20px; }}
    @media (max-width: 1200px) {{ .grid {{ grid-template-columns: repeat(3, minmax(0, 1fr)); }} .layout {{ grid-template-columns: 1fr; }} }}
    @media (max-width: 800px) {{ .grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }} .hero {{ flex-direction: column; align-items: start; }} }}
    @media (max-width: 520px) {{ .grid {{ grid-template-columns: 1fr; }} .wrap {{ padding: 16px; }} }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hero">
      <div>
        <h1>Fortinet Security Dashboard</h1>
        <div class="subtitle">Dispositivo: {escape(device_name)} · Hostname: {escape(hostname)} · Serial: {escape(serial or 'N/D')} · VDOM: {escape(vdom or 'root')}</div>
      </div>
      <div class="stamp">Leviathan SOC</div>
    </div>

    <section class="grid">{cards_html}</section>

    <section class="layout">
      <div class="panel">
        <h2>Hallazgos prioritarios</h2>
        {finding_html}
      </div>
      <div class="panel">
        <h2>Resumen ejecutivo</h2>
        <p><strong>Equipo:</strong> {escape(hostname)}</p>
        <p><strong>Versión:</strong> {escape(version or 'N/D')} (build {escape(str(build or 'N/D'))})</p>
        <p><strong>Configuración visible:</strong> {len(policies)} políticas, {len(addresses)} objetos de dirección, {len(interfaces)} interfaces y {len(routes)} rutas.</p>
        <p><strong>Estado del módulo:</strong> recolección y carga a PostgreSQL funcionando.</p>
        <p><strong>Observación:</strong> el endpoint de HA puede no estar soportado o no aplicar a este equipo.</p>
      </div>
    </section>

    {render_table('Top políticas de firewall', ['ID', 'Nombre', 'Src Intf', 'Dst Intf', 'Src Addr', 'Dst Addr', 'Service', 'Action', 'Status'], policies_rows, 20)}
    {render_table('Interfaces', ['Nombre', 'IP', 'Rol', 'Estado', 'Allowaccess', 'Alias'], interfaces_rows, 20)}
    {render_table('Objetos de dirección', ['Nombre', 'Tipo', 'Subnet / Rango / FQDN', 'Associated Interface', 'Allow Routing', 'Comentario'], addresses_rows, 20)}
    {render_table('Rutas estáticas', ['ID', 'Destino', 'Gateway', 'Interfaz', 'Distance', 'Status'], routes_rows, 20)}
    {render_table('Errores de recolección', ['Sección', 'Fecha', 'Error'], errors_rows, 20)}

    <div class="foot">Dashboard generado automáticamente desde PostgreSQL. Archivo listo para abrirse en navegador o integrarse al repo del SOC.</div>
  </div>
</body>
</html>"""
    return html


def _get_active_device_names() -> list[str]:
    """Detecta los dispositivos Fortinet activos según las vars FORTI_n_* del .env."""
    devices = []
    for n in range(1, 6):
        url   = os.getenv(f"FORTI_{n}_BASE_URL", "").strip()
        token = os.getenv(f"FORTI_{n}_API_TOKEN", "").strip()
        name  = os.getenv(f"FORTI_{n}_DEVICE_NAME", f"fortigate-{n}").strip()
        if url and token:
            devices.append(name)
    if not devices:
        legacy = os.getenv("FORTI_DEVICE_NAME", "").strip()
        if legacy:
            devices.append(legacy)
    return devices


def main():
    devices = _get_active_device_names()
    dash_dir = os.path.dirname(OUTPUT_PATH)
    generated = []

    conn = get_conn()
    try:
        for device_name in devices:
            try:
                chosen_device, sections, errors = fetch_latest_sections(conn, device_name)
                html = build_html(chosen_device, sections, errors)

                safe_name = device_name.lower().replace(" ", "_").replace("-", "_")
                per_device_path = os.path.join(dash_dir, f"fortinet_dashboard_{safe_name}.html")
                with open(per_device_path, "w", encoding="utf-8") as f:
                    f.write(html)

                if not generated:
                    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
                        f.write(html)

                generated.append(device_name)
                print(f"[OK] Dashboard generado para {device_name} → {per_device_path}")
            except Exception as e:
                print(f"[ERROR] Dispositivo {device_name}: {e}")
    finally:
        conn.close()

    if not generated:
        print("[WARN] No se generó ningún dashboard — verifica las variables FORTI_n_* en .env")
    else:
        print(f"[OK] {len(generated)} dashboard(s) generados")


if __name__ == "__main__":
    main()

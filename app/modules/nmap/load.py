# app/modules/nmap/load.py

import argparse
import json
import os
from pathlib import Path
from typing import Any

import psycopg2
from psycopg2.extras import Json


def get_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
    )


def upsert_asset(conn, asset: dict[str, Any]) -> int:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO nmap_assets (ip, hostname, mac, os_guess, status)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (ip)
            DO UPDATE SET
                hostname = EXCLUDED.hostname,
                mac = EXCLUDED.mac,
                os_guess = EXCLUDED.os_guess,
                status = EXCLUDED.status,
                last_seen = NOW()
            RETURNING id;
            """,
            (
                asset["ip"],
                asset.get("hostname"),
                asset.get("mac"),
                asset.get("os_guess"),
                asset.get("status"),
            ),
        )
        return cur.fetchone()[0]


def upsert_service(conn, asset_id: int, service: dict[str, Any]) -> int:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO nmap_services (
                asset_id, port, protocol, service_name,
                product, version, extrainfo, tags, scripts
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (asset_id, port, protocol)
            DO UPDATE SET
                service_name = EXCLUDED.service_name,
                product = EXCLUDED.product,
                version = EXCLUDED.version,
                extrainfo = EXCLUDED.extrainfo,
                tags = EXCLUDED.tags,
                scripts = EXCLUDED.scripts,
                last_seen = NOW()
            RETURNING id;
            """,
            (
                asset_id,
                service["port"],
                service["protocol"],
                service["service_name"],
                service.get("product"),
                service.get("version"),
                service.get("extrainfo"),
                Json(service.get("tags", [])),
                Json(service.get("scripts", [])),
            ),
        )
        return cur.fetchone()[0]


def insert_finding(conn, asset_id: int, service_id: int | None, finding: dict[str, Any]) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO nmap_findings (
                asset_id, service_id, severity, title,
                description, recommendation, category,
                evidence, source, script_name, status,
                first_seen, last_seen
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
            """,
            (
                asset_id,
                service_id,
                finding["severity"],
                finding["title"],
                finding.get("description"),
                finding.get("recommendation"),
                finding.get("category"),
                Json(finding.get("evidence", {})),
                finding.get("source", "nmap"),
                finding.get("script_name", ""),
                finding.get("status", "open"),
                finding.get("first_seen"),
                finding.get("last_seen"),
            ),
        )


def upsert_vulnerability(conn, asset_id: int, service_id: int | None, vuln: dict[str, Any]) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO nmap_vulnerabilities (
                asset_id, service_id, port, protocol, vuln_id, is_cve, cvss,
                severity, detection, has_exploit, in_kev, kev_ransomware, nvd_affected, title,
                product, version, cpe, script_name, reference_url, status,
                first_seen, last_seen
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, 'open', NOW(), NOW())
            ON CONFLICT (asset_id, port, protocol, vuln_id)
            DO UPDATE SET
                service_id    = EXCLUDED.service_id,
                is_cve        = EXCLUDED.is_cve,
                cvss          = EXCLUDED.cvss,
                severity      = EXCLUDED.severity,
                detection     = EXCLUDED.detection,
                has_exploit   = EXCLUDED.has_exploit,
                in_kev        = EXCLUDED.in_kev,
                kev_ransomware = EXCLUDED.kev_ransomware,
                nvd_affected  = EXCLUDED.nvd_affected,
                title         = EXCLUDED.title,
                product       = EXCLUDED.product,
                version       = EXCLUDED.version,
                cpe           = EXCLUDED.cpe,
                script_name   = EXCLUDED.script_name,
                reference_url = EXCLUDED.reference_url,
                status        = 'open',
                resolved_at   = NULL,
                last_seen     = NOW();
            """,
            (
                asset_id,
                service_id,
                vuln.get("port", 0),
                vuln.get("protocol", ""),
                vuln["vuln_id"],
                vuln.get("is_cve", True),
                vuln.get("cvss"),
                vuln["severity"],
                vuln["detection"],
                vuln.get("has_exploit", False),
                vuln.get("in_kev", False),
                vuln.get("kev_ransomware", False),
                vuln.get("nvd_affected"),
                vuln.get("title"),
                vuln.get("product"),
                vuln.get("version"),
                vuln.get("cpe"),
                vuln.get("script_name"),
                vuln.get("reference_url"),
            ),
        )


def resolve_missing_vulnerabilities(conn, asset_id: int, asset: dict[str, Any]) -> int:
    """
    Marca como resueltas las vulnerabilidades abiertas del activo que este
    escaneo (con scripts) ya no reportó. NOW() es constante dentro de la
    transacción, así que "no vista en esta corrida" = last_seen < NOW().

    Salvaguarda: si en un puerto que sigue abierto el script vulners no
    produjo salida (API de vulners.com caída, timeout), sus CVEs "por versión"
    NO se resuelven.
    """
    services = asset.get("services", [])
    if asset.get("status") != "up" or not services:
        return 0

    open_ports = [s["port"] for s in services]
    vulners_ports = [
        s["port"] for s in services
        if any(sc.get("id") == "vulners" and sc.get("output") for sc in s.get("scripts", []))
    ]
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE nmap_vulnerabilities
               SET status = 'resolved', resolved_at = NOW()
             WHERE asset_id = %s
               AND status = 'open'
               AND last_seen < NOW()
               AND (
                    detection <> 'version'
                    OR port <> ALL(%s)
                    OR port = ANY(%s)
               )
            """,
            (asset_id, open_ports, vulners_ports),
        )
        return cur.rowcount


def load_to_db(enriched_data: dict[str, Any], vuln_scan: bool = False) -> None:
    """
    vuln_scan: True si el perfil ejecutó scripts NSE de vulnerabilidades.
               Sólo entonces se cierran las vulnerabilidades que ya no aparecen
               (un escaneo sin scripts no puede afirmar que algo se corrigió).
    """
    conn = get_connection()

    try:
        for asset in enriched_data.get("assets", []):
            asset_id = upsert_asset(conn, asset)
            service_map: dict[tuple[int, str], int] = {}

            for service in asset.get("services", []):
                service_id = upsert_service(conn, asset_id, service)
                service_map[(service["port"], service["protocol"])] = service_id

            for finding in enriched_data.get("findings", []):
                if finding["asset_ip"] != asset["ip"]:
                    continue

                service_id = service_map.get((finding["port"], finding["protocol"]))
                insert_finding(conn, asset_id, service_id, finding)

            for vuln in enriched_data.get("vulnerabilities", []):
                if vuln["asset_ip"] != asset["ip"]:
                    continue

                service_id = service_map.get((vuln["port"], vuln["protocol"]))
                upsert_vulnerability(conn, asset_id, service_id, vuln)

            if vuln_scan:
                resolve_missing_vulnerabilities(conn, asset_id, asset)

        conn.commit()
        print("[OK] Datos Nmap cargados a PostgreSQL")

    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Carga JSON enriquecido de Nmap a PostgreSQL.")
    parser.add_argument("--infile", required=True, help="Ruta al JSON enriquecido")
    args = parser.parse_args()

    in_path = Path(args.infile)
    data = json.loads(in_path.read_text(encoding="utf-8"))
    load_to_db(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
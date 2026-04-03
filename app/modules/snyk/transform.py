from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _as_list(data: Any) -> list[dict]:
    if data is None:
        return []
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        return [data]
    return []


def _extract_vulns_from_doc(doc: dict) -> list[dict]:
    vulns = doc.get("vulnerabilities")
    if isinstance(vulns, list):
        return [v for v in vulns if isinstance(v, dict)]
    return []


def _join_list(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(x) for x in value if x)
    return str(value or "")


def parse_snyk_sca_findings(
        raw_json: Any,
        repo_name: str,
        repo_path: str,
        scan_run_id: int | None = None,
) -> list[dict]:
    """
    Normaliza findings SCA al esquema real de snyk_findings del proyecto.
    """
    docs = _as_list(raw_json)
    rows: list[dict] = []
    now_ts = datetime.now(timezone.utc)

    for doc in docs:
        project_name = (
                doc.get("projectName")
                or doc.get("displayTargetFile")
                or doc.get("targetFile")
                or repo_name
        )

        target_file = doc.get("displayTargetFile") or doc.get("targetFile") or ""
        package_manager = doc.get("packageManager") or ""

        # Para tu constraint única necesitamos file_path no vacío
        file_path = target_file or ""

        for vuln in _extract_vulns_from_doc(doc):
            identifiers = vuln.get("identifiers") or {}
            cves = identifiers.get("CVE") or []
            cwes = identifiers.get("CWE") or []

            issue_id = vuln.get("id") or ""
            severity = str(vuln.get("severity") or "").lower()
            title = vuln.get("title") or issue_id or "Unnamed issue"
            description = vuln.get("description") or vuln.get("overview") or ""
            package_name = vuln.get("packageName") or vuln.get("name") or ""
            version = vuln.get("version") or ""

            fixed_in = vuln.get("fixedIn") or []
            fixed_version = _join_list(fixed_in)

            exploit_maturity = vuln.get("exploitMaturity") or ""

            # Si el finding no trae file específico, usamos el manifest/lockfile del proyecto
            resolved_file_path = (
                    vuln.get("filePath")
                    or vuln.get("path")
                    or file_path
                    or target_file
                    or ""
            )

            row = {
                # esquema heredado real
                "repo_name": repo_name,
                "scan_type": "sca",
                "issue_id": issue_id,
                "severity": severity,
                "title": title,
                "description": description,
                "package_name": package_name,
                "version": version,
                "cve": cves[0] if isinstance(cves, list) and cves else "",
                "project_name": project_name,
                "file_path": resolved_file_path or "",
                "line": None,
                "rule_id": "",
                "language": package_manager or "",
                "exploit_maturity": exploit_maturity,
                "is_upgradable": bool(vuln.get("isUpgradable", False)),
                "is_patchable": bool(vuln.get("isPatchable", False)),
                "scan_timestamp": now_ts,
                "raw_file_path": target_file or "",
                "first_seen": now_ts,
                "last_seen": now_ts,
                "is_active": True,
                "created_at": now_ts,

                # columnas nuevas/extra que sí existen en tu tabla
                "scan_run_id": scan_run_id,
                "repo_path": repo_path,
                "vuln_id": issue_id,
                "issue_url": vuln.get("url") or "",
                "fixed_version": fixed_version,
                "cves": _join_list(cves),
                "cwes": _join_list(cwes),
                "is_pinnable": bool(vuln.get("isPinnable", False)),
                "json_data": vuln,
                "issue_type": "sca",
                "target_file": target_file,
            }

            rows.append(row)

    return rows
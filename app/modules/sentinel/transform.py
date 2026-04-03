from __future__ import annotations

from app.core.utils import stable_hash


def _safe_str(value):
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return str(value)
    return str(value)


def _pick_agent_name(r: dict) -> str | None:
    detection = r.get("agentDetectionInfo", {}) or {}
    realtime = r.get("agentRealtimeInfo", {}) or {}
    agent_info = r.get("agentInfo", {}) or {}

    return (
            realtime.get("agentComputerName")
            or detection.get("agentComputerName")
            or detection.get("agentName")
            or realtime.get("agentName")
            or realtime.get("computerName")
            or realtime.get("computer_name")
            or agent_info.get("agentName")
            or agent_info.get("computerName")
    )


def _pick_username(r: dict) -> str | None:
    detection = r.get("agentDetectionInfo", {}) or {}
    realtime = r.get("agentRealtimeInfo", {}) or {}
    threat_info = r.get("threatInfo", {}) or {}

    return (
            detection.get("agentLastLoggedInUserName")
            or detection.get("user")
            or realtime.get("loggedInUserName")
            or realtime.get("userName")
            or realtime.get("username")
            or threat_info.get("processUser")
    )


def _pick_classification(r: dict) -> str | None:
    threat_info = r.get("threatInfo", {}) or {}
    return (
            threat_info.get("classification")
            or r.get("classification")
    )


def _pick_severity(r: dict) -> str | None:
    threat_info = r.get("threatInfo", {}) or {}
    return (
            threat_info.get("confidenceLevel")
            or threat_info.get("severity")
            or r.get("threatSeverity")
    )


def _summarize_status(r: dict) -> str:
    threat_info = r.get("threatInfo", {}) or {}
    mitigation = r.get("mitigationStatus")

    incident_status = threat_info.get("incidentStatus")
    if incident_status:
        return str(incident_status).lower()

    threat_mitigation_status = threat_info.get("mitigationStatus")
    if threat_mitigation_status:
        return str(threat_mitigation_status).lower()

    if isinstance(mitigation, list):
        if not mitigation:
            return "unknown"

        statuses = [
            str(x.get("status", "")).lower()
            for x in mitigation
            if isinstance(x, dict)
        ]

        if statuses and all(s == "success" for s in statuses):
            return "mitigated"
        if any(s == "failed" for s in statuses):
            return "failed"
        if any(s == "pending" for s in statuses):
            return "pending"

        return "partial"

    if isinstance(mitigation, str) and mitigation.strip():
        return mitigation.strip().lower()

    return "unknown"


class SentinelTransformer:
    def run(self, rows, **kwargs):
        out = []

        for r in rows:
            threat_info = r.get("threatInfo", {}) or {}
            realtime = r.get("agentRealtimeInfo", {}) or {}

            incident_id = (
                    r.get("id")
                    or threat_info.get("threatId")
                    or ""
            )

            if not incident_id:
                continue

            item = {
                "incident_id": str(incident_id),
                "account_id": _safe_str(r.get("accountId") or realtime.get("accountId")),
                "site_id": _safe_str(r.get("siteId") or realtime.get("siteId")),
                "threat_name": _safe_str(threat_info.get("threatName")),
                "classification": _safe_str(_pick_classification(r)),
                "severity": _safe_str(_pick_severity(r)),
                "status": _summarize_status(r),
                "agent_id": _safe_str(realtime.get("agentId")),
                "agent_name": _safe_str(_pick_agent_name(r)),
                "username": _safe_str(_pick_username(r)),
                "created_at": threat_info.get("createdAt") or r.get("createdAt"),
                "updated_at": threat_info.get("updatedAt") or r.get("updatedAt"),
                "raw_hash": stable_hash(r),
                "raw_json": r,
            }

            out.append(item)

        return out
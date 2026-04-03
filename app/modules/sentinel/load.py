from __future__ import annotations

import json
from app.core.db import get_conn, bulk_upsert


def _safe_json(value):
    return json.dumps(value, default=str)


class SentinelLoader:
    def run(self, rows, **kwargs):
        if not rows:
            return 0

        sql = """
        INSERT INTO sentinel_incidents (
            incident_id, account_id, site_id, threat_name, classification, severity,
            status, agent_id, agent_name, username, created_at, updated_at,
            raw_hash, raw_json
        ) VALUES %s
        ON CONFLICT (incident_id) DO UPDATE SET
            account_id = EXCLUDED.account_id,
            site_id = EXCLUDED.site_id,
            threat_name = EXCLUDED.threat_name,
            classification = EXCLUDED.classification,
            severity = EXCLUDED.severity,
            status = EXCLUDED.status,
            agent_id = EXCLUDED.agent_id,
            agent_name = EXCLUDED.agent_name,
            username = EXCLUDED.username,
            created_at = EXCLUDED.created_at,
            updated_at = EXCLUDED.updated_at,
            raw_hash = EXCLUDED.raw_hash,
            raw_json = EXCLUDED.raw_json,
            ingested_at = NOW()
        """

        values = [(
            str(r["incident_id"]) if r.get("incident_id") is not None else None,
            str(r["account_id"]) if r.get("account_id") is not None else None,
            str(r["site_id"]) if r.get("site_id") is not None else None,
            str(r["threat_name"]) if r.get("threat_name") is not None else None,
            str(r["classification"]) if r.get("classification") is not None else None,
            str(r["severity"]) if r.get("severity") is not None else None,
            str(r["status"]) if r.get("status") is not None else None,
            str(r["agent_id"]) if r.get("agent_id") is not None else None,
            str(r["agent_name"]) if r.get("agent_name") is not None else None,
            str(r["username"]) if r.get("username") is not None else None,
            r.get("created_at"),
            r.get("updated_at"),
            str(r["raw_hash"]) if r.get("raw_hash") is not None else None,
            _safe_json(r.get("raw_json", {})),
        ) for r in rows]

        with get_conn() as conn:
            bulk_upsert(conn, sql, values)

        return len(rows)
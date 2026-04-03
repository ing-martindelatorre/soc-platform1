from __future__ import annotations

import requests
from app.core.config import settings


class SentinelExtractor:
    def run(
            self,
            limit: int = 200,
            date_from: str | None = None,
            date_to: str | None = None,
            **kwargs
    ):
        if not settings.S1_BASE_URL or not settings.S1_API_TOKEN:
            raise ValueError("Missing SentinelOne configuration")

        url = f"{settings.S1_BASE_URL.rstrip('/')}/web/api/v2.1/threats"
        headers = {
            "Authorization": f"ApiToken {settings.S1_API_TOKEN}",
            "Accept": "application/json",
        }

        all_rows: list[dict] = []
        cursor: str | None = None

        while True:
            params: dict[str, object] = {
                "limit": limit,
            }

            # Ajusta estos filtros si tu tenant usa otros nombres,
            # pero esta es la idea correcta para backfill por fechas.
            if date_from:
                params["createdAt__gte"] = date_from
            if date_to:
                params["createdAt__lte"] = date_to

            if cursor:
                params["cursor"] = cursor

            resp = requests.get(url, headers=headers, params=params, timeout=60)

            if resp.status_code >= 400:
                raise RuntimeError(
                    f"SentinelOne API error {resp.status_code}: {resp.text}"
                )

            payload = resp.json()
            batch = payload.get("data", []) or []

            if not batch:
                break

            all_rows.extend(batch)

            pagination = payload.get("pagination", {}) or {}
            next_cursor = (
                    pagination.get("nextCursor")
                    or pagination.get("next_cursor")
                    or payload.get("nextCursor")
                    or payload.get("next_cursor")
            )

            # Si no hay cursor siguiente o vino menos que el límite,
            # ya terminamos la ventana.
            if not next_cursor or len(batch) < limit:
                break

            cursor = next_cursor

        return all_rows
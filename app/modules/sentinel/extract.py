from __future__ import annotations

import logging
import time

import requests
from app.core.config import settings

logger = logging.getLogger("soc-platform")

# Reintentos ante fallas transitorias de la API (timeouts, errores de red, 429/5xx).
# Un 401/403/4xx no se reintenta: es un problema de token o de petición.
MAX_ATTEMPTS = 3
BACKOFF_SECONDS = (10, 30)
RETRYABLE_STATUS = {429, 500, 502, 503, 504}


def _get_with_retry(url: str, headers: dict, params: dict) -> requests.Response:
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=60)
            if resp.status_code not in RETRYABLE_STATUS:
                return resp
            reason = f"HTTP {resp.status_code}"
        except (requests.Timeout, requests.ConnectionError) as exc:
            if attempt == MAX_ATTEMPTS:
                raise
            reason = type(exc).__name__

        if attempt == MAX_ATTEMPTS:
            return resp

        wait = BACKOFF_SECONDS[min(attempt - 1, len(BACKOFF_SECONDS) - 1)]
        logger.warning(
            "[sentinel] %s en intento %d/%d, reintentando en %ds",
            reason, attempt, MAX_ATTEMPTS, wait,
        )
        time.sleep(wait)


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

            resp = _get_with_retry(url, headers, params)

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
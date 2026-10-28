"""
app/modules/replication/tables.py

Catálogo de tablas replicables hacia otra ubicación. Lo comparten el emisor
(service.py/extract.py, en esta instancia) y el receptor
(app/pipeline/replication_receiver.py, en la instancia destino) para que
ambos lados usen siempre la misma definición y no se desincronicen.
"""
from __future__ import annotations

# Solo tablas con PK numérica autoincremental ("id" BIGSERIAL) y SIN foreign
# keys hacia otras tablas — apply.py inserta cada fila de forma independiente,
# así que una fila con FK a una tabla no replicada rompería por violación de
# integridad referencial en el receptor. Quedan fuera a propósito:
#   - sentinel_incidents: su PK es incident_id (TEXT), no tiene columna "id".
#   - nmap_findings: tiene FK a nmap_assets y nmap_services, que no se
#     replican (harían falta esas dos tablas también, en orden, para que
#     resuelvan las referencias).
REPLICABLE_TABLES: list[dict] = [
    {"table": "fortinet_threats",       "label": "Fortinet — Amenazas"},
    {"table": "fortinet_raw_snapshots", "label": "Fortinet — Config/snapshots"},
    {"table": "snyk_findings",          "label": "Snyk"},
    {"table": "cpanel_mail_events",     "label": "cPanel — Correo"},
]

REPLICABLE_TABLE_NAMES = frozenset(t["table"] for t in REPLICABLE_TABLES)


def tables_for_target(selected: list[str] | None) -> list[dict]:
    """
    Filtra REPLICABLE_TABLES según la lista guardada en replication_targets.tables.
    Lista vacía o None = todas las tablas replicables.
    """
    if not selected:
        return REPLICABLE_TABLES
    wanted = set(selected)
    return [t for t in REPLICABLE_TABLES if t["table"] in wanted]

"""
Organizaciones y rangos de infraestructura considerados legítimos.
Una IP que pertenezca a cualquiera de estas categorías no se muestra
como sospechosa en el dashboard.
"""
from __future__ import annotations

import re

# ASNs verificados de proveedores de infraestructura confiable
TRUSTED_ASNS: set[str] = {
    "AS15169",   # Google LLC
    "AS396982",  # Google LLC (GCP)
    "AS36040",   # Google LLC (YouTube)
    "AS19679",   # Dropbox, Inc.
    "AS20940",   # Akamai International (CDN)
    "AS16625",   # Akamai Connected Cloud
    "AS32934",   # Facebook / Meta
    "AS54115",   # Facebook / Meta
    "AS8075",    # Microsoft Corporation
    "AS3598",    # Microsoft Corporation
    "AS16509",   # Amazon.com / AWS
    "AS14618",   # Amazon.com / AWS
    "AS714",     # Apple Inc.
    "AS13335",   # Cloudflare, Inc.
    "AS209242",  # Cloudflare, Inc.
    "AS32590",   # Valve / Steam
    "AS46489",   # Twitch Interactive (Amazon)
    "AS54113",   # Fastly CDN
    "AS22616",   # Twitter / X
    "AS13414",   # Twitter / X
    "AS2906",    # Netflix
    "AS55095",   # Spotify (AB)
}

# Patrones en el nombre de organización (case-insensitive)
TRUSTED_ORG_PATTERNS: list[str] = [
    r"google",
    r"dropbox",
    r"akamai",
    r"facebook",
    r"meta\s+platform",
    r"microsoft",
    r"amazon",
    r"apple\s+inc",
    r"cloudflare",
    r"fastly",
    r"twitter",
    r"spotify",
    r"netflix",
    r"steam",
    r"twitch",
]

# Tags de Shodan que indican infraestructura CDN/cloud legítima
TRUSTED_SHODAN_TAGS: set[str] = {"cdn", "cloud"}

# Patrones de hostname de infraestructura conocida
TRUSTED_HOSTNAME_PATTERNS: list[str] = [
    r"\.google\.com$",
    r"\.1e100\.net$",
    r"\.googleusercontent\.com$",
    r"\.googleapis\.com$",
    r"\.gstatic\.com$",
    r"dropbox\.com$",
    r"\.dropboxstatic\.com$",
    r"akamaitechnologies\.com$",
    r"\.akamai\.net$",
    r"\.akamaiedge\.net$",
    r"\.facebook\.com$",
    r"\.fbcdn\.net$",
    r"\.spotify\.com$",
    r"\.microsoft\.com$",
    r"\.azure\.com$",
    r"\.windows\.net$",
    r"cloudflare\.com$",
    r"\.amazonaws\.com$",
    r"\.apple\.com$",
    r"\.icloud\.com$",
    r"\.netflix\.com$",
    r"\.nflxvideo\.net$",
    r"\.steamcontent\.com$",
]

_ORG_RE  = [re.compile(p, re.IGNORECASE) for p in TRUSTED_ORG_PATTERNS]
_HOST_RE = [re.compile(p, re.IGNORECASE) for p in TRUSTED_HOSTNAME_PATTERNS]


def is_trusted(
    asn: str | None,
    org: str | None,
    hostnames: list[str] | None,
    tags: list[str] | None,
) -> tuple[bool, str]:
    """Retorna (es_confiable, razón_legible)."""
    # Normalizar ASN — ipinfo devuelve "AS15169 Google LLC", tomar solo el AS
    parts = (asn or "").upper().split()
    asn_clean = parts[0] if parts else ""
    if asn_clean in TRUSTED_ASNS:
        return True, f"ASN confiable: {asn_clean}"

    org_str = org or ""
    for pattern in _ORG_RE:
        if pattern.search(org_str):
            return True, f"Organización reconocida: {org_str[:60]}"

    for hostname in (hostnames or []):
        for pattern in _HOST_RE:
            if pattern.search(hostname):
                return True, f"Hostname reconocido: {hostname}"

    for tag in (tags or []):
        if tag.lower() in TRUSTED_SHODAN_TAGS:
            return True, f"Infraestructura {tag.upper()}: {org_str[:40] or 'desconocida'}"

    return False, ""

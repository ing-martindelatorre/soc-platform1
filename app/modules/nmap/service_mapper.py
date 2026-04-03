# app/modules/nmap/service_mapper.py

from typing import Dict, List, Tuple


HIGH_RISK_PORTS = {
    21: "FTP expuesto",
    23: "Telnet expuesto",
    445: "SMB expuesto",
    3389: "RDP expuesto",
    5900: "VNC expuesto",
    3306: "MySQL expuesto",
    5432: "PostgreSQL expuesto",
    6379: "Redis expuesto",
    27017: "MongoDB expuesto",
}

ADMIN_PORTS = {
    22: "SSH",
    80: "HTTP",
    161: "SNMP",
    443: "HTTPS",
    8080: "HTTP alterno",
    8443: "HTTPS alterno",
    10443: "Panel administrativo alterno",
}

INSECURE_SERVICES = {
    "telnet": ("high", "Telnet es inseguro y transmite credenciales en texto claro."),
    "ftp": ("medium", "FTP sin TLS puede exponer credenciales e información."),
    "vnc": ("high", "VNC suele representar una superficie de acceso remoto sensible."),
    "rdp": ("high", "RDP expuesto incrementa el riesgo de acceso remoto no autorizado."),
    "smb": ("high", "SMB expuesto requiere validación de endurecimiento y versiones."),
    "snmp": ("medium", "SNMP expuesto puede revelar información sensible si está mal configurado."),
    "redis": ("high", "Redis expuesto es comúnmente abusado si no requiere autenticación fuerte."),
    "mongodb": ("high", "MongoDB expuesto puede representar fuga o manipulación de datos."),
}


def normalize_service_name(service_name: str) -> str:
    if not service_name:
        return "unknown"

    name = service_name.strip().lower()

    aliases = {
        "microsoft-ds": "smb",
        "ms-wbt-server": "rdp",
        "ssl/http": "https",
        "https-alt": "https",
        "http-proxy": "http",
    }

    return aliases.get(name, name)


def port_risk(port: int) -> Tuple[str, str] | None:
    if port in HIGH_RISK_PORTS:
        return ("high", HIGH_RISK_PORTS[port])

    if port in ADMIN_PORTS:
        return ("medium", f"Puerto administrativo detectado: {ADMIN_PORTS[port]}")

    return None


def classify_service(service_name: str) -> Tuple[str, str] | None:
    normalized = normalize_service_name(service_name)
    return INSECURE_SERVICES.get(normalized)


def build_service_tags(port: int, service_name: str, product: str = "", version: str = "") -> List[str]:
    tags: List[str] = []

    normalized = normalize_service_name(service_name)

    if normalized in {"http", "https"}:
        tags.append("web")

    if normalized in {"ssh", "telnet", "rdp", "vnc"}:
        tags.append("remote-access")

    if normalized in {"mysql", "postgresql", "mongodb", "redis", "ms-sql-s"}:
        tags.append("database")

    if normalized in {"snmp"}:
        tags.append("network-management")

    if port in ADMIN_PORTS:
        tags.append("admin-port")

    if product:
        tags.append(f"product:{product.strip().lower().replace(' ', '_')}")

    if version:
        tags.append(f"version:{version.strip().lower().replace(' ', '_')}")

    return tags


def maybe_flag_legacy_version(service_name: str, product: str, version: str) -> Dict | None:
    s = normalize_service_name(service_name)
    product_l = (product or "").lower()
    version_l = (version or "").lower()

    if s == "ssl":
        return {
            "severity": "medium",
            "title": "Servicio SSL detectado",
            "description": "Se detectó un servicio SSL/TLS que requiere validación adicional.",
            "recommendation": "Validar protocolos, cifrados y certificado con herramientas TLS específicas.",
            "category": "tls",
        }

    if "openssh" in product_l and version_l.startswith(("5.", "6.", "7.0", "7.1", "7.2")):
        return {
            "severity": "medium",
            "title": "Versión antigua de OpenSSH detectada",
            "description": f"Se detectó {product} {version}, potencialmente desactualizado.",
            "recommendation": "Revisar parches y política de hardening del servicio SSH.",
            "category": "legacy-software",
        }

    if "apache httpd" in product_l and version_l.startswith(("2.2", "2.0")):
        return {
            "severity": "high",
            "title": "Versión legacy de Apache detectada",
            "description": f"Se detectó {product} {version}, posiblemente fuera de soporte.",
            "recommendation": "Actualizar Apache y validar CVEs asociados a la versión detectada.",
            "category": "legacy-software",
        }

    return None
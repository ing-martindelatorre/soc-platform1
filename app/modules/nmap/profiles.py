from __future__ import annotations

NMAP_PROFILES: dict[str, list[str]] = {
    # Perfil ligero para correr frecuente sin root
    "quick": [
        "-Pn",
        "-T4",
        "-sT",
        "-sV",
        "--top-ports", "100",
    ],

    # Escaneo completo TCP sin fingerprint de OS
    "full_tcp": [
        "-Pn",
        "-T4",
        "-sT",
        "-sV",
        "-p-",
    ],

    # Perímetro más pesado, sí requiere root por -sS y -O
    "perimeter": [
        "-Pn",
        "-T4",
        "-sS",
        "-sV",
        "-O",
        "--top-ports", "1000",
    ],

    # Vulnerabilidades, también pesado
    "vuln": [
        "-Pn",
        "-T4",
        "-sT",
        "-sV",
        "--script", "vuln",
        "--top-ports", "1000",
    ],
}


def get_profile_args(profile_name: str) -> list[str]:
    if profile_name not in NMAP_PROFILES:
        raise ValueError(f"Perfil Nmap no soportado: {profile_name}")
    return NMAP_PROFILES[profile_name]
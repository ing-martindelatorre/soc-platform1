"""
app/modules/cpanel/ssh_extract.py

Extrae eventos de seguridad del log de Exim via SSH.
Parsea /var/log/exim_mainlog buscando: spam, virus, rechazos, rebotes.
"""
from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import paramiko
    _PARAMIKO_OK = True
except ImportError:
    _PARAMIKO_OK = False


# =============================================================================
# Configuración SSH
# =============================================================================
def _get_ssh_cfg() -> Dict[str, Any]:
    whm_url  = os.getenv("WHM_BASE_URL", "")
    # Derivar host desde WHM_BASE_URL si WHM_SSH_HOST no está definido
    default_host = whm_url.replace("https://", "").replace("http://", "").split(":")[0]
    return {
        "host":     os.getenv("WHM_SSH_HOST", default_host),
        "port":     int(os.getenv("WHM_SSH_PORT", "22")),
        "user":     os.getenv("WHM_SSH_USER", "root"),
        "password": os.getenv("WHM_SSH_PASSWORD", ""),
        "key_file": os.getenv("WHM_SSH_KEY_FILE", ""),
        "timeout":  int(os.getenv("WHM_SSH_TIMEOUT", "30")),
    }


def _connect(cfg: Dict[str, Any]) -> "paramiko.SSHClient":
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kw: Dict[str, Any] = {
        "hostname": cfg["host"],
        "port":     cfg["port"],
        "username": cfg["user"],
        "timeout":  cfg["timeout"],
    }
    if cfg["key_file"] and os.path.exists(cfg["key_file"]):
        kw["key_filename"] = cfg["key_file"]
    elif cfg["password"]:
        kw["password"]       = cfg["password"]
        kw["look_for_keys"]  = False
        kw["allow_agent"]    = False
    client.connect(**kw)
    return client


def _run(client: "paramiko.SSHClient", cmd: str, timeout: int = 60) -> str:
    _, stdout, _ = client.exec_command(cmd, timeout=timeout)
    return stdout.read().decode("utf-8", errors="replace")


# =============================================================================
# Parser de líneas Exim mainlog
# =============================================================================
_RE_TIMESTAMP   = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})')
_RE_MSG_ID      = re.compile(r'\s([A-Za-z0-9]{6}-[A-Za-z0-9]{6}-[A-Za-z0-9]{2})\s')
_RE_ACCEPTED    = re.compile(r' <= (\S+).*?H=(\S+)\s+\[([^\]]+)\].*?S=(\d+)')
_RE_DELIVERED   = re.compile(r' => (\S+)')
_RE_BOUNCE      = re.compile(r' \*\* (\S+)')
_RE_REMOTE_IP   = re.compile(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]')
_RE_SENDER_FROM = re.compile(r'F=<([^>]*)>')
_RE_SPAM_SCORE  = re.compile(r'(?:score|SA)[:\s]+([\d.]+)', re.IGNORECASE)
_RE_SIZE        = re.compile(r'S=(\d+)')


def _parse_line(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line:
        return None

    ts_m = _RE_TIMESTAMP.match(line)
    event_time = None
    if ts_m:
        try:
            event_time = datetime.strptime(ts_m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            pass

    event_type    = None
    sender        = None
    recipient     = None
    remote_host   = None
    remote_ip     = None
    spam_score    = None
    reject_reason = None
    size_bytes    = None

    if " <= " in line:
        event_type = "accepted"
        m = _RE_ACCEPTED.search(line)
        if m:
            sender, remote_host, remote_ip = m.group(1), m.group(2), m.group(3)
            size_bytes = int(m.group(4))

    elif " => " in line:
        event_type = "delivered"
        m = _RE_DELIVERED.search(line)
        if m:
            recipient = m.group(1)

    elif " ** " in line:
        event_type = "bounce"
        m = _RE_BOUNCE.search(line)
        if m:
            recipient = m.group(1)

    elif re.search(r'(?i)virus|clamav|infected', line):
        event_type = "virus"
        reject_reason = line[20:300]

    elif re.search(r'(?i)spam score|X-Spam-Score|SA spam', line):
        event_type = "spam"
        m = _RE_SPAM_SCORE.search(line)
        if m:
            try:
                spam_score = float(m.group(1))
            except ValueError:
                pass

    elif "rejected" in line.lower():
        event_type = "connection_rejected" if re.search(r'SMTP (call|connection) from', line) else "rejected"
        idx = line.lower().find("rejected")
        reject_reason = line[idx:idx + 250].strip()

    else:
        return None

    # Completar campos faltantes
    if not remote_ip:
        m = _RE_REMOTE_IP.search(line)
        if m:
            remote_ip = m.group(1)
    if not sender:
        m = _RE_SENDER_FROM.search(line)
        if m:
            sender = m.group(1)
    if not size_bytes:
        m = _RE_SIZE.search(line)
        if m:
            size_bytes = int(m.group(1))

    msg_m = _RE_MSG_ID.search(line)

    line_hash = hashlib.sha256(line.encode()).hexdigest()

    return {
        "event_time":     event_time,
        "event_type":     event_type,
        "message_id":     msg_m.group(1) if msg_m else None,
        "sender":         sender[:200] if sender else None,
        "recipient":      recipient[:200] if recipient else None,
        "remote_host":    remote_host[:200] if remote_host else None,
        "remote_ip":      remote_ip,
        "spam_score":     spam_score,
        "reject_reason":  reject_reason[:300] if reject_reason else None,
        "size_bytes":     size_bytes,
        "line_hash":      line_hash,
        "raw":            line[:500],
    }


# =============================================================================
# Entry point
# =============================================================================
def extract_logs(lines: int = 20000, **kwargs) -> Dict[str, Any]:
    if not _PARAMIKO_OK:
        raise ImportError("Instala paramiko: pip install paramiko")

    cfg = _get_ssh_cfg()
    if not cfg["host"]:
        raise EnvironmentError("WHM_SSH_HOST (o WHM_BASE_URL) no configurado en .env")
    if not cfg["password"] and not cfg["key_file"]:
        raise EnvironmentError("WHM_SSH_PASSWORD o WHM_SSH_KEY_FILE no configurados en .env")

    data: Dict[str, Any] = {
        "mode":        "logs",
        "server_host": cfg["host"],
        "events":      [],
        "queue_count": None,
        "errors":      [],
    }

    client = None
    try:
        client = _connect(cfg)

        # Leer últimas N líneas del mainlog (probar ambas rutas)
        raw_log = _run(
            client,
            f"tail -n {lines} /var/log/exim_mainlog 2>/dev/null"
            f" || tail -n {lines} /var/log/exim/mainlog 2>/dev/null",
        )

        events: List[Dict[str, Any]] = []
        for line in raw_log.splitlines():
            ev = _parse_line(line)
            if ev:
                events.append(ev)
        data["events"] = events

        # Cola de correo actual
        try:
            q = _run(client, "exim -bpn 2>/dev/null | wc -l", timeout=15).strip()
            data["queue_count"] = int(q)
        except Exception:
            pass

    except Exception as exc:
        data["errors"].append({"section": "ssh", "error": str(exc)})
    finally:
        if client:
            try:
                client.close()
            except Exception:
                pass

    return data

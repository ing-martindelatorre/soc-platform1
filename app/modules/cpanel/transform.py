"""
app/modules/cpanel/transform.py

Transformador de datos de WHM/cPanel.
Normaliza las respuestas de la API para el loader.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


def _safe_float(value: Any) -> Optional[float]:
    try:
        return float(value) if value not in (None, "", "N/A") else None
    except (TypeError, ValueError):
        return None


def _safe_int(value: Any) -> Optional[int]:
    try:
        return int(value) if value not in (None, "", "N/A") else None
    except (TypeError, ValueError):
        return None


# =============================================================================
# STATS
# =============================================================================
def transform_stats(data: Dict[str, Any]) -> Dict[str, Any]:
    sections = data.get("sections", {})

    # /json-api/loadavg → {"one": "0.04", "five": "0.06", "fifteen": "0.05"}
    load = sections.get("loadavg", {})

    # /json-api/version con api.version=1 → {"data": {"version": "..."}}
    version_raw = sections.get("version", {})
    version = (version_raw.get("data") or version_raw).get("version")

    # /json-api/gethostname → {"data": {"hostname": "..."}}
    hostname_raw = sections.get("hostname", {})
    hostname = (hostname_raw.get("data") or hostname_raw).get("hostname")

    # /json-api/showbw → {"data": {"totalused": ..., "acct": [...]}}
    bw_raw  = sections.get("bandwidth", {})
    bw_data = bw_raw.get("data") or bw_raw
    bw_total_bytes = _safe_int(bw_data.get("totalused"))
    bw_accts = bw_data.get("acct") or []
    top_bw = sorted(
        [{"user": a.get("user"), "domain": a.get("maindomain"), "bytes": _safe_int(a.get("totalbytes"))}
         for a in bw_accts],
        key=lambda x: x.get("bytes") or 0, reverse=True
    )[:5]

    return {
        "mode":         "stats",
        "server_host":  data.get("server_host"),
        "hostname":     hostname,
        "version":      version,
        "mail_queue":   None,
        "cpu_load_1":   _safe_float(load.get("one")),
        "cpu_load_5":   _safe_float(load.get("five")),
        "cpu_load_15":  _safe_float(load.get("fifteen")),
        "memory_total": None,
        "memory_used":  None,
        "memory_free":  None,
        "disk_used_pct": None,
        "errors":       data.get("errors", []),
        "raw":          sections,
        "summary": {
            "hostname":        hostname,
            "version":         version,
            "cpu_load_1":      load.get("one"),
            "cpu_load_5":      load.get("five"),
            "cpu_load_15":     load.get("fifteen"),
            "bw_total_gb":     round(bw_total_bytes / 1_073_741_824, 2) if bw_total_bytes else None,
            "top_bw_users":    top_bw,
            "errors_count":    len(data.get("errors", [])),
        },
    }


# =============================================================================
# SECURITY
# =============================================================================
def transform_security(data: Dict[str, Any]) -> Dict[str, Any]:
    sections = data.get("sections", {})
    events: List[Dict[str, Any]] = []

    # Cuentas suspendidas → cada una es un evento de seguridad
    suspended_raw  = sections.get("suspended", {})
    suspended_data = suspended_raw.get("data") or suspended_raw
    suspended_list = suspended_data.get("account") or []
    for acct in suspended_list:
        user = acct if isinstance(acct, str) else acct.get("user", str(acct))
        events.append({
            "ip":            None,
            "username":      user,
            "service":       "cpanel_account",
            "attempts":      None,
            "blocked":       True,
            "blocked_until": None,
            "payload":       acct if isinstance(acct, dict) else {"user": acct},
        })

    # Estado de configuración de Exim
    exim_raw  = sections.get("exim_check", {})
    exim_data = exim_raw.get("data") or exim_raw
    exim_ok   = exim_data.get("message") is None

    return {
        "mode":        "security",
        "server_host": data.get("server_host"),
        "events":      events,
        "exim_config_ok": exim_ok,
        "exim_message":   exim_data.get("message"),
        "errors":      data.get("errors", []),
        "summary": {
            "suspended_accounts": len(suspended_list),
            "exim_config_ok":     exim_ok,
            "exim_message":       exim_data.get("message"),
            "errors_count":       len(data.get("errors", [])),
        },
    }


# =============================================================================
# ACCOUNTS
# =============================================================================
def transform_accounts(data: Dict[str, Any]) -> Dict[str, Any]:
    sections = data.get("sections", {})
    accts_raw = sections.get("accounts", {})

    # WHM listaccts devuelve los datos directamente en acct (sin api.version=1)
    acct_list = accts_raw.get("acct") or []

    accounts: List[Dict[str, Any]] = []
    for acct in acct_list:
        # disk usage viene como "123 M" o como número en MB
        disk_used_raw  = acct.get("diskused", "")
        disk_limit_raw = acct.get("disklimit", "")

        def _parse_mb(val: Any) -> Optional[float]:
            if val in (None, "", "unlimited", "0"):
                return None
            try:
                return float(str(val).replace("M", "").strip())
            except ValueError:
                return None

        accounts.append({
            "username":     acct.get("user"),
            "domain":       acct.get("domain"),
            "plan":         acct.get("plan"),
            "suspended":    str(acct.get("suspended", "0")) not in ("0", "false", ""),
            "disk_used_mb": _parse_mb(disk_used_raw),
            "disk_limit_mb": _parse_mb(disk_limit_raw),
            "payload":      acct,
        })

    # acctcounts → {"data": {"reseller": {"active": N, "suspended": N}}}
    counts_raw = sections.get("acctcounts", {})
    counts     = (counts_raw.get("data") or counts_raw).get("reseller", {})

    return {
        "mode":        "accounts",
        "server_host": data.get("server_host"),
        "accounts":    accounts,
        "errors":      data.get("errors", []),
        "summary": {
            "total_accounts":    len(accounts),
            "suspended_count":   sum(1 for a in accounts if a.get("suspended")),
            "active_reseller":   _safe_int(counts.get("active")),
            "suspended_reseller": _safe_int(counts.get("suspended")),
            "errors_count":      len(data.get("errors", [])),
        },
    }


# =============================================================================
# LOGS (Exim via SSH)
# =============================================================================
def transform_logs(data: Dict[str, Any]) -> Dict[str, Any]:
    from collections import Counter

    events = data.get("events", [])

    counts: Dict[str, int] = {
        "accepted": 0, "delivered": 0, "rejected": 0,
        "spam": 0, "virus": 0, "bounce": 0, "connection_rejected": 0,
    }
    for ev in events:
        et = ev.get("event_type", "")
        if et in counts:
            counts[et] += 1

    rejected_ips = Counter(
        ev.get("remote_ip") for ev in events
        if ev.get("event_type") in ("rejected", "connection_rejected") and ev.get("remote_ip")
    )
    spam_senders = Counter(
        ev.get("sender") for ev in events
        if ev.get("event_type") == "spam" and ev.get("sender")
    )
    virus_senders = Counter(
        ev.get("sender") or ev.get("remote_ip") for ev in events
        if ev.get("event_type") == "virus"
    )

    return {
        "mode":        "logs",
        "server_host": data.get("server_host"),
        "events":      events,
        "queue_count": data.get("queue_count"),
        "errors":      data.get("errors", []),
        "summary": {
            **counts,
            "total":         len(events),
            "queue_count":   data.get("queue_count"),
            "errors_count":  len(data.get("errors", [])),
        },
        "top_rejected_ips":  [{"ip": ip, "count": c} for ip, c in rejected_ips.most_common(20)],
        "top_spam_senders":  [{"sender": s, "count": c} for s, c in spam_senders.most_common(20)],
        "top_virus_senders": [{"sender": s, "count": c} for s, c in virus_senders.most_common(10)],
    }


# =============================================================================
# Entry point
# =============================================================================
def transform(data: Dict[str, Any]) -> Dict[str, Any]:
    mode = data.get("mode", "stats")
    if mode == "security":
        return transform_security(data)
    if mode == "accounts":
        return transform_accounts(data)
    if mode == "logs":
        return transform_logs(data)
    return transform_stats(data)

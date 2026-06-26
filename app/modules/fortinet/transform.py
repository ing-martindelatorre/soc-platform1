"""
app/modules/fortinet/transform.py

Transformador de datos de Fortinet.
Soporta modos: config, logs, threats.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List


def _results(section: Dict[str, Any]) -> List[Dict[str, Any]]:
    results = section.get("results", [])
    return results if isinstance(results, list) else []


def _top_counter(items: List[Dict[str, Any]], key: str, limit: int = 10) -> List[Dict[str, Any]]:
    counter = Counter()
    for item in items:
        value = item.get(key)
        if value not in (None, "", "N/A"):
            counter[str(value)] += 1
    return [{"value": name, "count": count} for name, count in counter.most_common(limit)]


# =============================================================================
# CONFIG
# =============================================================================
def transform_config(data: Dict[str, Any]) -> Dict[str, Any]:
    sections = data.get("sections", {})

    firewall_addresses = _results(sections.get("firewall_addresses", {}))
    firewall_policies  = _results(sections.get("firewall_policies", {}))
    interfaces         = _results(sections.get("interfaces", {}))
    system_admins      = _results(sections.get("system_admins", {}))
    router_static      = _results(sections.get("router_static", {}))

    return {
        "mode":        "config",
        "device_name": data.get("device_name", "fortigate"),
        "meta": data.get("meta", {}),
        "summary": {
            "addresses_count":  len(firewall_addresses),
            "policies_count":   len(firewall_policies),
            "interfaces_count": len(interfaces),
            "admins_count":     len(system_admins),
            "routes_count":     len(router_static),
            "errors_count":     len(data.get("errors", [])),
        },
        "addresses":    firewall_addresses,
        "policies":     firewall_policies,
        "interfaces":   interfaces,
        "admins":       system_admins,
        "routes":       router_static,
        "raw_sections": sections,
        "errors":       data.get("errors", []),
    }


# =============================================================================
# LOGS (legacy)
# =============================================================================
def transform_logs(data: Dict[str, Any]) -> Dict[str, Any]:
    sections     = data.get("sections", {})
    logs_section = sections.get("logs", {})
    log_entries  = _results(logs_section)

    return {
        "mode":        "logs",
        "device_name": data.get("device_name", "fortigate"),
        "meta": data.get("meta", {}),
        "summary": {
            "logs_count":   len(log_entries),
            "errors_count": len(data.get("errors", [])),
            "top_actions":  _top_counter(log_entries, "action", limit=10),
            "top_levels":   _top_counter(log_entries, "level", limit=10),
            "top_subtypes": _top_counter(log_entries, "subtype", limit=10),
            "top_srcip":    _top_counter(log_entries, "srcip", limit=10),
            "top_dstip":    _top_counter(log_entries, "dstip", limit=10),
        },
        "logs":         log_entries,
        "raw_sections": sections,
        "errors":       data.get("errors", []),
    }


# =============================================================================
# THREATS
# =============================================================================

# IPs de países considerados de alto riesgo para alertas
HIGH_RISK_COUNTRIES = {
    "China", "Russia", "Iran", "North Korea", "Belarus",
    "Venezuela", "Cuba", "Myanmar", "Syria",
}

# Apps de alto riesgo
HIGH_RISK_APPS = {
    "BitTorrent", "eMule", "Tor", "VPN", "Proxy",
    "TeamViewer", "AnyDesk", "Kali",
}

# logids conocidos de login fallido en FortiGate
LOGIN_FAIL_LOGIDS = {
    "0100032003",  # Admin login failed
    "0100032002",  # Admin login attempt
    "0100044546",  # SSL VPN login failed
    "0101037130",  # SSH login failed
}

# Categorías de webfilter sospechosas
SUSPICIOUS_WEBFILTER_CATS = {
    "Malware", "Phishing", "Spyware", "Hacking",
    "Botnets", "Spam", "Pornography", "Gambling",
    "Peer-to-Peer", "Proxy Avoidance and Anonymizers",
}


def _classify_traffic(entry: Dict[str, Any]) -> str:
    """Clasifica una entrada de tráfico como normal, sospechosa o bloqueada."""
    action      = (entry.get("action") or "").lower()
    dstcountry  = entry.get("dstcountry", "")
    app         = entry.get("app", "")
    apprisk     = (entry.get("apprisk") or "").lower()

    if action in ("deny", "block", "reset"):
        return "blocked"
    if dstcountry in HIGH_RISK_COUNTRIES:
        return "suspicious"
    if any(h.lower() in (app or "").lower() for h in HIGH_RISK_APPS):
        return "suspicious"
    if apprisk in ("critical", "high"):
        return "suspicious"
    return "normal"


def _classify_event(entry: Dict[str, Any]) -> str:
    """Clasifica un evento de sistema."""
    logid   = str(entry.get("logid") or "")
    logdesc = (entry.get("logdesc") or "").lower()
    msg     = (entry.get("msg") or "").lower()
    level   = (entry.get("level") or "").lower()

    if logid in LOGIN_FAIL_LOGIDS:
        return "login_failure"
    if any(w in logdesc or w in msg for w in ["fail", "error", "attack", "block", "deny"]):
        return "alert"
    if level in ("critical", "alert", "emergency"):
        return "critical"
    if any(w in logdesc or w in msg for w in ["login", "admin", "auth"]):
        return "auth_event"
    return "info"


def _classify_webfilter(entry: Dict[str, Any]) -> str:
    """Clasifica una entrada de webfilter."""
    action  = (entry.get("action") or "").lower()
    catdesc = entry.get("catdesc", "")

    if action in ("block", "blocked", "deny"):
        return "blocked"
    if catdesc in SUSPICIOUS_WEBFILTER_CATS:
        return "suspicious"
    return "allowed"


def transform_threats(data: Dict[str, Any]) -> Dict[str, Any]:
    sections = data.get("sections", {})

    # ── Tráfico forward ──────────────────────────────────────────────────────
    traffic_records = _results(sections.get("traffic_forward", {}))
    traffic_classified = []
    for entry in traffic_records:
        classification = _classify_traffic(entry)
        traffic_classified.append({
            "date":         entry.get("date"),
            "time":         entry.get("time"),
            "srcip":        entry.get("srcip"),
            "srcname":      entry.get("srcname"),
            "dstip":        entry.get("dstip"),
            "dstport":      entry.get("dstport"),
            "dstcountry":   entry.get("dstcountry"),
            "action":       entry.get("action"),
            "app":          entry.get("app"),
            "apprisk":      entry.get("apprisk"),
            "service":      entry.get("service"),
            "policyname":   entry.get("policyname"),
            "sentbyte":     entry.get("sentbyte"),
            "rcvdbyte":     entry.get("rcvdbyte"),
            "classification": classification,
        })

    traffic_summary = {
        "total":      len(traffic_records),
        "blocked":    sum(1 for t in traffic_classified if t["classification"] == "blocked"),
        "suspicious": sum(1 for t in traffic_classified if t["classification"] == "suspicious"),
        "normal":     sum(1 for t in traffic_classified if t["classification"] == "normal"),
        "top_srcip":      _top_counter(traffic_records, "srcip", 10),
        "top_dstcountry": _top_counter(traffic_records, "dstcountry", 10),
        "top_app":        _top_counter(traffic_records, "app", 10),
        "top_action":     _top_counter(traffic_records, "action", 5),
    }

    # ── Eventos de sistema ───────────────────────────────────────────────────
    event_records = _results(sections.get("event_system", {}))
    events_classified = []
    for entry in event_records:
        classification = _classify_event(entry)
        events_classified.append({
            "date":         entry.get("date"),
            "time":         entry.get("time"),
            "logid":        str(entry.get("logid") or ""),
            "logdesc":      entry.get("logdesc"),
            "level":        entry.get("level"),
            "action":       entry.get("action"),
            "msg":          entry.get("msg"),
            "cpu":          entry.get("cpu"),
            "mem":          entry.get("mem"),
            "totalsession": entry.get("totalsession"),
            "classification": classification,
        })

    login_failures = [e for e in events_classified if e["classification"] == "login_failure"]
    auth_events    = [e for e in events_classified if e["classification"] == "auth_event"]
    critical_events = [e for e in events_classified if e["classification"] == "critical"]

    # Stats de performance (última entrada con cpu/mem)
    perf_stats = {}
    for entry in event_records:
        if entry.get("cpu") is not None:
            perf_stats = {
                "cpu":          entry.get("cpu"),
                "mem":          entry.get("mem"),
                "totalsession": entry.get("totalsession"),
                "setuprate":    entry.get("setuprate"),
                "bandwidth":    entry.get("bandwidth"),
                "sysuptime":    entry.get("sysuptime"),
            }
            break

    events_summary = {
        "total":          len(event_records),
        "login_failures": len(login_failures),
        "auth_events":    len(auth_events),
        "critical":       len(critical_events),
        "top_logdesc":    _top_counter(event_records, "logdesc", 10),
        "perf_stats":     perf_stats,
    }

    # ── Webfilter ────────────────────────────────────────────────────────────
    webfilter_records = _results(sections.get("webfilter", {}))
    webfilter_classified = []
    for entry in webfilter_records:
        classification = _classify_webfilter(entry)
        webfilter_classified.append({
            "date":           entry.get("date"),
            "time":           entry.get("time"),
            "srcip":          entry.get("srcip"),
            "dstip":          entry.get("dstip"),
            "hostname":       entry.get("hostname"),
            "url":            entry.get("url"),
            "action":         entry.get("action"),
            "catdesc":        entry.get("catdesc"),
            "profile":        entry.get("profile"),
            "dstcountry":     entry.get("dstcountry"),
            "classification": classification,
        })

    webfilter_summary = {
        "total":      len(webfilter_records),
        "blocked":    sum(1 for w in webfilter_classified if w["classification"] == "blocked"),
        "suspicious": sum(1 for w in webfilter_classified if w["classification"] == "suspicious"),
        "allowed":    sum(1 for w in webfilter_classified if w["classification"] == "allowed"),
        "top_catdesc":  _top_counter(webfilter_records, "catdesc", 10),
        "top_hostname": _top_counter(webfilter_records, "hostname", 10),
        "top_srcip":    _top_counter(webfilter_records, "srcip", 10),
    }

    # ── Antivirus ────────────────────────────────────────────────────────────
    virus_records = _results(sections.get("virus", {}))
    virus_classified = []
    for entry in virus_records:
        action = (entry.get("action") or "").lower()
        classification = "blocked" if action in ("blocked", "block", "deny") else "detected"
        virus_classified.append({
            "date":         entry.get("date"),
            "time":         entry.get("time"),
            "srcip":        entry.get("srcip"),
            "srcname":      entry.get("srcname"),
            "dstip":        entry.get("dstip"),
            "dstport":      entry.get("dstport"),
            "service":      entry.get("service"),
            "action":       entry.get("action"),
            "virus":        entry.get("virus"),
            "filename":     entry.get("filename"),
            "profile":      entry.get("profile"),
            "dtype":        entry.get("dtype"),
            "url":          entry.get("url"),
            "policyname":   entry.get("policyname"),
            "level":        entry.get("level"),
            "msg":          entry.get("msg"),
            "logdesc":      entry.get("logdesc"),
            "classification": classification,
        })

    virus_summary = {
        "total":        len(virus_records),
        "blocked":      sum(1 for v in virus_classified if v["classification"] == "blocked"),
        "detected":     sum(1 for v in virus_classified if v["classification"] == "detected"),
        "top_virus":    _top_counter(virus_records, "virus", 10),
        "top_srcip":    _top_counter(virus_records, "srcip", 10),
        "top_filename": _top_counter(virus_records, "filename", 10),
        "top_dtype":    _top_counter(virus_records, "dtype", 5),
    }

    # ── IPS ──────────────────────────────────────────────────────────────────
    ips_records = _results(sections.get("ips", {}))
    ips_summary = {
        "total":       len(ips_records),
        "top_attack":  _top_counter(ips_records, "attack", 10),
        "top_srcip":   _top_counter(ips_records, "srcip", 10),
        "top_severity": _top_counter(ips_records, "severity", 5),
    }

    # ── VPN ──────────────────────────────────────────────────────────────────
    vpn_records = _results(sections.get("event_vpn", {}))
    vpn_summary = {
        "total":       len(vpn_records),
        "top_action":  _top_counter(vpn_records, "action", 5),
        "top_srcip":   _top_counter(vpn_records, "srcip", 10),
    }

    return {
        "mode":        "threats",
        "device_name": data.get("device_name", "fortigate"),
        "meta": data.get("meta", {}),
        "summary": {
            "total_traffic":        len(traffic_records),
            "blocked_traffic":      traffic_summary["blocked"],
            "suspicious_traffic":   traffic_summary["suspicious"],
            "total_events":         len(event_records),
            "login_failures":       len(login_failures),
            "critical_events":      len(critical_events),
            "total_webfilter":      len(webfilter_records),
            "blocked_webfilter":    webfilter_summary["blocked"],
            "total_ips":            len(ips_records),
            "total_vpn":            len(vpn_records),
            "total_virus":          len(virus_records),
            "blocked_virus":        virus_summary["blocked"],
            "errors_count":         len(data.get("errors", [])),
        },
        "traffic": {
            "summary": traffic_summary,
            "records": traffic_classified,
        },
        "events": {
            "summary":       events_summary,
            "records":       events_classified,
            "login_failures": login_failures,
            "auth_events":   auth_events,
            "critical":      critical_events,
        },
        "webfilter": {
            "summary": webfilter_summary,
            "records": webfilter_classified,
        },
        "ips": {
            "summary": ips_summary,
            "records": ips_records,
        },
        "vpn": {
            "summary": vpn_summary,
            "records": vpn_records,
        },
        "antivirus": {
            "summary": virus_summary,
            "records": virus_classified,
        },
        "errors": data.get("errors", []),
    }


# =============================================================================
# Entry point
# =============================================================================
def transform(data: Dict[str, Any]) -> Dict[str, Any]:
    mode = data.get("mode", "config")
    if mode == "logs":
        return transform_logs(data)
    if mode == "threats":
        return transform_threats(data)
    return transform_config(data)

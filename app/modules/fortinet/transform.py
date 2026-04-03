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


def transform_config(data: Dict[str, Any]) -> Dict[str, Any]:
    sections = data.get("sections", {})

    firewall_addresses = _results(sections.get("firewall_addresses", {}))
    firewall_policies = _results(sections.get("firewall_policies", {}))
    interfaces = _results(sections.get("interfaces", {}))
    system_admins = _results(sections.get("system_admins", {}))
    router_static = _results(sections.get("router_static", {}))

    return {
        "mode": "config",
        "meta": data.get("meta", {}),
        "summary": {
            "addresses_count": len(firewall_addresses),
            "policies_count": len(firewall_policies),
            "interfaces_count": len(interfaces),
            "admins_count": len(system_admins),
            "routes_count": len(router_static),
            "errors_count": len(data.get("errors", [])),
        },
        "addresses": firewall_addresses,
        "policies": firewall_policies,
        "interfaces": interfaces,
        "admins": system_admins,
        "routes": router_static,
        "raw_sections": sections,
        "errors": data.get("errors", []),
    }


def transform_logs(data: Dict[str, Any]) -> Dict[str, Any]:
    sections = data.get("sections", {})
    logs_section = sections.get("logs", {})
    log_entries = _results(logs_section)

    return {
        "mode": "logs",
        "meta": data.get("meta", {}),
        "summary": {
            "logs_count": len(log_entries),
            "errors_count": len(data.get("errors", [])),
            "top_actions": _top_counter(log_entries, "action", limit=10),
            "top_levels": _top_counter(log_entries, "level", limit=10),
            "top_subtypes": _top_counter(log_entries, "subtype", limit=10),
            "top_srcip": _top_counter(log_entries, "srcip", limit=10),
            "top_dstip": _top_counter(log_entries, "dstip", limit=10),
        },
        "logs": log_entries,
        "raw_sections": sections,
        "errors": data.get("errors", []),
    }


def transform(data: Dict[str, Any]) -> Dict[str, Any]:
    mode = data.get("mode", "config")

    if mode == "logs":
        return transform_logs(data)

    return transform_config(data)
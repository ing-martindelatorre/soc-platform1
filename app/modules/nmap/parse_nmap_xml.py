# app/modules/nmap/parse_nmap_xml.py

import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


def get_text_attr(element: ET.Element | None, attr: str, default: str = "") -> str:
    if element is None:
        return default
    return element.attrib.get(attr, default)


def parse_scripts(port_el: ET.Element) -> list[dict[str, Any]]:
    scripts = []
    for script in port_el.findall("script"):
        scripts.append({
            "id": script.attrib.get("id", ""),
            "output": script.attrib.get("output", ""),
            "elements": [
                {
                    "key": elem.attrib.get("key", ""),
                    "text": elem.text or ""
                }
                for elem in script.findall("elem")
            ]
        })
    return scripts


def parse_hostscripts(host_el: ET.Element) -> list[dict[str, Any]]:
    scripts = []
    hostscript = host_el.find("hostscript")
    if hostscript is None:
        return scripts

    for script in hostscript.findall("script"):
        scripts.append({
            "id": script.attrib.get("id", ""),
            "output": script.attrib.get("output", ""),
            "elements": [
                {
                    "key": elem.attrib.get("key", ""),
                    "text": elem.text or ""
                }
                for elem in script.findall("elem")
            ]
        })
    return scripts


def parse_ports(host_el: ET.Element) -> list[dict[str, Any]]:
    ports_out = []
    ports = host_el.find("ports")
    if ports is None:
        return ports_out

    for port in ports.findall("port"):
        state_el = port.find("state")
        service_el = port.find("service")

        ports_out.append({
            "port": int(port.attrib.get("portid", "0")),
            "protocol": port.attrib.get("protocol", ""),
            "state": get_text_attr(state_el, "state"),
            "reason": get_text_attr(state_el, "reason"),
            "service_name": get_text_attr(service_el, "name"),
            "product": get_text_attr(service_el, "product"),
            "version": get_text_attr(service_el, "version"),
            "extrainfo": get_text_attr(service_el, "extrainfo"),
            "ostype": get_text_attr(service_el, "ostype"),
            "method": get_text_attr(service_el, "method"),
            "conf": get_text_attr(service_el, "conf"),
            "scripts": parse_scripts(port),
        })

    return ports_out


def parse_addresses(host_el: ET.Element) -> dict[str, str]:
    out = {}
    for addr in host_el.findall("address"):
        addrtype = addr.attrib.get("addrtype", "unknown")
        out[addrtype] = addr.attrib.get("addr", "")
    return out


def parse_hostnames(host_el: ET.Element) -> list[str]:
    names = []
    hostnames_el = host_el.find("hostnames")
    if hostnames_el is None:
        return names

    for hn in hostnames_el.findall("hostname"):
        name = hn.attrib.get("name")
        if name:
            names.append(name)
    return names


def parse_os(host_el: ET.Element) -> dict[str, Any]:
    os_el = host_el.find("os")
    if os_el is None:
        return {}

    matches = []
    for osmatch in os_el.findall("osmatch"):
        matches.append({
            "name": osmatch.attrib.get("name", ""),
            "accuracy": osmatch.attrib.get("accuracy", ""),
            "line": osmatch.attrib.get("line", ""),
        })

    return {
        "matches": matches,
        "best_guess": matches[0] if matches else {},
    }


def parse_xml(xml_path: Path) -> dict[str, Any]:
    tree = ET.parse(xml_path)
    root = tree.getroot()

    output: dict[str, Any] = {
        "scanner": root.attrib.get("scanner", ""),
        "args": root.attrib.get("args", ""),
        "start": root.attrib.get("start", ""),
        "startstr": root.attrib.get("startstr", ""),
        "version": root.attrib.get("version", ""),
        "xmloutputversion": root.attrib.get("xmloutputversion", ""),
        "hosts": [],
        "runstats": {},
    }

    for host in root.findall("host"):
        status_el = host.find("status")

        host_data = {
            "status": get_text_attr(status_el, "state"),
            "reason": get_text_attr(status_el, "reason"),
            "addresses": parse_addresses(host),
            "hostnames": parse_hostnames(host),
            "os": parse_os(host),
            "ports": parse_ports(host),
            "hostscripts": parse_hostscripts(host),
        }

        output["hosts"].append(host_data)

    runstats = root.find("runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        hosts = runstats.find("hosts")
        output["runstats"] = {
            "finished_time": finished.attrib.get("time", "") if finished is not None else "",
            "summary": finished.attrib.get("summary", "") if finished is not None else "",
            "elapsed": finished.attrib.get("elapsed", "") if finished is not None else "",
            "hosts_up": hosts.attrib.get("up", "") if hosts is not None else "",
            "hosts_down": hosts.attrib.get("down", "") if hosts is not None else "",
            "hosts_total": hosts.attrib.get("total", "") if hosts is not None else "",
        }

    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Parsea XML de Nmap a JSON normalizado.")
    parser.add_argument("--xml", required=True, help="Ruta al XML de Nmap")
    parser.add_argument("--out", required=True, help="Ruta al JSON de salida")
    args = parser.parse_args()

    xml_path = Path(args.xml)
    out_path = Path(args.out)

    data = parse_xml(xml_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[OK] JSON generado en: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
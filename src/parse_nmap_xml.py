#!/usr/bin/env python3
import argparse
import json
import os
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, Any, List, Optional


# Simple risk model: tune later
HIGH_RISK_PORTS = {21, 23, 445, 3389}          # FTP, Telnet, SMB, RDP (often risky if exposed)
MEDIUM_RISK_PORTS = {22, 80, 8080, 5900}       # SSH/HTTP/VNC-ish
LOW_RISK_PORTS = {443}                         # HTTPS (still depends on config)

HIGH_RISK_SERVICES = {"telnet", "ftp", "microsoft-ds", "ms-wbt-server"}
MEDIUM_RISK_SERVICES = {"ssh", "http"}
LOW_RISK_SERVICES = {"https"}


def risk_label(level: str) -> str:
    level = level.upper()
    if level == "HIGH":
        return "[HIGH RISK]"
    if level == "MEDIUM":
        return "[MEDIUM RISK]"
    return "[LOW RISK]"


def score_port(port: int, service: str) -> str:
    service = (service or "").lower()

    if port in HIGH_RISK_PORTS or service in HIGH_RISK_SERVICES:
        return "HIGH"
    if port in MEDIUM_RISK_PORTS or service in MEDIUM_RISK_SERVICES:
        return "MEDIUM"
    if port in LOW_RISK_PORTS or service in LOW_RISK_SERVICES:
        return "LOW"
    # default
    return "LOW"


def parse_nmap_xml(path: str) -> Dict[str, Any]:
    tree = ET.parse(path)
    root = tree.getroot()

    hosts: List[Dict[str, Any]] = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        addr_el = host.find("address[@addrtype='ipv4']")
        ip = addr_el.get("addr") if addr_el is not None else "unknown"

        hn_el = host.find("hostnames/hostname")
        hostname = hn_el.get("name") if hn_el is not None else None

        port_items: List[Dict[str, Any]] = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                protocol = port_el.get("protocol", "tcp")
                portid = int(port_el.get("portid", "0"))

                state_el = port_el.find("state")
                state = state_el.get("state") if state_el is not None else "unknown"
                if state != "open":
                    continue

                svc_el = port_el.find("service")
                svc_name = svc_el.get("name") if svc_el is not None else ""
                product = svc_el.get("product") if svc_el is not None else None
                version = svc_el.get("version") if svc_el is not None else None

                risk = score_port(portid, svc_name)

                port_items.append({
                    "protocol": protocol,
                    "port": portid,
                    "service": svc_name,
                    "product": product,
                    "version": version,
                    "risk": risk,
                    "label": risk_label(risk),
                })

        # Host overall risk = max of port risks
        overall = "LOW"
        if any(p["risk"] == "HIGH" for p in port_items):
            overall = "HIGH"
        elif any(p["risk"] == "MEDIUM" for p in port_items):
            overall = "MEDIUM"

        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "overall_risk": overall,
            "overall_label": risk_label(overall),
            "open_ports": sorted(port_items, key=lambda x: x["port"]),
        })

    # Summary
    total_hosts = len(hosts)
    high_hosts = sum(1 for h in hosts if h["overall_risk"] == "HIGH")
    med_hosts = sum(1 for h in hosts if h["overall_risk"] == "MEDIUM")

    return {
        "generated_at": datetime.now().isoformat(),
        "source_file": path,
        "summary": {
            "total_hosts": total_hosts,
            "high_risk_hosts": high_hosts,
            "medium_risk_hosts": med_hosts,
            "low_risk_hosts": max(total_hosts - high_hosts - med_hosts, 0),
        },
        "hosts": hosts,
        "risk_model": {
            "high_risk_ports": sorted(list(HIGH_RISK_PORTS)),
            "medium_risk_ports": sorted(list(MEDIUM_RISK_PORTS)),
            "low_risk_ports": sorted(list(LOW_RISK_PORTS)),
            "high_risk_services": sorted(list(HIGH_RISK_SERVICES)),
            "medium_risk_services": sorted(list(MEDIUM_RISK_SERVICES)),
            "low_risk_services": sorted(list(LOW_RISK_SERVICES)),
        }
    }


def write_markdown(report: Dict[str, Any], out_path: str) -> None:
    s = report["summary"]
    lines: List[str] = []
    lines.append("# 🛡️ Nmap Risk Report\n")
    lines.append(f"- Generated: `{report['generated_at']}`")
    lines.append(f"- Source: `{report['source_file']}`\n")

    lines.append("## ✅ Summary\n")
    lines.append(f"- Total hosts: **{s['total_hosts']}**")
    lines.append(f"- High risk hosts: **{s['high_risk_hosts']}**")
    lines.append(f"- Medium risk hosts: **{s['medium_risk_hosts']}**")
    lines.append(f"- Low risk hosts: **{s['low_risk_hosts']}**\n")

    lines.append("## 🧾 Findings by Host\n")
    for h in report["hosts"]:
        hn = f" ({h['hostname']})" if h.get("hostname") else ""
        lines.append(f"### {h['ip']}{hn} — {h['overall_label']}\n")

        if not h["open_ports"]:
            lines.append("_No open ports found in this XML._\n")
            continue

        lines.append("| Port | Proto | Service | Product | Version | Risk |")
        lines.append("|---:|:---:|:---|:---|:---|:---|")
        for p in h["open_ports"]:
            lines.append(
                f"| {p['port']} | {p['protocol']} | {p['service']} | {p.get('product') or ''} | {p.get('version') or ''} | {p['label']} |"
            )
        lines.append("")

    lines.append("## 🧠 Notes\n")
    lines.append("- Risk labels are **heuristic** and intended for learning.")
    lines.append("- Always validate exposure context (internal vs internet-facing) and compensate with controls (firewall, MFA, allow-lists).")
    lines.append("- Only scan systems you own or have explicit permission to test.\n")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main() -> None:
    ap = argparse.ArgumentParser(description="Parse Nmap XML and generate a risk-scored report (JSON + Markdown).")
    ap.add_argument("--xml", required=True, help="Path to an Nmap XML file (e.g., demo/demo_nmap.xml).")
    ap.add_argument("--out-md", default="reports/report.md", help="Markdown output path.")
    ap.add_argument("--out-json", default="reports/report.json", help="JSON output path.")
    args = ap.parse_args()

    if not os.path.exists(args.xml):
        print(f"❌ XML file not found: {args.xml}")
        raise SystemExit(1)

    report = parse_nmap_xml(args.xml)

    os.makedirs(os.path.dirname(args.out_md), exist_ok=True)
    os.makedirs(os.path.dirname(args.out_json), exist_ok=True)

    with open(args.out_json, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    write_markdown(report, args.out_md)

    print("✅ Nmap Risk Report generated")
    print(f"- Markdown: {args.out_md}")
    print(f"- JSON:     {args.out_json}")


if __name__ == "__main__":
    main()


#!/usr/bin/env python3
import os
import re
from typing import Dict, Any, List
import sys

# Allow importing from src/
sys.path.insert(0, os.path.abspath("src"))

from parse_nmap_xml import parse_nmap_xml  # noqa


README_PATH = "README.md"
RISKY_XML = "demo/demo_nmap.xml"
CLEAN_XML = "demo/demo_nmap_clean.xml"

START_MARKER = "<!-- COMPARISON_START -->"
END_MARKER = "<!-- COMPARISON_END -->"


def get_metrics(report: Dict[str, Any]) -> Dict[str, Any]:
    s = report["summary"]
    pr = report.get("port_risk_summary", {})
    top = pr.get("top_high_risk_ports", [])

    return {
        "total_hosts": s["total_hosts"],
        "high_hosts": s["high_risk_hosts"],
        "medium_hosts": s["medium_risk_hosts"],
        "low_hosts": s["low_risk_hosts"],
        "high_ports": pr.get("high_open_ports", 0),
        "medium_ports": pr.get("medium_open_ports", 0),
        "low_ports": pr.get("low_open_ports", 0),
        "top_high_ports": top,
    }


def build_markdown(risky: Dict[str, Any], clean: Dict[str, Any]) -> str:
    r = get_metrics(risky)
    c = get_metrics(clean)

    lines: List[str] = []

    lines.append("")
    lines.append("| Metric | Risky Demo (`demo_nmap.xml`) | Clean Demo (`demo_nmap_clean.xml`) |")
    lines.append("|---|---:|---:|")
    lines.append(f"| Total hosts | {r['total_hosts']} | {c['total_hosts']} |")
    lines.append(f"| High-risk hosts | {r['high_hosts']} | {c['high_hosts']} |")
    lines.append(f"| Medium-risk hosts | {r['medium_hosts']} | {c['medium_hosts']} |")
    lines.append(f"| Low-risk hosts | {r['low_hosts']} | {c['low_hosts']} |")
    lines.append(f"| High-risk open ports (total) | {r['high_ports']} | {c['high_ports']} |")
    lines.append(f"| Medium-risk open ports (total) | {r['medium_ports']} | {c['medium_ports']} |")
    lines.append(f"| Low-risk open ports (total) | {r['low_ports']} | {c['low_ports']} |")
    lines.append("")

    lines.append("### 🔥 Top High-Risk Ports (Risky Demo)")
    if r["top_high_ports"]:
        lines.append("| Port/Proto + Service | Count |")
        lines.append("|---|---:|")
        for item in r["top_high_ports"]:
            lines.append(f"| {item['port_service']} | {item['count']} |")
    else:
        lines.append("_No HIGH-risk ports detected in risky demo._")

    lines.append("")
    lines.append("> Auto-generated from demo XML files using the heuristic risk model.")
    lines.append("")

    return "\n".join(lines)


def replace_between_markers(text: str, start: str, end: str, replacement: str) -> str:
    pattern = re.compile(re.escape(start) + r".*?" + re.escape(end), re.DOTALL)
    new_block = start + replacement + end
    if not pattern.search(text):
        raise RuntimeError("Markers not found in README.md")
    return pattern.sub(new_block, text, count=1)


def main() -> None:
    if not os.path.exists(README_PATH):
        raise SystemExit("❌ README.md not found")
    if not os.path.exists(RISKY_XML):
        raise SystemExit("❌ demo_nmap.xml not found")
    if not os.path.exists(CLEAN_XML):
        raise SystemExit("❌ demo_nmap_clean.xml not found")

    risky_report = parse_nmap_xml(RISKY_XML)
    clean_report = parse_nmap_xml(CLEAN_XML)

    md_block = build_markdown(risky_report, clean_report)

    with open(README_PATH, "r", encoding="utf-8") as f:
        readme = f.read()

    updated = replace_between_markers(readme, START_MARKER, END_MARKER, md_block)

    with open(README_PATH, "w", encoding="utf-8") as f:
        f.write(updated)

    print("✅ README comparison table updated successfully")
    print("Run `git diff` to review changes")


if __name__ == "__main__":
    main()


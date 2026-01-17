# 🛡️ Nmap XML Risk Report (Python)

## 📌 Overview
A lightweight Python tool that parses **Nmap XML output** and generates:
- A **risk-scored** host/port summary
- A clean **Markdown report** (`reports/report.md`) suitable for GitHub
- A structured **JSON report** (`reports/report.json`) for tooling/SOC workflows

> ✅ Includes a safe **demo Nmap XML** so reviewers can run it immediately.

---

## 🔧 Tools Used
- Python 3 (stdlib only)
- Nmap XML format (input)

---

## 📂 Project Structure
```text
nmap-xml-risk-report/
├── README.md
├── requirements.txt
├── demo/
│   └── demo_nmap.xml
├── reports/
│   ├── report.md
│   └── report.json
└── src/
    └── parse_nmap_xml.py


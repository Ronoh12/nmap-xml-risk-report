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

## 🧪 Demo: Clean vs Risky Networks

### Risky demo (includes SMB/RDP/FTP examples)
```bash
python3 src/parse_nmap_xml.py --xml demo/demo_nmap.xml --out-md reports/risky_report.md --out-json reports/risky_report.json

## 📊 Comparison: Clean vs Risky (Auto-generated)

<!-- COMPARISON_START -->
| Metric | Risky Demo (`demo_nmap.xml`) | Clean Demo (`demo_nmap_clean.xml`) |
|---|---:|---:|
| Total hosts | 2 | 2 |
| High-risk hosts | 2 | 0 |
| Medium-risk hosts | 0 | 1 |
| Low-risk hosts | 0 | 1 |
| High-risk open ports (total) | 3 | 0 |
| Medium-risk open ports (total) | 2 | 1 |
| Low-risk open ports (total) | 1 | 2 |

### 🔥 Top High-Risk Ports (Risky Demo)
| Port/Proto + Service | Count |
|---|---:|
| 445/tcp microsoft-ds | 1 |
| 3389/tcp ms-wbt-server | 1 |
| 21/tcp ftp | 1 |

> Auto-generated from demo XML files using the heuristic risk model.
<!-- COMPARISON_END -->

Run:
```bash
python3 src/generate_comparison.py


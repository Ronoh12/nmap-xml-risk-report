# 🛡️ Nmap Risk Report

- Generated: `2026-01-17T20:14:20.652500`
- Source: `demo/demo_nmap.xml`

## ✅ Summary

- Total hosts: **2**
- High risk hosts: **2**
- Medium risk hosts: **0**
- Low risk hosts: **0**

## 🧾 Findings by Host

### 192.168.1.10 (demo-host-1) — [HIGH RISK]

| Port | Proto | Service | Product | Version | Risk |
|---:|:---:|:---|:---|:---|:---|
| 22 | tcp | ssh | OpenSSH | 8.9 | [MEDIUM RISK] |
| 80 | tcp | http | nginx | 1.18 | [MEDIUM RISK] |
| 445 | tcp | microsoft-ds | Samba | 4.15 | [HIGH RISK] |

### 192.168.1.20 (demo-host-2) — [HIGH RISK]

| Port | Proto | Service | Product | Version | Risk |
|---:|:---:|:---|:---|:---|:---|
| 21 | tcp | ftp | vsftpd | 3.0.3 | [HIGH RISK] |
| 443 | tcp | https | Apache httpd | 2.4 | [LOW RISK] |
| 3389 | tcp | ms-wbt-server | Microsoft Terminal Services |  | [HIGH RISK] |

## 🧠 Notes

- Risk labels are **heuristic** and intended for learning.
- Always validate exposure context (internal vs internet-facing) and compensate with controls (firewall, MFA, allow-lists).
- Only scan systems you own or have explicit permission to test.

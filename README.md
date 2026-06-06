# 🔍 Network Traffic Analysis — PCAP Investigation

<div align="center">

![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?style=for-the-badge&logo=wireshark&logoColor=white)
![Snort](https://img.shields.io/badge/Snort-IDS-red?style=for-the-badge)
![Security](https://img.shields.io/badge/Cybersecurity-Portfolio-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Complete-success?style=for-the-badge)

**Real-world malicious PCAP analysis | C2 Detection | Custom Snort Rules | Incident Reports**

</div>

---

## 📌 Project Overview

This project demonstrates hands-on network forensics skills by analyzing real-world malicious network traffic (PCAP files). Using **Wireshark**, I identified active **Command & Control (C2) communication**, a **malware executable download**, and **beaconing behavior** on an infected Windows host.

Custom **Snort IDS rules** were written based on discovered Indicators of Compromise (IOCs), and a professional **incident report** was produced for each investigation — exactly as a SOC Analyst or Incident Responder would do on the job.

---

## 🎯 Skills Demonstrated

| Skill | Details |
|-------|---------|
| **Network Forensics** | Deep packet analysis using Wireshark |
| **Threat Detection** | Identified C2 beaconing, malware download, suspicious HTTP |
| **IOC Extraction** | Extracted IPs, URLs, file hashes, server fingerprints |
| **IDS Rule Writing** | 23 custom Snort rules based on real traffic patterns |
| **Incident Reporting** | Professional SOC-style incident reports with timeline |
| **Malware Analysis** | Identified disguised executable (.audiodg.exe) |

---

## 🗂️ Repository Structure

```
network-traffic-analysis/
│
├── 📄 README.md                              ← You are here
│
├── 📁 pcap-files/
│   └── README.md                             ← Download guide & sources
│
├── 📁 snort-rules/
│   ├── detection-rules.rules                 ← 23 custom Snort detection rules
│   └── README.md                             ← Rules explained line by line
│
├── 📁 incident-reports/
│   ├── IR-001-GSNTPAWQ-C2-Investigation.md  ← Full investigation report
│   └── report-template.md                    ← Reusable report template
│
└── 📁 screenshots/
    ├── README.md                             ← Screenshot index & descriptions
    ├── 01-traffic-overview.png
    ├── 02-protocol-hierarchy.png
    ├── 03-conversations.png
    ├── 04-dns-queries.png
    ├── 05-http-traffic.png
    ├── 06-suspicious-ip.png
    ├── 07-tcp-stream.png
    ├── 08-export-objects.png
    ├── 09-endpoints.png
    └── 10-malicious-url.png
```

---

## 🔬 Investigation Summary — IR-001

> **PCAP:** `2021-09-14.pcap` | **Date:** September 14, 2021 | **Severity:** 🔴 HIGH

### What Was Found

A Windows host named **GSNTPAWQ** (`10.0.0.168`) was actively communicating with a **Command & Control server** at `103.232.55.148`. The malware used Internet Explorer's User-Agent to disguise itself and accessed a full web-based C2 panel. A malicious executable disguised as a legitimate Windows process was downloaded during the session.

### Attack Flow

```
[Infected Host]           [C2 Server: 103.232.55.148]
10.0.0.168
    │
    ├──► GET /service/          ← Initial C2 checkin
    │◄── HTTP 200 OK (C2 panel listing)
    │
    ├──► GET /dashboard/        ← C2 control panel loaded
    │◄── HTTP 200 OK (full web panel)
    │
    └──► GET /service/.audiodg.exe  ← Malware EXE downloaded!
```

### Key Stats

| Metric | Value |
|--------|-------|
| Total Packets | 3,679 |
| C2 Traffic | 2,075 packets (56.4%) |
| C2 Server | 103.232.55.148 (XAMPP/Apache) |
| Malware File | `.audiodg.exe` (disguised as Windows audio process) |
| Attack Duration | ~112 seconds captured |
| Infection Time | Sep 14, 2021 — 14:32:16 UTC |
| EXE Download | Sep 14, 2021 — 14:35:32 UTC |

---

## 🚨 Indicators of Compromise (IOCs)

### Malicious IP
```
103.232.55.148
```

### Malicious URLs
```
http://103.232.55.148/service/
http://103.232.55.148/dashboard/
http://103.232.55.148/service/.audiodg.exe
```

### Victim Host
```
Hostname : GSNTPAWQ
IP       : 10.0.0.168
MAC      : ca:96:8f:b3:0d:dd
OS       : Windows 10 (WOW64)
```

### C2 Server Fingerprint
```
Server   : Apache/2.4.47 (Win64) OpenSSL/1.1.1k PHP/7.3.28
Platform : XAMPP (Windows)
Port     : 80 (HTTP — unencrypted)
```

---

## 🛡️ Snort Rules (Sample)

```snort
# Detect C2 checkin
alert tcp $HOME_NET any -> 103.232.55.148 80 \
(msg:"C2 BEACON IR-001 GET /service/ checkin"; \
flow:established,to_server; content:"GET"; http_method; \
content:"/service/"; http_uri; \
classtype:trojan-activity; sid:2000001; rev:1;)

# Detect malware EXE download
alert tcp $HOME_NET any -> 103.232.55.148 80 \
(msg:"MALWARE IR-001 audiodg.exe download from C2"; \
flow:established,to_server; content:".audiodg.exe"; http_uri; \
classtype:trojan-activity; sid:2000003; rev:1;)
```

> 📄 Full ruleset with 23 rules → [`snort-rules/detection-rules.rules`](snort-rules/detection-rules.rules)

---

## 🛠️ Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| **Wireshark** | 4.x | Packet capture analysis & protocol inspection |
| **Snort** | 2.9+ | Intrusion detection rule writing & testing |
| **tshark** | 4.x | Command-line packet analysis & IOC extraction |
| **Ubuntu Linux** | 22.04 | Analysis environment |

---

## 📸 Screenshots

10 key Wireshark screenshots are included in `/screenshots/` documenting every step of the analysis:

| # | Screenshot | What It Shows |
|---|-----------|---------------|
| 01 | Traffic Overview | Full 3,679 packet capture — C2 IP clearly visible |
| 02 | Protocol Hierarchy | TCP 96.9% dominance — beaconing signature |
| 03 | Conversations | 2,075 packets to single C2 IP — abnormal |
| 04 | DNS Queries | 36 DNS packets — mostly Microsoft, no DGA |
| 05 | HTTP Traffic | GET /service/ and GET /dashboard/ — C2 activity |
| 06 | Suspicious IP Filter | All traffic isolated to 103.232.55.148 |
| 07 | TCP Stream | Raw HTTP showing C2 server headers & response |
| 08 | Export Objects | Files served by C2 including .audiodg.exe |
| 09 | Endpoints | IP endpoint list — C2 server dominates |
| 10 | Malicious URL | GET /dashboard/ with Referer: /service/ |

---

## 📋 How to Reproduce

### Requirements
```
- Wireshark 4.x    → https://www.wireshark.org
- Snort 2.9+       → https://www.snort.org
```

### Steps
```bash
# 1. Download PCAP from malware-traffic-analysis.net
# 2. Open in Wireshark
File → Open → [pcap file]

# 3. Apply filter to see C2 traffic
ip.addr == 103.232.55.148

# 4. Follow TCP stream on any HTTP packet
Right-click → Follow → TCP Stream

# 5. Test Snort rules against PCAP
snort -c /etc/snort/snort.conf -r [pcap] -A console
```

---

## 📚 PCAP Source

All PCAP files used in this project are from:

> 🌐 **[Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/training-exercises.html)**

A free, publicly available resource for security training and practice.

---

## ⚠️ Disclaimer

All PCAP files contain **captured malicious network traffic** — not live malware. This project was conducted in an **isolated analysis environment** for **educational purposes only**. No malicious executables were run.

---

## 👤 Author

**[Your Name]**
SOC Analyst | Cybersecurity Enthusiast | Network Forensics

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat&logo=linkedin)](https://linkedin.com/in/yourprofile)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-black?style=flat&logo=github)](https://github.com/yourusername)

---

<div align="center">
<i>Built as part of a hands-on cybersecurity portfolio — real traffic, real tools, real findings.</i>
</div>

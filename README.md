# 🔍 Network Traffic Analysis — PCAP Investigation

## Malicious Traffic Detection Project

> **Cybersecurity Portfolio Project** | Tools: Wireshark · Snort · Git  
> **Focus:** C2 Communication · Data Exfiltration · Beaconing Detection

---

## 📌 Project Overview

This project demonstrates network traffic analysis skills by investigating real-world malicious PCAP (Packet Capture) files. Each PCAP was analyzed using Wireshark to identify Indicators of Compromise (IOCs), malware communication patterns, and suspicious network behavior. Custom Snort detection rules were written for each threat discovered.

**Skills Demonstrated:**
- Network forensics and packet analysis
- Malware C2 (Command & Control) traffic identification
- Intrusion Detection System (IDS) rule writing with Snort
- Professional incident report writing
- IOC (Indicators of Compromise) extraction

---

## 🗂️ Repository Structure

```
network-traffic-analysis/
│
├── README.md                        ← You are here
│
├── pcap-files/                      ← PCAP samples analyzed
│   └── README.md                    ← Source info & download guide
│
├── snort-rules/                     ← Custom Snort detection rules
│   ├── detection-rules.rules        ← All detection rules
│   └── README.md                    ← Rules explanation
│
├── incident-reports/                ← Detailed analysis reports
│   ├── report-template.md           ← Template used for each report
│   └── [report files per PCAP]      ← Individual investigation reports
│
└── screenshots/                     ← Evidence screenshots from Wireshark
    └── README.md                    ← Screenshot index & descriptions
```

---

## 🛠️ Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| Wireshark | 4.x | Packet capture analysis |
| Snort | 2.9+ | Intrusion detection rules |
| Git | Latest | Version control |
| VS Code | Latest | Report writing & rule editing |

---

## 📂 PCAP Files Analyzed

| # | File | Malware Type | Date | Report |
|---|------|-------------|------|--------|
| 1 | [PCAP name here] | [e.g., Emotet, Ursnif] | [Date] | [Link to report] |
| 2 | [PCAP name here] | [e.g., C2 Beacon] | [Date] | [Link to report] |

> **Source:** All PCAP files are from [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net) — a free, publicly available resource for security training.

---

## 🔎 Key Findings Summary

### Threats Detected:
- **C2 Communication** — Periodic beaconing to external IPs
- **Data Exfiltration** — Unusual outbound data transfers
- **Port Scanning** — Sequential port access patterns
- **DNS Tunneling** — Suspicious DNS query patterns

### IOCs Found:
- Malicious IPs: [to be filled per investigation]
- Malicious Domains: [to be filled per investigation]
- File Hashes: [to be filled per investigation]

---

## 📸 Screenshots

10 key screenshots are included in the `/screenshots/` folder documenting the analysis process. See [screenshots/README.md](screenshots/README.md) for full index.

---

## 📋 Snort Rules

Custom detection rules are located in `/snort-rules/detection-rules.rules`. These rules were written based on IOCs and traffic patterns discovered during analysis.

---

## 📖 How to Reproduce This Analysis

### Prerequisites
```bash
# Install Wireshark
# Download from: https://www.wireshark.org/download.html

# Install Snort
# Download from: https://www.snort.org/downloads
```

### Steps
1. Download PCAP files from Malware-Traffic-Analysis.net
2. Open in Wireshark: `File → Open → [pcap file]`
3. Apply filters to isolate malicious traffic
4. Document IOCs in incident report
5. Write Snort rule based on findings

---

## 👤 Author

**[Your Name]**  
Cybersecurity Enthusiast | SOC Analyst in Training  
📧 [your-email@example.com]  
🔗 [Your LinkedIn URL]  
🐙 [Your GitHub URL]

---

## ⚠️ Disclaimer

All PCAP files used in this project are from controlled training environments. This project is for **educational purposes only**. All malware samples are handled in isolated, offline environments.

---

*This project was created as part of a cybersecurity portfolio to demonstrate network forensics and threat detection skills.*

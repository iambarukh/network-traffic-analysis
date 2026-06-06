#  Network Traffic Analysis — PCAP Investigation


##  Project Overview

This project demonstrates hands-on network forensics skills by analyzing real-world malicious network traffic (PCAP files). Using **Wireshark**, I identified active **Command & Control (C2) communication**, a **malware executable download**, and **beaconing behavior** on an infected Windows host.

Custom **Snort IDS rules** were written based on discovered Indicators of Compromise (IOCs), and a professional **incident report** was produced for each investigation, exactly as a SOC Analyst or Incident Responder would do on the job.

---

##  Skills Demonstrated

| Skill | Details |
|-------|---------|
| **Network Forensics** | Deep packet analysis using Wireshark |
| **Threat Detection** | Identified C2 beaconing, malware download, suspicious HTTP |
| **IOC Extraction** | Extracted IPs, URLs, file hashes, server fingerprints |
| **IDS Rule Writing** | 23 custom Snort rules based on real traffic patterns |
| **Incident Reporting** | Professional SOC-style incident reports with timeline |
| **Malware Analysis** | Identified disguised executable (.audiodg.exe) |

---

##  Repository Structure

```
network-traffic-analysis/
│
├──  README.md                              
│
├──  pcap-files/
│   └── 2021-09-14.pcap
│                      
├──  snort-rules/
│   ├── detection-rules.rules                                            
│
├──  incident-reports/
│   ├── IR-001-GSNTPAWQ-C2-Investigation.md              
│
└──  screenshots/                           
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

##  Investigation Summary — IR-001

> **PCAP:** `2021-09-14.pcap`| **Severity:**  HIGH

### What Was Found

A Windows host named **GSNTPAWQ** (`10.0.0.168`) was actively communicating with a **Command & Control server** at `103.232.55.148`. The malware used Internet Explorer's User-Agent to disguise itself and accessed a full web-based C2 panel. A malicious executable disguised as a legitimate Windows process was downloaded during the session.


---

##  Indicators of Compromise (IOCs)

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

##  Snort Rules 

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

>  Full ruleset with 23 rules → [`snort-rules/detection-rules.rules`](snort-rules/detection-rules.rules)

---

##  Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| **Wireshark** | 4.x | Packet capture analysis & protocol inspection |
| **Snort** | 2.9+ | Intrusion detection rule writing & testing |
| **Ubuntu Linux** | 22.04 | Analysis environment |

---

##  Screenshots

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

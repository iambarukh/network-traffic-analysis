# 🚨 Incident Report IR-001
## C2 Communication & Malware Download — Host GSNTPAWQ

| Field | Details |
|-------|---------|
| **Report ID** | IR-001 |
| **Date of Analysis** | June 06, 2026 |
| **PCAP File** | 1.pcap (2021-09-14.pcap) |
| **Analyst** | [Your Name] |
| **Severity** | 🔴 HIGH |
| **Status** | ✅ Complete |

---

## 1. Executive Summary

On **September 14, 2021 at 14:32:16 UTC**, a Windows host named **GSNTPAWQ** (IP: `10.0.0.168`) was observed making repeated HTTP connections to an external IP address `103.232.55.148`. Investigation revealed this to be a **Command & Control (C2) server** running XAMPP on Windows. The infected machine accessed the C2 panel (`/dashboard/`) and subsequently downloaded a suspicious executable file disguised as a legitimate Windows process (`audiodg.exe`). The total C2 communication lasted approximately **112 seconds**, with **2,075 packets (56.4% of all traffic)** exchanged with the C2 server.

---

## 2. Victim Details

| Field | Value |
|-------|-------|
| **Hostname** | GSNTPAWQ |
| **IP Address** | 10.0.0.168 |
| **MAC Address** | ca:96:8f:b3:0d:dd |
| **Operating System** | Windows 10 (WOW64) |
| **Browser** | Internet Explorer 11 (Trident/7.0) |
| **Network** | 10.0.0.0/24 |
| **Gateway** | 10.0.0.1 |

---

## 3. Timeline of Events

| Time (UTC) | Event | Source | Destination |
|-----------|-------|--------|-------------|
| 14:32:16 | PCAP capture begins — host active on network | 10.0.0.168 | Broadcast |
| 14:32:24 | **First C2 contact** — GET /service/ HTTP/1.1 | 10.0.0.168 | 103.232.55.148 |
| 14:32:24 | C2 server responds — Apache/2.4.47 XAMPP | 103.232.55.148 | 10.0.0.168 |
| 14:32:25 | C2 panel resources loaded — blank.gif, back.gif | 10.0.0.168 | 103.232.55.148 |
| 14:32:25 | favicon.ico loaded from C2 — confirms panel access | 10.0.0.168 | 103.232.55.148 |
| 14:33:53 | **C2 dashboard accessed** — GET /dashboard/ HTTP/1.1 | 10.0.0.168 | 103.232.55.148 |
| 14:33:54 | C2 panel fully loaded — CSS, JS, images downloaded | 10.0.0.168 | 103.232.55.148 |
| 14:35:31 | Bing search query for C2 URL observed (IE autocomplete) | 10.0.0.168 | 13.107.5.80 |
| 14:35:32 | **Malware EXE downloaded** — /service/.audiodg.exe | 10.0.0.168 | 103.232.55.148 |
| 14:35:32 | DNS query for connect.facebook.net (C2 panel resource) | 10.0.0.168 | 8.8.8.8 |
| 14:32–15:52 | Continuous C2 beaconing — multiple reconnections | 10.0.0.168 | 103.232.55.148 |

---

## 4. Indicators of Compromise (IOCs)

### 🌐 Malicious IP Addresses
```
103.232.55.148    # Primary C2 Server (HTTP Port 80)
```

### 🔗 Malicious URLs
```
http://103.232.55.148/service/
http://103.232.55.148/dashboard/
http://103.232.55.148/service/.audiodg.exe
http://103.232.55.148/dashboard/stylesheets/normalize.css
http://103.232.55.148/dashboard/stylesheets/all.css
http://103.232.55.148/dashboard/javascripts/all.js
http://103.232.55.148/dashboard/javascripts/modernizr.js
```

### 🖥️ Malicious File
```
Filename:   .audiodg.exe
Source:     http://103.232.55.148/service/.audiodg.exe
Note:       Disguised as legitimate Windows Audio Device Graph process
            Hidden with leading dot (.) — Unix-style file hiding technique
```

### 📡 C2 Server Fingerprint
```
Server:       Apache/2.4.47 (Win64) OpenSSL/1.1.1k PHP/7.3.28
Framework:    XAMPP (Windows) — bitnami-xampp.png confirmed
Date:         Tue, 14 Sep 2021 14:32:24 GMT
Port:         80 (HTTP — unencrypted)
```

### 🔍 Suspicious User-Agent
```
Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko
Note: Internet Explorer 11 User-Agent — may be malware spoofing browser
```

---

## 5. Attack Analysis

### 5.1 C2 Communication Pattern
The infected host made **15+ separate TCP connections** to `103.232.55.148:80` over the capture period. The pattern shows:
- Initial checkin via `GET /service/`
- Full C2 panel load via `GET /dashboard/`
- Periodic reconnections consistent with **HTTP beaconing**
- **2,075 total packets** exchanged with C2 — 56.4% of all network traffic

### 5.2 Malware Delivery
A suspicious executable was downloaded from the C2 server:
- **Filename:** `.audiodg.exe` (note the leading dot)
- **Disguise technique:** `audiodg.exe` is a legitimate Windows system process (Audio Device Graph Isolator). The malware uses an almost identical name to avoid suspicion.
- **Hiding technique:** The leading dot (`.audiodg.exe`) is a Unix/Linux convention for hiding files — unusual on Windows, suggests attacker has Linux background or is attempting to hide the file.

### 5.3 C2 Infrastructure
The C2 server is running **XAMPP** — a free Apache/PHP/MySQL stack typically used for local development, not production servers. This suggests:
- An **amateur or low-budget threat actor**
- Server may be a **compromised home PC or VPS**
- Easy to set up and tear down quickly

### 5.4 Network Traffic Profile
```
Total Packets:        3,679
C2 Traffic:          2,075 packets (56.4%)
DNS Packets:         36 (1.0%)
HTTP Packets:        86 (2.3%)
TCP (other):         3,566 packets (96.9%)
```

---

## 6. Snort Rules Written

```snort
# Rule 1: Detect C2 checkin via /service/ path
alert tcp $HOME_NET any -> 103.232.55.148 80 \
(msg:"C2 BEACON IR-001 GET /service/ checkin"; \
flow:established,to_server; \
content:"GET"; http_method; \
content:"/service/"; http_uri; \
classtype:trojan-activity; sid:2000001; rev:1;)

# Rule 2: Detect C2 dashboard access
alert tcp $HOME_NET any -> 103.232.55.148 80 \
(msg:"C2 PANEL IR-001 Dashboard accessed"; \
flow:established,to_server; \
content:"GET"; http_method; \
content:"/dashboard/"; http_uri; \
classtype:trojan-activity; sid:2000002; rev:1;)

# Rule 3: Detect malware EXE download
alert tcp $HOME_NET any -> 103.232.55.148 80 \
(msg:"MALWARE IR-001 audiodg.exe download from C2"; \
flow:established,to_server; \
content:"GET"; http_method; \
content:".audiodg.exe"; http_uri; \
classtype:trojan-activity; sid:2000003; rev:1;)

# Rule 4: Detect XAMPP C2 server response
alert tcp 103.232.55.148 80 -> $HOME_NET any \
(msg:"C2 SERVER IR-001 XAMPP Apache response"; \
flow:established,to_client; \
content:"Apache/2.4.47 (Win64)"; http_header; \
classtype:trojan-activity; sid:2000004; rev:1;)
```

---

## 7. Screenshots Evidence

| # | Filename | What It Shows |
|---|----------|---------------|
| 01 | 01-traffic-overview.png | Full packet list — 3,679 packets, C2 IP visible |
| 02 | 02-protocol-hierarchy.png | TCP 96.9%, DNS 1.0% — C2 beaconing pattern |
| 03 | 03-conversations.png | 2,075 packets to 103.232.55.148 — dominant connection |
| 04 | 04-dns-queries.png | 36 DNS queries — mostly Microsoft, no malicious domains |
| 05 | 05-http-traffic.png | GET /service/ and GET /dashboard/ — C2 activity |
| 06 | 06-suspicious-ip.png | Filtered view of all C2 traffic (56.4% of capture) |
| 07 | 07-tcp-stream.png | Raw HTTP stream showing C2 server response headers |
| 08 | 08-export-objects.png | Files served by C2: dashboard, .audiodg.exe, etc. |
| 09 | 09-endpoints.png | All IP endpoints — 103.232.55.148 clearly dominant |
| 10 | 10-malicious-url.png | GET /dashboard/ with Referer: /service/ — confirms flow |

---

## 8. Recommendations

### ⚡ Immediate (Within 24 Hours)
1. **Isolate** host `10.0.0.168` (GSNTPAWQ) from the network immediately
2. **Block** IP `103.232.55.148` at the firewall — all ports
3. **Preserve** the PCAP file as forensic evidence
4. **Investigate** if `.audiodg.exe` was executed on the host
5. **Check** for persistence mechanisms (registry run keys, scheduled tasks)

### 🔧 Short-Term (Within 1 Week)
1. **Reimage** the infected host — do not trust it after EXE download
2. **Scan** all other hosts on 10.0.0.0/24 for similar C2 traffic
3. **Reset** all passwords that may have been accessible on GSNTPAWQ
4. **Deploy** the 4 Snort rules from Section 6 to the network IDS
5. **Check** Windows Event Logs on GSNTPAWQ for process execution

### 🛡️ Long-Term
1. **Implement** web filtering to block direct IP connections (no-domain HTTP)
2. **Enable** full DNS logging to catch future beaconing
3. **Deploy** EDR (Endpoint Detection and Response) on all Windows hosts
4. **Restrict** Internet Explorer usage — severely outdated and exploitable
5. **Segment** network to limit lateral movement if reinfection occurs

---

## 9. Conclusion

The PCAP analysis of host **GSNTPAWQ (10.0.0.168)** confirmed an active C2 infection. The host communicated with a XAMPP-based C2 server at `103.232.55.148` using unencrypted HTTP. The C2 server served a full web panel (`/dashboard/`) and delivered a malicious executable disguised as the Windows system process `audiodg.exe`. The use of a leading dot and legitimate process name suggests deliberate evasion. The threat actor appears to be using off-the-shelf tooling (XAMPP, standard web panel) rather than advanced custom infrastructure.

---

*Report generated as part of Network Traffic Analysis Portfolio Project*
*PCAP Source: 2021-09-14.pcap | Analysis Tool: Wireshark 4.x*

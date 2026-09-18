# Wazuh SIEM Home Lab

A self-built, continuously maintained SOC home lab used to reinforce hands-on SIEM administration, detection engineering, and log-based threat detection outside of day-to-day work — built on **Wazuh** and the **ELK Stack (Elasticsearch, Logstash, Kibana)** running on Linux.

> This repository documents the lab's architecture, configuration, and a simulated incident walkthrough. All IPs, hostnames, and screenshots are sanitized/example values from an isolated personal lab environment — no production or employer data is included.

---

## Table of Contents
- [Overview](#overview)
- [Why I Built This](#why-i-built-this)
- [Architecture](#architecture)
- [Lab Environment](#lab-environment)
- [Setup Summary](#setup-summary)
- [Custom Detection Rules](#custom-detection-rules)
- [Simulated Incident Walkthrough: SSH Brute-Force Detection](#simulated-incident-walkthrough-ssh-brute-force-detection)
- [Simulated Incident Walkthrough: File Integrity Monitoring](#simulated-incident-walkthrough-file-integrity-monitoring)
- [Dashboards Built in Kibana](#dashboards-built-in-kibana)
- [MITRE ATT&CK Coverage Mapping](#mitre-attck-coverage-mapping)
- [Lessons Learned](#lessons-learned)
- [Roadmap](#roadmap)
- [Tools Used](#tools-used)
- [References](#references)

---

## Overview

This lab centralizes log collection, correlation, and alerting across multiple monitored endpoints using Wazuh (the SIEM/XDR layer) with Elasticsearch and Kibana (the ELK stack) as the backend storage and visualization layer. It's actively maintained as a continuous-learning environment — new detection rules, simulated attack scenarios, and dashboard views get added as I encounter new techniques worth understanding hands-on rather than just reading about.

---

## Why I Built This

Working in a 24×7 SOC gives me exposure to how Microsoft Sentinel and Defender for Endpoint operate as a consumer of pre-built detections — but it doesn't give me visibility into how a SIEM is actually configured, tuned, and administered from the ground up. This lab exists to close that gap: to understand log ingestion pipelines, write my own correlation rules from scratch, and see the full path from a raw log line to a fired alert — the same underlying concepts that make platforms like Sentinel work, but built and owned end-to-end by me.

---

## Architecture

```
┌─────────────────────┐        ┌──────────────────────┐        ┌─────────────────────┐
│   Monitored Host(s)  │        │     Wazuh Manager     │        │      ELK Stack       │
│  (Wazuh Agent installed)     │  (Rule processing,    │        │  Elasticsearch       │
│  - Ubuntu Server VM  │──────▶│   decoding, alerting)  │──────▶│  Logstash            │
│  - Windows 10 VM      │       │                       │        │  Kibana (dashboards) │
└─────────────────────┘        └──────────────────────┘        └─────────────────────┘
        │                               │                               │
   Auth logs,                    Custom rules (.xml)              Alert visualization,
   file integrity,                Active response                 log search,
   syscall/process data           triggers                        trend dashboards
```

**Data flow:** Agent collects logs → forwards to Wazuh Manager → Manager decodes and evaluates against rule sets → matched alerts are indexed into Elasticsearch → visualized and searched via Kibana.

---

## Lab Environment

| Component | Details |
|---|---|
| Hypervisor | VirtualBox / [your actual hypervisor] |
| Wazuh Manager | Ubuntu Server 22.04 LTS |
| Monitored Endpoint 1 | Ubuntu Server 22.04 LTS (Wazuh Agent) |
| Monitored Endpoint 2 | Windows 10 (Wazuh Agent) |
| ELK Stack | Elasticsearch + Kibana (bundled with Wazuh's default deployment) |
| Network | Isolated internal virtual network, no exposure to the internet |

---

## Setup Summary

High-level setup steps (see official Wazuh documentation linked in References for full install commands):

1. Deployed a Wazuh Manager (all-in-one Wazuh + Elasticsearch + Kibana install for lab simplicity).
2. Installed Wazuh Agents on both a Linux and a Windows endpoint, registered each against the Manager.
3. Enabled key Wazuh modules: **Log Data Analysis**, **File Integrity Monitoring (FIM)**, **Security Configuration Assessment (SCA)**, and **Active Response**.
4. Verified log ingestion end-to-end by confirming agent connection status (`agent_control -l`) and checking that test events appeared in Kibana's Wazuh dashboard.
5. Began writing and testing custom detection rules against simulated attack scenarios (below).

---

## Custom Detection Rules

### Rule 1: SSH Brute-Force Detection

Extends Wazuh's default SSH decoder with a custom correlation rule that fires after repeated failed login attempts from the same source within a short window.

`rules/local_rules.xml`:
```xml
<group name="local,syslog,sshd,">
  <rule id="100010" level="10" frequency="5" timeframe="120">
    <if_matched_sid>5716</if_matched_sid>
    <same_source_ip />
    <description>SSH brute-force attempt: 5 failed logins from the same source IP within 2 minutes</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
  </rule>
</group>
```
*(Rule ID 5716 is Wazuh's built-in "SSHD authentication failed" rule; this custom rule correlates repeated hits on it.)*

### Rule 2: File Integrity Monitoring — Unauthorized Change to a Critical File

Configured FIM to watch a sensitive directory and alert on any modification.

`ossec.conf` (agent-side FIM config snippet):
```xml
<syscheck>
  <directories check_all="yes" report_changes="yes" realtime="yes">/etc/passwd</directories>
  <directories check_all="yes" report_changes="yes" realtime="yes">/etc/shadow</directories>
</syscheck>
```

`rules/local_rules.xml` addition:
```xml
<rule id="100020" level="12">
  <if_sid>550</if_sid>
  <field name="file">/etc/passwd|/etc/shadow</field>
  <description>Critical system file modified: possible privilege escalation or persistence attempt</description>
  <mitre>
    <id>T1098</id>
  </mitre>
</rule>
```

---

## Simulated Incident Walkthrough: SSH Brute-Force Detection

**Objective:** Validate that Rule 100010 correctly detects and alerts on a simulated brute-force attempt.

**Steps performed:**
1. From a separate attacker VM, ran repeated failed SSH login attempts against the monitored Ubuntu endpoint using incorrect credentials, scripted to hit the threshold within the rule's 2-minute window.
2. Wazuh Manager's log analysis engine processed the incoming `auth.log` entries via the built-in `sshd` decoder.
3. After the 5th failed attempt from the same source IP within 120 seconds, custom Rule 100010 fired.
4. Alert appeared in Kibana's Wazuh alerts dashboard with severity level 10, correctly tagged with MITRE technique T1110.001 (Password Guessing).

**Result:** ✅ Detection confirmed working as designed.

**What I'd improve next:** Add a Wazuh Active Response script to automatically block the offending source IP via `iptables` after the alert fires, closing the loop from detection to containment.

---

## Simulated Incident Walkthrough: File Integrity Monitoring

**Objective:** Validate that Rule 100020 detects unauthorized modification of a sensitive system file.

**Steps performed:**
1. On the monitored Ubuntu endpoint, manually modified `/etc/passwd` to simulate an unauthorized account-related change.
2. Wazuh's `syscheck` module, configured with `realtime="yes"`, detected the change immediately rather than waiting for its default scheduled scan interval.
3. Custom Rule 100020 matched on the modified file path and fired at severity level 12.
4. Alert appeared in Kibana, showing the specific file changed and a diff of what was altered (`report_changes="yes"` captures this).

**Result:** ✅ Detection confirmed working as designed, with real-time alerting rather than delayed batch detection.

---

## Dashboards Built in Kibana

- **Authentication Overview** — failed vs. successful login trends across all monitored endpoints
- **File Integrity Alerts** — timeline of FIM-triggered events, filterable by host and file path
- **Agent Health** — connection status and last-seen heartbeat for all registered agents
- **MITRE ATT&CK Coverage View** — alert volume grouped by mapped technique ID, to visually track which techniques the lab's current rule set actually covers

---

## MITRE ATT&CK Coverage Mapping

| Tactic | Technique | ID | Covered By |
|---|---|---|---|
| Credential Access | Brute Force: Password Guessing | T1110.001 | Rule 100010 |
| Persistence | Account Manipulation | T1098 | Rule 100020 |
| Defense Evasion | File and Directory Permissions Modification | T1222 | FIM baseline (syscheck) |

---

## Lessons Learned

- **Decoders matter as much as rules.** A correlation rule is only as good as the underlying decoder correctly parsing the log format — most of the early troubleshooting time went into confirming logs were being decoded correctly before any custom rule could ever fire.
- **Tuning frequency/timeframe thresholds is a real skill, not a default setting.** Too tight a window misses slow, low-and-slow brute-force attempts; too loose a window generates noisy false positives on hosts with naturally higher failed-login rates.
- **Real-time FIM has a real performance cost.** Watching high-change-frequency directories in realtime mode generates meaningfully more log volume than scheduled scanning — a trade-off worth understanding before applying it broadly in a production-scale deployment.

---

## Roadmap

- [ ] Add Wazuh Active Response to auto-block brute-force source IPs
- [ ] Integrate a threat intel feed (e.g. AbuseIPDB) to auto-enrich alerts with IP reputation
- [ ] Add a simulated web-server log source and build a rule set for common web attack patterns (e.g. SQL injection attempts in access logs)
- [ ] Build a Sigma-to-Wazuh rule conversion reference, extending the same conversion logic already documented in my Sentinel detection-engineering project

---

## Tools Used

- [Wazuh](https://wazuh.com) — SIEM/XDR: log analysis, FIM, SCA, active response
- Elasticsearch + Kibana (ELK Stack) — log storage, search, and visualization
- Linux (Ubuntu Server) — Wazuh Manager and monitored endpoint host OS
- VirtualBox — lab virtualization

---

## References

- [Wazuh Official Documentation](https://documentation.wazuh.com/)
- [Wazuh Ruleset Documentation](https://documentation.wazuh.com/current/user-manual/ruleset/index.html)
- MITRE ATT&CK — [T1110.001: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- MITRE ATT&CK — [T1098: Account Manipulation](https://attack.mitre.org/techniques/T1098/)

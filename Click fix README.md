# Detection Research: ClickFix Social Engineering Attacks

A SOC analyst methodology project examining the **ClickFix** technique — a fast-growing social engineering method where victims are tricked into copying and pasting attacker-supplied commands into the Windows Run dialog or PowerShell themselves, bypassing browser download warnings and traditional file-based detection entirely.

> This write-up documents an investigation **methodology and detection logic** for a named, publicly documented attack technique. Sources are cited throughout; no live malicious infrastructure or organizational data is referenced.

---

## Table of Contents
- [Overview](#overview)
- [Why ClickFix Evades Traditional Defenses](#why-clickfix-evades-traditional-defenses)
- [The Attack Chain](#the-attack-chain)
- [Investigation Workflow](#investigation-workflow)
- [Step 1: Initial Alert Triage](#step-1-initial-alert-triage)
- [Step 2: Delivery Vector Analysis](#step-2-delivery-vector-analysis)
- [Step 3: Clipboard & Command Reconstruction](#step-3-clipboard--command-reconstruction)
- [Step 4: Process Tree Analysis](#step-4-process-tree-analysis)
- [Step 5: Network Traffic Analysis](#step-5-network-traffic-analysis)
- [Step 6: Payload Identification](#step-6-payload-identification)
- [Step 7: IOC Extraction](#step-7-ioc-extraction)
- [Step 8: Disposition & Escalation](#step-8-disposition--escalation)
- [Step 9: Detection Engineering Follow-Up](#step-9-detection-engineering-follow-up)
- [Real-World Campaign Examples](#real-world-campaign-examples)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Tools Used](#tools-used)
- [Analyst Checklist](#analyst-checklist)
- [References](#references)

---

## Overview

ClickFix (also referred to as "ClearFake" in some of its earliest campaigns) is a social engineering technique — not a single piece of malware — that has grown into one of the dominant malware delivery methods observed across email and web-based campaigns since mid-2024. The lure presents a fake human-verification challenge (a CAPTCHA, a "your browser needs an update," or a fake meeting-software error) and instructs the victim to fix the "problem" themselves: press `Win+R`, paste a command already sitting in their clipboard, and press Enter.

Because the victim manually types the keystrokes and the command is copy-pasted rather than downloaded as a file, no browser download warning fires and no SmartScreen prompt appears — the execution looks like ordinary user activity, not an automated attack.

---

## Why ClickFix Evades Traditional Defenses

- **No file download to scan** — the payload often runs directly in memory, or is fetched by a legitimate system binary (PowerShell, `mshta.exe`, `curl`) rather than arriving as an attachment.
- **Email gateways can't block a legitimate-looking URL** — especially when the lure site is a compromised legitimate website rather than attacker-registered infrastructure.
- **The user initiates execution themselves** — EDR products that weight "did a human interact with this" as a trust signal can under-score what is functionally a malicious execution.
- **The visible clipboard text often looks harmless** — e.g. a fake reCAPTCHA verification string — while the actual malicious command is hidden in the same clipboard payload or appended invisibly.

---

## The Attack Chain

```
1. Lure delivered
   (compromised website, malvertising, phishing email/link, fake meeting-software error)
        │
        ▼
2. Fake verification page displayed
   (CAPTCHA clone, "update your browser," "fix the audio/video issue")
        │
        ▼
3. Victim instructed to press Win+R (or open Terminal) and paste
   (JavaScript on the page silently copies a malicious command to the clipboard)
        │
        ▼
4. Victim pastes and presses Enter
   (executes with the victim's own user privileges — no elevation prompt needed)
        │
        ▼
5. Initial command downloads/executes a loader
   (commonly via PowerShell, mshta.exe, or curl — often injected into a LOLBin process)
        │
        ▼
6. Final payload deployed
   (infostealers, RATs, or multi-stage toolkits observed in real campaigns)
```

---

## Investigation Workflow

```
Alert / User Report Received
        │
        ▼
Step 1: Initial Alert Triage
        │
        ▼
Step 2: Delivery Vector Analysis
        │
        ▼
Step 3: Clipboard & Command Reconstruction
        │
        ▼
Step 4: Process Tree Analysis
        │
        ▼
Step 5: Network Traffic Analysis
        │
        ▼
Step 6: Payload Identification
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

- **How was this flagged?** EDR behavioral detection on `powershell.exe`/`mshta.exe` spawned from a user-interactive `Win+R` (RunMRU) action, a user self-report ("I think I ran something I shouldn't have"), or a proxy/web-security alert on the lure page itself
- **User account of events** — did they visit a specific site, see a "verification" or "error" prompt, and follow on-screen instructions to fix it? This is a strong ClickFix indicator even before any technical confirmation
- **Time elapsed since the reported interaction** — as with any click-based compromise, speed matters; the loader-to-final-payload chain can complete in seconds

---

## Step 2: Delivery Vector Analysis

Real campaigns have used all of the following — check browser history and email/message logs accordingly:

- **Compromised legitimate websites** injected with malicious JavaScript that displays the fake verification overlay — the domain itself may have a long-standing good reputation, which is what makes this vector effective
- **Malvertising** — malicious ad networks serving the lure to visitors of unrelated, legitimate sites
- **Email-based delivery** — either a malicious HTML attachment rendering the fake CAPTCHA locally, or a link redirecting to hosted lure infrastructure
- **Fake software/meeting-tool errors** — e.g. a cloned Google Meet page claiming a microphone/camera issue, instructing the "fix" via clipboard-paste

Check whether the referring site is a known-good domain (likely compromised, not attacker-owned) or a freshly registered lookalike — this determines both the takedown/notification path and how the initial detection gap should be framed for follow-up.

---

## Step 3: Clipboard & Command Reconstruction

This is the step unique to ClickFix investigations.

- **Browser history / page source** — if the lure page is still reachable (via sandbox, never directly), inspect its JavaScript for the clipboard-writing function (commonly `navigator.clipboard.writeText()` or an older `execCommand('copy')` call) to recover the exact command that was staged
- **RunMRU registry key** (`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`) — records the exact string typed/pasted into the Windows Run dialog, often recoverable during endpoint forensics even after the fact
- **PowerShell console history / ScriptBlock logging** — if enabled, captures the full command executed, including any obfuscation
- **Visible vs. actual payload mismatch** — the text shown to the victim (e.g. a fake verification code) is frequently different from the actual clipboard content, which may append additional hidden characters or a second command using line-separator tricks

---

## Step 4: Process Tree Analysis

- **Parent process is frequently `explorer.exe`** — because the user manually invoked Run/Terminal themselves, rather than a script or document spawning the shell automatically; this is the key process-tree signature that distinguishes ClickFix from a typical macro-delivered or drive-by attack
- **Common execution binaries observed in real campaigns:** `powershell.exe`, `mshta.exe`, `msbuild.exe`, `regasm.exe`, `curl.exe` — often used specifically because they are trusted LOLBins
- **Injection into legitimate processes** — some observed campaigns hook a DLL into a common Office process (e.g. `excel.exe`) after initial execution, so that subsequent C2 traffic appears to originate from ordinary office application activity rather than the original shell

---

## Step 5: Network Traffic Analysis

Apply the same network investigation depth used for any suspicious outbound connection (see the companion `curl` and phishing-click projects for full methodology):

- **First-stage download** — the initial PowerShell/mshta command typically reaches out to fetch a loader script; check DNS and proxy/firewall logs for the destination
- **C2 beaconing** — once the final payload (infostealer/RAT) is active, look for regular-interval outbound connections
- **Blended C2 traffic** — if process injection into a trusted application occurred (Step 4), the C2 traffic may appear to originate from that trusted process rather than the original shell, so correlate by timestamp and destination rather than by process name alone

---

## Step 6: Payload Identification

Real-world ClickFix campaigns have delivered a wide range of final-stage payloads, so don't assume a single outcome:

- **Infostealers** — designed to harvest browser-saved credentials, cryptocurrency wallet data, and session tokens
- **Remote Access Trojans (RATs)** — providing full interactive attacker access to the compromised endpoint
- **Multi-module toolkits** — some observed campaigns deployed combined capability sets including file encryption, credential/file collection, network/USB scanning, and screen-locking in a single operation

Submit any recovered payload (loader script, downloaded binary) to a sandbox for full dynamic analysis, following the same process documented in this portfolio's dedicated malware-analysis write-up.

---

## Step 7: IOC Extraction

| IOC Type | Field |
|---|---|
| Lure page URL / compromised domain | `[extracted]` |
| Exact clipboard/pasted command | `[extracted]` |
| First-stage download URL | `[extracted]` |
| Final payload hash | `[SHA256]` |
| C2 domain/IP | `[extracted]` |
| Affected user/host | `[extracted]` |

Submit all indicators to threat intel and search the environment for the same RunMRU pattern or process-tree signature (`explorer.exe → powershell.exe/mshta.exe` with no intervening script/document) across other endpoints.

---

## Step 8: Disposition & Escalation

| Disposition | Criteria | Action |
|---|---|---|
| **Benign / Near-miss** | User recognized the lure and did not paste/execute anything | Document for awareness, no technical action needed |
| **Executed, no confirmed payload** | Command ran but loader failed to retrieve a payload (e.g. C2 already taken down) or execution was interrupted | Isolate endpoint pending full review, treat as compromised until proven otherwise |
| **Confirmed Compromise** | Payload confirmed executed (infostealer/RAT identified) | Isolate endpoint immediately, reset all credentials that may have been stored/entered on that device, revoke active sessions, full incident response lifecycle, search environment-wide for the same IOC set |

---

## Step 9: Detection Engineering Follow-Up

**Microsoft Sentinel / Defender Advanced Hunting — explorer.exe directly spawning a scripting engine (core ClickFix signature):**

```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName in~ ("powershell.exe", "mshta.exe", "cmd.exe", "wscript.exe", "cscript.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

**Microsoft Sentinel / Defender Advanced Hunting — RunMRU-style execution followed by outbound network connection within seconds:**

```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName in~ ("powershell.exe", "mshta.exe")
| join kind=inner (DeviceNetworkEvents) on DeviceId
| where (Timestamp1 - Timestamp) between (0s .. 15s)
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, RemoteUrl, RemoteIP
```

**Microsoft Defender for Office 365 — flag known fake-CAPTCHA/ClickFix behavioral signatures on inbound links and HTML attachments**
*(built-in capability in modern Defender for Office 365 — verify the feature is enabled/tuned rather than writing a custom rule for this layer)*

> Tune the parent-process baseline carefully — some legitimate IT-support workflows do instruct users to run commands via Win+R, so pair this detection with destination/context review rather than alerting on the pattern alone.

---

## Real-World Campaign Examples

*(Referenced for pattern awareness — summarized from public threat research, not personally investigated cases)*

- **ClearFake** — one of the earliest documented clusters, using a fake browser-update overlay on compromised WordPress sites to deliver the initial ClickFix lure.
- **StopAndProtect** — a large-scale operation abusing roughly 2,000 compromised WordPress sites, delivering a six-module toolkit (encryption, credential/file collection, network scanning, screen-locking) via a fake verification prompt.
- **Fake Google Meet cluster** — cloned Google Meet pages falsely reporting a microphone/headset problem, instructing victims to "fix" it via clipboard-paste.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Phishing | T1566 |
| Execution | User Execution: Malicious Link | T1204.001 |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Defense Evasion | System Binary Proxy Execution | T1218 |
| Defense Evasion | Process Injection | T1055 |
| Command and Control | Application Layer Protocol | T1071.001 |
| Credential Access | Credentials from Password Stores | T1555 |

---

## Tools Used

- Microsoft Defender for Endpoint — Advanced Hunting, process tree review, RunMRU/registry forensics
- Microsoft Sentinel — KQL detection and cross-host pattern search
- Microsoft Defender for Office 365 — built-in fake-CAPTCHA/ClickFix behavioral signatures
- [ANY.RUN](https://any.run) — safe detonation of recovered lure pages and payloads
- [VirusTotal](https://www.virustotal.com) — domain/IP/hash reputation checks
- Registry viewer / forensic tooling — RunMRU key recovery

---

## Analyst Checklist

- [ ] User's account of the interaction captured (what site, what prompt, what they were told to do)
- [ ] Delivery vector identified (compromised site, malvertising, email, fake software error)
- [ ] Exact pasted/executed command reconstructed (via RunMRU, PowerShell logging, or page source)
- [ ] Process tree reviewed for the explorer.exe → scripting-engine signature
- [ ] Network traffic reviewed for first-stage download and any subsequent C2 beaconing
- [ ] Final payload identified and, if recovered, submitted for sandboxed analysis
- [ ] Full IOC set documented and submitted to threat intel
- [ ] Environment-wide search performed for the same process-tree/IOC pattern
- [ ] Credentials/sessions reset if compromise is confirmed or likely
- [ ] Detection rule created/tuned, and Defender for Office 365 ClickFix signatures confirmed enabled

---

## References

- Microsoft Security Blog — [Think before you Click(Fix): Analyzing the ClickFix social engineering technique](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/)
- SentinelOne — [Caught in the CAPTCHA: How ClickFix is Weaponizing Verification Fatigue](https://www.sentinelone.com/blog/how-clickfix-is-weaponizing-verification-fatigue-to-deliver-rats-infostealers/)
- U.S. HHS HC3 — ClickFix Attacks Sector Alert (TLP:CLEAR)
- MITRE ATT&CK — [T1204.001: User Execution — Malicious Link](https://attack.mitre.org/techniques/T1204/001/)

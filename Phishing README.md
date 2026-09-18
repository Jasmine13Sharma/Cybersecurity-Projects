# Phishing Email Investigation: Header Analysis & SPF/DKIM/DMARC Validation

A SOC analyst methodology project documenting the full investigation workflow for a suspected phishing email — from initial triage through header-level authentication analysis to final disposition and detection engineering follow-up.

> This repository documents an investigation **methodology and toolset**, illustrated with a sanitized/synthetic email header. No real organizational data, real sender information, or actual malicious payloads are included.

---

## Table of Contents
- [Overview](#overview)
- [Why Header Analysis Matters](#why-header-analysis-matters)
- [Investigation Workflow](#investigation-workflow)
- [Step 1: Initial Triage](#step-1-initial-triage)
- [Step 2: Header Extraction](#step-2-header-extraction)
- [Step 3: SPF Validation](#step-3-spf-validation)
- [Step 4: DKIM Validation](#step-4-dkim-validation)
- [Step 5: DMARC Validation](#step-5-dmarc-validation)
- [Step 6: Additional Header Red Flags](#step-6-additional-header-red-flags)
- [Step 7: URL & Attachment Analysis](#step-7-url--attachment-analysis)
- [Step 8: IOC Extraction](#step-8-ioc-extraction)
- [Step 9: Disposition & Escalation](#step-9-disposition--escalation)
- [Step 10: Detection Engineering Follow-Up](#step-10-detection-engineering-follow-up)
- [Sample Header Walkthrough](#sample-header-walkthrough)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Tools Used](#tools-used)
- [Analyst Checklist](#analyst-checklist)
- [References](#references)

---

## Overview

Phishing remains one of the highest-volume alert categories in any 24×7 SOC. Most phishing triage decisions come down to one core question: **did this email actually originate from where it claims to?** Email header analysis — specifically SPF, DKIM, and DMARC validation — is the fastest, most reliable way to answer that question before ever touching a link or attachment.

This project documents a repeatable, structured process for investigating a reported or flagged phishing email, from the moment it lands in the SOC queue to final closure and any resulting detection tuning.

---

## Why Header Analysis Matters

- **Body content is easy to fake; headers are harder.** Attackers can copy a brand's logo and wording perfectly, but spoofing the technical delivery path leaves detectable traces.
- **Authentication results tell you what the receiving mail server actually verified** — not what the sender claims. This is ground truth, not appearance.
- **It's fast.** A header review takes minutes and often resolves the case without needing to detonate a link or attachment in a sandbox.

---

## Investigation Workflow

```
Alert/Report Received
        │
        ▼
Step 1: Initial Triage (sender, subject, urgency cues)
        │
        ▼
Step 2: Extract Full Headers
        │
        ▼
Step 3-5: SPF / DKIM / DMARC Validation
        │
        ▼
Step 6: Additional Header Red Flags
        │
        ▼
Step 7: URL & Attachment Analysis (sandboxed)
        │
        ▼
Step 8: IOC Extraction
        │
        ▼
Step 9: Disposition (Benign / Suspicious / Malicious) + Escalation
        │
        ▼
Step 10: Detection Tuning / Rule Update
```

---

## Step 1: Initial Triage

Before diving into headers, capture the basics:

- **Reported by:** end user, automated detection (e.g. Abnormal AI, Proofpoint), or SOC monitoring queue
- **Sender display name vs. actual email address** — mismatches here are one of the most common and easiest red flags (e.g. "Microsoft Support" from a Gmail address)
- **Subject line urgency cues** — "Action Required," "Account Suspended," "Invoice Overdue," password reset lures
- **Recipient(s)** — single targeted user (possible spear-phishing) vs. mass distribution (commodity campaign)

---

## Step 2: Header Extraction

Pull the **full raw header**, not just the summary fields shown in the mail client. In most clients:

- Outlook: `File → Properties → Internet Headers`
- Gmail: `Show Original`
- Exported `.eml` file: open in any text editor or a header analyzer tool

The full header contains every mail server hop (`Received:` lines), the authentication results block, sender/return-path fields, and the message ID — all of which are needed for the next steps.

---

## Step 3: SPF Validation

**Sender Policy Framework (SPF)** verifies that the sending mail server is authorized to send on behalf of the claimed domain.

**What to check in the header:**
```
Authentication-Results: mx.recipient.com;
    spf=pass (or fail / softfail / neutral / none) smtp.mailfrom=domain.com
```

| Result | Meaning | Analyst Action |
|---|---|---|
| `pass` | Sending IP is authorized in the domain's SPF record | Not conclusive alone — spoofed lookalike domains can still pass SPF for *their own* domain |
| `fail` | Sending IP is explicitly **not** authorized | Strong phishing indicator |
| `softfail` | Sending IP is not authorized, but the domain's policy is lenient (`~all`) | Treat as suspicious, verify with DKIM/DMARC |
| `neutral` / `none` | No SPF record, or record makes no assertion | Domain has weak/no SPF hygiene — check DMARC policy next |

**Manual verification:** Look up the claimed sending domain's SPF record directly:
```
nslookup -type=txt domain.com
```
Compare the authorized sending IPs/includes against the actual sending IP shown in the header's `Received:` chain.

---

## Step 4: DKIM Validation

**DomainKeys Identified Mail (DKIM)** verifies that the email content wasn't altered in transit and was cryptographically signed by the claimed domain.

**What to check in the header:**
```
Authentication-Results: mx.recipient.com;
    dkim=pass (or fail / none) header.d=domain.com
```

| Result | Meaning | Analyst Action |
|---|---|---|
| `pass` | Signature is valid and matches the signing domain | Good sign, but check that `header.d=` matches the **actual** claimed sender domain, not an unrelated one |
| `fail` | Signature present but invalid (content altered, or signed by wrong key) | Strong phishing/tampering indicator |
| `none` | No DKIM signature present at all | Common for spoofed mail — legitimate senders from major providers almost always sign |

**Key check:** A `dkim=pass` result only proves the signing domain is valid — it does **not** prove the signing domain is the one the user thinks they're talking to. Attackers who own a lookalike domain can generate a valid DKIM pass for *that* domain.

---

## Step 5: DMARC Validation

**Domain-based Message Authentication, Reporting and Conformance (DMARC)** ties SPF and DKIM together and tells receiving servers what to do if both fail — and critically, whether the visible "From:" domain actually matches what SPF/DKIM authenticated (this is called **alignment**).

**What to check in the header:**
```
Authentication-Results: mx.recipient.com;
    dmarc=pass (or fail) action=none/quarantine/reject header.from=domain.com
```

| Result | Meaning | Analyst Action |
|---|---|---|
| `pass` | SPF or DKIM passed **and** was aligned with the visible From: domain | Strong legitimacy signal |
| `fail` | Alignment failed even if SPF/DKIM individually passed | High-confidence spoofing indicator |

**Check the domain's actual DMARC policy:**
```
nslookup -type=txt _dmarc.domain.com
```
A policy of `p=none` means the domain owner isn't enforcing anything — mail can fail DMARC and still get delivered. A policy of `p=reject` or `p=quarantine` means spoofed mail claiming that domain should have been blocked or junked, which is itself worth noting if it still reached the inbox.

---

## Step 6: Additional Header Red Flags

Beyond SPF/DKIM/DMARC, review:

- **Return-Path vs. From address mismatch** — bounces going to a different domain than the visible sender
- **Reply-To header** — a common trick is a legitimate-looking From address but a Reply-To pointed at an attacker-controlled mailbox
- **Received: chain anomalies** — unexpected hops through unrelated countries/providers, or a hop count inconsistent with the claimed sender's normal infrastructure
- **Message-ID domain** — should generally match the sending infrastructure; a mismatch (e.g. claims to be from a bank but Message-ID domain is a free webmail provider) is a red flag
- **X-Mailer / X-Originating-IP headers** — can reveal the actual sending client/infrastructure, sometimes exposing spoofing tools

---

## Step 7: URL & Attachment Analysis

Only after header review, move to content:

- **Never click links directly** — extract URLs from the raw header/body and submit them to a sandboxed URL scanner
- **Hover-text mismatch** — displayed link text vs. actual href destination
- **URL shorteners / redirect chains** — follow (in a sandbox) to the final landing page
- **Attachments** — detonate in an isolated sandbox (e.g. ANY.RUN), never open locally; check file type against the claimed extension (e.g. a `.pdf.exe` double extension)

---

## Step 8: IOC Extraction

Compile every indicator found during the investigation into a structured record:

| IOC Type | Example |
|---|---|
| Sender email address | `[extracted]` |
| Sender IP | `[extracted from Received: chain]` |
| Reply-To address (if different) | `[extracted]` |
| Malicious URL(s) | `[extracted]` |
| Attachment hash (if present) | `[SHA256]` |
| Subject line (for pattern matching future alerts) | `[extracted]` |

These get submitted to threat intel platforms (VirusTotal, internal blocklists) and used to search for other recipients of the same campaign across the mail environment.

---

## Step 9: Disposition & Escalation

| Disposition | Criteria | Action |
|---|---|---|
| **Benign** | SPF/DKIM/DMARC all pass and aligned, no suspicious links/attachments, sender is a known legitimate contact | Close, no further action |
| **Suspicious** | Mixed authentication results, unusual urgency/content but no confirmed malicious payload | Quarantine, monitor sender/domain, no org-wide alert yet |
| **Malicious / Confirmed Phishing** | Authentication failures + malicious link/attachment confirmed via sandbox | Block sender/domain/URL org-wide, search mailboxes for other recipients, notify affected users, escalate per SOP if credentials may have been entered |

For confirmed cases, document: initial detection source, full IOC list, number of recipients, remediation actions taken (mailbox purge, password reset if credentials were entered), and time-to-containment.

---

## Step 10: Detection Engineering Follow-Up

A mature SOC turns every confirmed phishing case into future prevention:

- Update mail-gateway blocklists with sender domain/IP/URL
- Tune SIEM detection rules for the observed pattern (e.g. new lookalike domain family, new subject-line pattern)
- If the campaign bypassed existing email security tooling (e.g. Abnormal AI, Proofpoint), file a detection gap report with the observed evasion technique

**Example Microsoft Sentinel KQL — flagging DMARC failures reaching the inbox:**

```kql
EmailEvents
| where AuthenticationDetails has "dmarc=fail"
| where DeliveryAction == "Delivered"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, AuthenticationDetails
```

**Example KQL — sender display name / domain mismatch pattern:**

```kql
EmailEvents
| where SenderDisplayName has_any ("Microsoft", "Support", "IT Help", "Security Team")
| where SenderFromDomain !contains "yourcompany.com"
| project Timestamp, SenderDisplayName, SenderFromAddress, RecipientEmailAddress, Subject
```

> These are illustrative starting queries — tune against your organization's actual email schema and known-legitimate sender patterns to control false positives.

---

## Sample Header Walkthrough

Below is a **synthetic** authentication-results block used to illustrate the analysis process described above (not a real captured email):

```
Authentication-Results: mx.recipient-corp.com;
    spf=softfail smtp.mailfrom=secure-billing-update.com;
    dkim=none;
    dmarc=fail action=quarantine header.from=paypal.com
```

**Walkthrough:**
1. **From: header** claims `paypal.com` — a well-known brand, high-trust target for spoofing.
2. **SPF softfail** on `secure-billing-update.com` — the actual sending domain is *not* PayPal's domain at all, meaning the visible sender name is likely misrepresenting the true source.
3. **DKIM none** — no cryptographic signature present, which is unusual for a mature domain like PayPal that enforces strict signing.
4. **DMARC fail, action=quarantine** — the receiving server's own policy check confirms misalignment between the claimed `paypal.com` identity and the actual authenticated domain, and recommends quarantine.
5. **Conclusion:** This combination — trusted brand name, unrelated sending domain, no DKIM, DMARC fail — is a textbook spoofing pattern. Disposition: **Malicious**, proceed to Steps 7–10.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Phishing | T1566 |
| Initial Access | Phishing: Spearphishing Link | T1566.002 |
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 |
| Defense Evasion | Impersonation | T1656 |

---

## Tools Used

- Mail client header viewer (Outlook / Gmail "Show Original")
- [MXToolbox Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx) — parses raw headers and authentication results
- `nslookup` / `dig` — manual SPF and DMARC DNS record lookups
- [VirusTotal](https://www.virustotal.com) — URL, domain, and hash reputation checks
- [ANY.RUN](https://any.run) — sandboxed detonation of links/attachments
- Abnormal AI / Proofpoint — automated pre-filtering and initial flagging (organization-dependent)
- Microsoft Sentinel — KQL-based detection tuning and historical alert correlation

---

## Analyst Checklist

- [ ] Full raw header extracted (not summary view)
- [ ] SPF result checked and cross-verified against DNS record
- [ ] DKIM result checked, signing domain matches expected sender
- [ ] DMARC result and alignment checked
- [ ] Return-Path / Reply-To compared against visible From address
- [ ] Received: chain reviewed for anomalous hops
- [ ] URLs extracted and sandbox-scanned (never clicked directly)
- [ ] Attachments detonated in isolated sandbox only
- [ ] Full IOC set documented and submitted to threat intel
- [ ] Disposition assigned and documented with reasoning
- [ ] Other recipients of the same campaign searched org-wide
- [ ] Detection rule created/tuned if this represents a new pattern

---

## References

- [MXToolbox — Email Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx)
- [DMARC.org — How DMARC Works](https://dmarc.org/overview/)
- MITRE ATT&CK — [T1566: Phishing](https://attack.mitre.org/techniques/T1566/)

# 🛡️ Threat Hunt Report – Northpeak Logistics: Post-Intrusion Investigation

---

## 📌 Executive Summary

On the evening of 16 June, an external actor gained access to the Northpeak Logistics estate using a single valid credential (`sancadmin`) rather than any exploit. The loud volume of failed logons across the environment was a deliberate decoy; the real entry authenticated cleanly via RDP from `148.64.103.173` and never tripped a detection. Contrary to the intuitive assumption that Linux was the initial foothold, the timeline proves the Windows workstation was compromised first — over an hour before the Linux host was ever touched, and from the same external actor. Over roughly three and a half hours the operator staged fileless reconnaissance and tooling on Linux, pivoted internally back into the Windows workstation, planted user-profile logon persistence disguised as legitimate company software, and ran a three-domain C2 channel with one domain deliberately hidden via Base64 encoding. The operation concluded with the exfiltration of `customer_data_export_20260616.csv` from the server, uploaded during a second, reconnected RDP session — after the operator had disconnected and come back. At no point did the operator disable, uninstall, or tamper with any security tooling; the entire intrusion relied on a valid account and native OS capability ("living off the land").

---

## 🎯 Hunt Objectives

- Identify malicious activity across endpoints and network telemetry
- Correlate attacker behavior to MITRE ATT&CK techniques
- Document evidence, detection gaps, and response opportunities

---

## 🧭 Scope & Environment

- **Environment:** Northpeak Logistics cyber range estate — **NPT-WS01** (Windows workstation), **NPT-SRV01** (Windows server), **NPT-LINUX01** (Linux host), all reachable from a shared, noisy Sentinel workspace alongside unrelated estates.
- **Data Sources:** Microsoft Sentinel (`law-cyber-range` workspace), MDE tables — `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceRegistryEvents`, `DeviceEvents`. Every query scoped to `DeviceName has_any ("npt-ws01","npt-srv01","npt-linux01")` to filter out unrelated tenants sharing the workspace.
- **Timeframe:** **2026-06-16 20:00 UTC → 2026-06-17 00:30 UTC**

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔍 Flag Analysis](#-flag-analysis)
  - [🚩 Flag 1 – The Real Foothold](#-flag-1)
  - [🚩 Flag 2 – First Foothold, Proven](#-flag-2)
  - [🚩 Flag 3 – The Sloppy Artifact](#-flag-3)
  - [🚩 Flag 4 – The Server's Own Way In](#-flag-4)
  - [🚩 Flag 5 – Privilege Escalation Recon](#-flag-5)
  - [🚩 Flag 6 – Fileless RDP Reachability Check](#-flag-6)
  - [🚩 Flag 7 – Tooling Up](#-flag-7)
  - [🚩 Flag 8 – The Internal Pivot](#-flag-8)
  - [🚩 Flag 9 – Human vs. Machine Noise](#-flag-9)
  - [🚩 Flag 10 – Persistence Mechanism](#-flag-10)
  - [🚩 Flag 11 – The Three C2 Domains](#-flag-11)
  - [🚩 Flag 12 – Unwrapping the Obfuscated Beacon](#-flag-12)
  - [🚩 Flag 13 – Separating C2 Chatter from Noise](#-flag-13)
  - [🚩 Flag 14 – Beacon Rhythm](#-flag-14)
  - [🚩 Flag 15 – The Crown Jewel Leaves](#-flag-15)
  - [🚩 Flag 16 – Which Session Exfiltrated](#-flag-16)
  - [🚩 Flag 17 – Operating Without Touching Defenses](#-flag-17)
  - [🚩 Flag 18 – Confirming Privilege](#-flag-18)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

The intrusion followed a deliberately quiet path designed to blend into a noisy, shared telemetry environment. The brute-force failed-logon volume across the estate was a decoy; the actual entry point authenticated cleanly on both Windows hosts using a single compromised credential, `sancadmin`, from external IP `148.64.103.173`. Separating the one clean success from dozens of noisy, high-failure source IPs required looking past raw volume to the success/failure ratio per source — the real entry point stood out by having almost no failures behind it.

Contrary to the "obvious" assumption that Linux was the initial foothold, the timeline proves Windows (`NPT-WS01`) was compromised first — at 20:57:54 UTC, over an hour before the Linux host (`NPT-LINUX01`) was ever touched, and `NPT-SRV01` was reached independently and directly from the same external actor, not via internal lateral movement. Every remote Windows session also leaked a consistent client artifact (`RemoteDeviceName: loranse`) tying every touch back to the same operating environment.

Once on Linux, the operator ran fileless, native reconnaissance — a fumbled `sudo -1` corrected to `sudo -l`, a Bash `/dev/tcp` port-3389 reachability check against both Windows hosts, and installed NetExec via `pipx` after confirming no existing tooling was present. They then pivoted internally back into the Windows workstation over RDP from the Linux host's internal address. On the workstation, human-driven activity (parented by `explorer.exe`) was cleanly separable from heavy Defender/Azure Guest Configuration automation noise. Persistence was planted in the operator's own user profile (`HKCU\...\Run`), disguised as a legitimate internal sync tool, and a three-domain C2 channel was established — with one domain hidden via Base64 encoding and consistent ~38-second beacon spacing confirming automated, timer-driven operation rather than manual typing. Before reconnecting to move data, the operator ran a precise SID-based check (`S-1-5-32-544`) to confirm their own local Administrator membership.

The operation concluded with data theft: a customer data export was staged and uploaded from the server to the C2 infrastructure, during a *second*, reconnected RDP session — after the operator had disconnected and come back. Throughout the entire multi-hour operation, no security tooling was disabled, stopped, or tampered with. The operator relied exclusively on a valid account and native, built-in OS tooling to stay under the radar — a textbook living-off-the-land operation.

---

## 🧬 MITRE ATT&CK Summary

| Flag | Technique Category | MITRE ID | Priority |
|-----:|-------------------|----------|----------|
| 1 | Initial Access – Valid Accounts / Remote Services | T1078, T1021.001 | High |
| 2 | Initial Access – Valid Accounts | T1078 | High |
| 3 | Discovery / Attribution Artifact | T1021.001 (informational) | Low |
| 4 | Initial Access – Valid Accounts / Remote Services | T1078, T1021.001 | High |
| 5 | Discovery – Permission Groups Discovery | T1069.001 | Medium |
| 6 | Discovery – Network Service Scanning (fileless) | T1046 | Medium |
| 7 | Command and Control Tooling – Ingress Tool Transfer | T1105 | Medium |
| 8 | Lateral Movement – Remote Services (RDP) | T1021.001 | High |
| 9 | Analyst Technique – Process Tree Triage | N/A (defensive analysis) | Informational |
| 10 | Persistence – Registry Run Keys / Startup Folder | T1547.001 | High |
| 11 | Command and Control – Dynamic Resolution / Web Protocols | T1568, T1071.001 | High |
| 12 | Defense Evasion – Obfuscated Files or Information | T1027, T1140 | High |
| 13 | Analyst Technique – Baseline vs. Anomaly Triage | N/A (defensive analysis) | Informational |
| 14 | Command and Control – Application Layer Protocol (beaconing) | T1071.001 | Medium |
| 15 | Exfiltration – Exfiltration Over C2 Channel | T1041 | High |
| 16 | Exfiltration Context – Remote Services (RDP session) | T1021.001 | Medium |
| 17 | Defense Evasion (ruled out) – Living off the Land | T1059.001, T1078 | High |
| 18 | Discovery – Permission Groups Discovery | T1069.001 | Medium |

---

## 🔍 Flag Analysis

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: The Real Foothold</strong></summary>

### 🎯 Objective
Separate the genuine, clean external logon from the brute-force decoy noise flooding the logs.

### 📌 Finding
One external IP authenticated successfully with almost no failed-logon history, in stark contrast to the high-failure brute-force IPs. It authenticated via RDP (`RemoteInteractive`, Negotiate) directly to the Windows estate.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | NPT-WS01, NPT-SRV01 |
| Timestamp | 2026-06-16T20:57:54Z (first success) |
| RemoteIP | 148.64.103.173 |
| LogonType | RemoteInteractive (Negotiate) |
| Account | sancadmin |

### 💡 Why it matters
Confirms the brute-force volume is a decoy; the actual entry vector never touched password-guessing behavior and would evade any alerting keyed on failed-logon thresholds.

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where DeviceName has_any ("npt-ws01","npt-srv01")
| where Timestamp between (datetime(2026-06-16T20:00:00Z) .. datetime(2026-06-17T00:30:00Z))
| where RemoteIPType == "Public"
| summarize Successes = countif(ActionType == "LogonSuccess"),
            Failures  = countif(ActionType == "LogonFailed")
          by RemoteIP
| order by Successes desc
```

### 🖼️ Screenshot
<img width="928" height="556" alt="Flag_01" src="https://github.com/user-attachments/assets/02472f9f-eb5b-4845-b29b-710e69a5fbbc" />

</details>

---

<details>
<summary id="-flag-2">🚩 <strong>Flag 2: First Foothold, Proven</strong></summary>

### 🎯 Objective
Determine which host — Windows or Linux — was actually compromised first, without assuming the "obvious" narrative.

### 📌 Finding
`NPT-WS01` was compromised first, at 20:57:54 UTC — over an hour before `NPT-LINUX01` was touched at 22:01:38 UTC. All three hosts were accessed from the same external IP, disproving the assumption of an independent Linux-first entry.

### 🔍 Evidence

| Field | Value |
|------|-------|
| First Host | NPT-WS01 |
| First Success | 2026-06-16T20:57:54.375Z |
| RemoteIP | 148.64.103.173 |
| Compare | NPT-SRV01: 21:58:03Z; NPT-LINUX01: 22:01:38Z |

### 💡 Why it matters
Overturns the intuitive "Linux first, pivot to Windows" assumption that shapes typical incident narratives — the true order changes the entire pivot analysis.

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where DeviceName has_any ("npt-ws01","npt-srv01","npt-linux01")
| where ActionType == "LogonSuccess" and RemoteIPType == "Public"
| summarize FirstSuccess = min(Timestamp) by DeviceName, RemoteIP
| order by FirstSuccess asc
```

### 🖼️ Screenshot
<img width="1516" height="722" alt="Flag_02" src="https://github.com/user-attachments/assets/40e85005-968e-450f-bdd9-05514160502b" />

</details>

---

<details>
<summary id="-flag-3">🚩 <strong>Flag 3: The Sloppy Artifact</strong></summary>

### 🎯 Objective
Identify a consistent artifact the operator's own tooling leaked across every remote session.

### 📌 Finding
Every NTLM/RDP session into NPT-WS01 and NPT-SRV01 carried the same `RemoteDeviceName`: `loranse` — the attacker's own client machine name, leaked via the NTLM handshake on every connection.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | NPT-WS01, NPT-SRV01 |
| Artifact | RemoteDeviceName = loranse |
| Occurrences | Present on every NTLM logon across both hosts |
| Account | sancadmin |

### 💡 Why it matters
A durable, host-independent identifier for the attacker's operating environment — usable for cross-referencing against any other estate this actor may have touched.

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where DeviceName has_any ("npt-ws01","npt-srv01","npt-linux01")
| where RemoteIP == "148.64.103.173"
| project Timestamp, DeviceName, RemoteDeviceName, AdditionalFields
| order by Timestamp asc
```

### 🖼️ Screenshot
<img width="1485" height="715" alt="Flag_03" src="https://github.com/user-attachments/assets/28ed6424-3ec3-40b4-b90a-7c10e38ad99d" />

</details>

---

<details>
<summary id="-flag-4">🚩 <strong>Flag 4: The Server's Own Way In</strong></summary>

### 🎯 Objective
Determine whether NPT-SRV01 was reached via internal lateral movement or directly from outside.

### 📌 Finding
No internal connection preceded NPT-SRV01's compromise. It was reached directly and independently from the same external IP and account as NPT-WS01, via the same RDP method — not through an internal pivot from the workstation.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | NPT-SRV01 |
| Timestamp | 2026-06-16T21:58:03Z |
| RemoteIP | 148.64.103.173 (Public) |
| LogonType | Network (NTLM) → RemoteInteractive (Negotiate) |

### 💡 Why it matters
Confirms two independent, direct external footholds rather than a single entry point with lateral spread — materially changes the scope of "patient zero" analysis.

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where DeviceName == "npt-srv01"
| where RemoteIPType == "Private"
| project Timestamp, AccountName, LogonType, RemoteIP
```

### 🖼️ Screenshot
<>

</details>

---

<details>
<summary id="-flag-5">🚩 <strong>Flag 5: Privilege Escalation Recon</strong></summary>

### 🎯 Objective
Identify the first privilege-escalation check the operator ran on the Linux host, including a failed attempt.

### 📌 Finding
The operator mistyped `sudo -1` (digit one instead of letter L) at 22:11:28, then corrected it with the valid `sudo -l` at 22:16:52 — confirming their own privilege scope before proceeding.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | NPT-LINUX01 |
| Timestamp (failed) | 22:11:28 — `sudo -1` |
| Timestamp (correct) | 22:16:52 — `sudo -l` |
| Account | sancadmin |

### 💡 Why it matters
A human-driven typo followed by a corrected privileged command is strong evidence of hands-on-keyboard activity, distinct from scripted automation.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "npt-linux01"
| where AccountName == "sancadmin"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```

### 🖼️ Screenshot
<<img width="765" height="601" alt="Flag_05" src="https://github.com/user-attachments/assets/982d6442-0fdd-4a18-b59e-5fdddcc6a71d" />
>

</details>

---

<details>
<summary id="-flag-6">🚩 <strong>Flag 6: Fileless RDP Reachability Check</strong></summary>

### 🎯 Objective
Determine how the operator checked Windows host reachability from Linux without dropping any tooling on disk, and which port they targeted.

### 📌 Finding
Used Bash's built-in `/dev/tcp` pseudo-device wrapped in `timeout 2`, probing port 3389 (RDP) against both Windows internal IPs — a fully fileless technique using no external binary.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | NPT-LINUX01 |
| Timestamp | 22:21:28 |
| Command | `timeout 2 bash -c "echo > /dev/tcp/10.2.0.10/3389"` (and `.20`) |
| Port | 3389 (RDP) |

### 💡 Why it matters
Fileless network scanning leaves no scanning-tool artifact on disk, evading file-based detection entirely; the port choice reveals clear pivot intent toward RDP.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "npt-linux01"
| where FileName in ("timeout","bash") and ProcessCommandLine has "/dev/tcp"
| project Timestamp, ProcessCommandLine
```

### 🖼️ Screenshot
<img width="941" height="739" alt="Flag_06" src="https://github.com/user-attachments/assets/2dd35a08-fc12-4231-a7df-adae2a2f8f1e" />

</details>

---

<details>
<summary id="-flag-7">🚩 <strong>Flag 7: Tooling Up</strong></summary>

### 🎯 Objective
Identify the tool the operator committed to installing after checking for existing capabilities.

### 📌 Finding
Checked for `xfreerdp`/`rdesktop` and `nxc`/`netexec`/`crackmapexec` via `which` (none present), then installed **NetExec** via `pipx` — a modern Windows lateral-movement/enumeration tool.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | NPT-LINUX01 |
| Timestamp | 22:29:16 |
| Command | `python3 /usr/bin/pipx install netexec` |
| Account | sancadmin |

### 💡 Why it matters
Confirms deliberate preparation for authenticated lateral movement against the Windows estate, directly preceding the internal pivot.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "npt-linux01"
| where Timestamp between (datetime(2026-06-16 22:20:00) .. datetime(2026-06-16 22:30:00))
| where FileName in ("dash","sudo","apt-get","python3.12","pipx","snap") or ProcessCommandLine has_any ("which","apt-get","pipx","command-not-found")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

### 🖼️ Screenshot
<img width="943" height="747" alt="Flag_07" src="https://github.com/user-attachments/assets/509ed149-3c07-4ac0-bc0a-17e244912d19" />

</details>

---

<details>
<summary id="-flag-8">🚩 <strong>Flag 8: The Internal Pivot</strong></summary>

### 🎯 Objective
Reconstruct the internal hop back into the Windows workstation from the Linux host.

### 📌 Finding
`sancadmin` pivoted from NPT-LINUX01's internal IP (10.2.0.30) into NPT-WS01 via RDP, one second after completing the port-3389 reachability check.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Account | sancadmin |
| Source IP | 10.2.0.30 (NPT-LINUX01, internal) |
| Target | NPT-WS01 |
| Timestamp | 22:21:29Z |

### 💡 Why it matters
Confirms the internal pivot mechanism and method precisely, completing the lateral movement portion of the attack chain.

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where DeviceName == "npt-ws01"
| where RemoteIPType == "Private"
| project Timestamp, AccountName, LogonType, RemoteIP
```

### 🖼️ Screenshot
<img width="656" height="590" alt="Flag_08" src="https://github.com/user-attachments/assets/ba22a561-a069-46fd-bd04-16420f0e39e0" />

</details>

---

<details>
<summary id="-flag-9">🚩 <strong>Flag 9: Human vs. Machine Noise</strong></summary>

### 🎯 Objective
Separate the operator's genuine interactive activity from the high volume of automated PowerShell noise on NPT-WS01.

### 📌 Finding
Automated Defender/Azure Guest Configuration activity (parented by `senseir.exe`, `gc_worker.exe`, `cmd.exe`, running as SYSTEM) accounts for most PowerShell launches. Filtering strictly to the `sancadmin` account, the odd parent out was **`explorer.exe`** — the one shell genuinely launched by a person interacting with the desktop.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | NPT-WS01 |
| Account | sancadmin |
| Distinguishing Parent | explorer.exe (human) vs. powershell.exe→powershell.exe (scripted) |

### 💡 Why it matters
Establishes a reliable, repeatable method for triaging noisy PowerShell telemetry down to genuine operator activity — critical in any environment with heavy automation.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "npt-ws01"
| where Timestamp between (datetime(2026-06-16 20:00:00) .. datetime(2026-06-17 00:30:00))
| where AccountName =~ "sancadmin"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by Timestamp asc
```

### 🖼️ Screenshot
<img width="1528" height="733" alt="Flag_09b" src="https://github.com/user-attachments/assets/d3617997-a116-4fd5-9680-3991ca0c3f4d" />

</details>

---

<details>
<summary id="-flag-10">🚩 <strong>Flag 10: Persistence Mechanism</strong></summary>

### 🎯 Objective
Identify the exact command planted for reboot/logon persistence, including full path.

### 📌 Finding
The operator tested `NorthpeakSyncTray.ps1` interactively several times before writing it to a `Run` key in `sancadmin`'s own user profile — logon persistence scoped to the user, not a service or scheduled task.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | NPT-WS01 |
| Registry Key | HKCU\Software\Microsoft\Windows\CurrentVersion\Run |
| Value Data (command) | `powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\Northpeak\NorthpeakSync\Bin\NorthpeakSyncTray.ps1"` |
| Account | sancadmin |

### 💡 Why it matters
Registry Run-key persistence under a user profile blends into normal user software and survives reboot without requiring elevated service/task privileges — a common, low-visibility persistence pattern.

### 🔧 KQL Query Used
```kql
DeviceRegistryEvents
| where DeviceName == "npt-ws01"
| where ActionType == "RegistryValueSet"
| where RegistryKey has @"\Run"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```

### 🖼️ Screenshot
<img width="1544" height="706" alt="Flag_10a" src="https://github.com/user-attachments/assets/8b6d9189-ea47-4e02-b75c-b3b7aee553a6" />

</details>

---

<details>
<summary id="-flag-11">🚩 <strong>Flag 11: The Three C2 Domains</strong></summary>

### 🎯 Objective
Identify all three look-alike C2 subdomains and where each was actually observable, given that network telemetry only captured one.

### 📌 Finding
Three subdomains of `sync-northpeak.com` were used, in first-contact order: `status`, `updates`, `cdn`. Only `status.sync-northpeak.com` appears in `DeviceNetworkEvents`; `updates.sync-northpeak.com` is visible only as plaintext in process command lines; `cdn.sync-northpeak.com` is hidden entirely inside a Base64 `-EncodedCommand` blob.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Domain 1 | status.sync-northpeak.com (network-visible) |
| Domain 2 | updates.sync-northpeak.com (process-only, plaintext) |
| Domain 3 | cdn.sync-northpeak.com (process-only, Base64-obfuscated) |
| Source | InitiatingProcessCommandLine |

### 💡 Why it matters
Demonstrates that network telemetry alone is insufficient for full C2 infrastructure discovery in this environment — process-level command-line data was essential to complete the picture.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "npt-ws01"
| where AccountName =~ "sancadmin"
| where ProcessCommandLine has "sync-northpeak.com" or ProcessCommandLine has "EncodedCommand"
| project Timestamp, ProcessCommandLine
| order by Timestamp asc
```

### 🖼️ Screenshot
<img width="1539" height="590" alt="Flag_11" src="https://github.com/user-attachments/assets/dd87d52b-dcf4-473a-821c-ef045bfc929f" />

</details>

---

<details>
<summary id="-flag-12">🚩 <strong>Flag 12: Unwrapping the Obfuscated Beacon</strong></summary>

### 🎯 Objective
Decode the Base64-wrapped beacon command to reveal the full destination and parameters.

### 📌 Finding
The `-EncodedCommand` payload decodes (Base64 → UTF-16LE) to a full `Invoke-WebRequest` call to the `cdn` subdomain, carrying a host identifier and a static campaign/flag tag.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Full URL | `https://cdn.sync-northpeak.com/api/beacon?id=NPT-WS01&flag=NORTHPEAK-09` |
| Parameters | id=NPT-WS01, flag=NORTHPEAK-09 |
| Method | Invoke-WebRequest, -TimeoutSec 4 |

### 💡 Why it matters
Reveals the complete beacon structure, including a static tag consistent across this host's traffic — useful for cross-environment IOC matching.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "npt-ws01"
| where ProcessCommandLine has "EncodedCommand"
| extend EncodedPart = extract(@"-EncodedCommand\s+(\S+)", 1, ProcessCommandLine)
| extend DecodedBytes = base64_decodestring(EncodedPart)
| project Timestamp, ProcessCommandLine, DecodedBytes
```

### 🖼️ Screenshot
<img width="1469" height="476" alt="Flag_12" src="https://github.com/user-attachments/assets/218ea43a-d732-43d9-8e78-6de9109f3f7a" />

</details>

---

<details>
<summary id="-flag-13">🚩 <strong>Flag 13: Separating C2 Chatter from Noise</strong></summary>

### 🎯 Objective
Distinguish genuine operator-driven encoded commands from benign, repeating system automation among all encoded PowerShell activity.

### 📌 Finding
The overwhelming majority of encoded commands are launched by **`gc_worker.exe`** (Azure Guest Configuration), running as SYSTEM, repeating an identical static payload every time. The few that matter are self-spawned PowerShell under `sancadmin`, each carrying a unique, non-repeating payload.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Noise generator | gc_worker.exe (SYSTEM), static repeating payload |
| Operator activity | powershell.exe→powershell.exe (sancadmin), unique payloads |

### 💡 Why it matters
Proves a repeatable triage method: identical, repeating encoded payloads from a known automation binary can be safely bulk-dismissed, isolating the handful of commands that require analyst attention.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "npt-ws01"
| where ProcessCommandLine has "EncodedCommand"
| summarize Count = count() by InitiatingProcessFileName
| order by Count desc
```

### 🖼️ Screenshot
<img width="611" height="549" alt="Flag_13" src="https://github.com/user-attachments/assets/d44324d1-d603-46e0-b73d-5483f778833e" />

</details>

---

<details>
<summary id="-flag-14">🚩 <strong>Flag 14: Beacon Rhythm</strong></summary>

### 🎯 Objective
Interpret the spacing between early check-ins to the first C2 domain to determine what is driving the channel.

### 📌 Finding
Check-ins to `status.sync-northpeak.com` and `updates.sync-northpeak.com` both repeat at a near-identical ~38-second interval — consistent, fixed-interval spacing, not the bursty irregularity of manual typing. This proves an automated, timer/sleep-driven beacon loop is operating the channel.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Interval | ~38.4–38.5 seconds, consistent across both domains |
| Interpretation | Automated sleep-timer beacon loop |

### 💡 Why it matters
Confirms the C2 channel operates independently of the operator's live attention — a persistent, scheduled callback rather than one-off manual requests.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "npt-ws01"
| where ProcessCommandLine has "status.sync-northpeak.com"
| project Timestamp, ProcessCommandLine
| order by Timestamp asc
| serialize
| extend PrevTimestamp = prev(Timestamp)
| extend SpacingSeconds = datetime_diff('second', Timestamp, PrevTimestamp)
```

### 🖼️ Screenshot
<img width="1462" height="617" alt="Flag_14a" src="https://github.com/user-attachments/assets/f7fb3130-e4c0-40af-8d32-82406e8d8225" />

</details>

---

<details>
<summary id="-flag-15">🚩 <strong>Flag 15: The Crown Jewel Leaves</strong></summary>

### 🎯 Objective
Identify the final exfiltrated file, its source host, and its destination.

### 📌 Finding
`customer_data_export_20260616.csv` was uploaded from `NPT-SRV01` to `cdn.sync-northpeak.com` — the final action of the entire intrusion.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Filename | customer_data_export_20260616.csv |
| Source Host | NPT-SRV01 |
| Destination | cdn.sync-northpeak.com |

### 💡 Why it matters
Confirms the "crown jewel" data type and the specific asset it was taken from, completing the impact assessment required for breach-notification scoping.

### 🔧 KQL Query Used
```kql
DeviceFileEvents
| where DeviceName == "npt-srv01"
| where FileName has "customer_data_export"
| project Timestamp, ActionType, FileName, FolderPath
```
```kql
DeviceNetworkEvents
| where DeviceName == "npt-srv01"
| where RemoteUrl == "cdn.sync-northpeak.com"
| project Timestamp, RemoteUrl, InitiatingProcessCommandLine
```

### 🖼️ Screenshot
<Insert screenshot>

</details>

---

<details>
<summary id="-flag-16">🚩 <strong>Flag 16: Which Session Exfiltrated</strong></summary>

### 🎯 Objective
Determine whether the exfiltration occurred in the operator's first RDP session on NPT-SRV01 or a later reconnect.

### 📌 Finding
Two distinct RemoteInteractive sessions exist on NPT-SRV01: the original at 21:58:08 UTC, and a reconnect (RemoteInteractive + Unlock) at 23:42:52 UTC. The export occurred in the **second session — the one they came back through**.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Session 1 | RemoteInteractive, 21:58:08Z |
| Session 2 (reconnect) | RemoteInteractive + Unlock, 23:42:52Z |
| Exfil occurred in | Session 2 (reconnect) |

### 💡 Why it matters
Indicates deliberate, staged operator behavior — the exfil was a distinct, later action taken after other objectives were completed and the operator briefly stepped away, not a rushed action within the initial access window.

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where DeviceName == "npt-srv01"
| where ActionType in ("LogonSuccess","Unlock")
| project Timestamp, ActionType, LogonType, RemoteIPType
| order by Timestamp asc
```

### 🖼️ Screenshot
<Insert screenshot>

</details>

---

<details>
<summary id="-flag-17">🚩 <strong>Flag 17: Operating Without Touching Defenses</strong></summary>

### 🎯 Objective
Determine how the operator remained undetected for hours without disabling or tampering with security tooling.

### 📌 Finding
No commands anywhere in the intrusion window disabled, stopped, or tampered with Defender, auditing, or any security service. The operator instead relied entirely on a **valid, compromised credential** and **native, built-in OS tools** (PowerShell, Bash, registry Run keys, `Invoke-WebRequest`, `/dev/tcp`) — a living-off-the-land approach that never touched the security stack.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Absence | No Defender/service tampering commands found across all three hosts |
| Substitute | Valid credentials (sancadmin) + native OS tooling only |

### 💡 Why it matters
Confirms that the environment's security tooling remained fully operational throughout — the intrusion succeeded through legitimate-looking access, not evasion of active defenses, which has direct implications for detection strategy (behavioral over signature-based).

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName has_any ("npt-ws01","npt-srv01","npt-linux01")
| where ProcessCommandLine has_any (
    "Set-MpPreference","DisableRealtimeMonitoring","Stop-Service",
    "sc stop","net stop","auditpol","systemctl stop","iptables -F")
| project Timestamp, DeviceName, ProcessCommandLine
```

### 🖼️ Screenshot
<Insert screenshot>

</details>

---

<details>
<summary id="-flag-18">🚩 <strong>Flag 18: Confirming Privilege</strong></summary>

### 🎯 Objective
Identify what the operator was confirming about their own account immediately upon re-entering the workstation.

### 📌 Finding
Upon reconnecting to NPT-WS01 (Unlock at 22:42:39 UTC), the operator ran a short identity-check burst ending in a command filtering for the well-known SID `S-1-5-32-544` — the fixed identifier for **BUILTIN\Administrators** — confirming whether `sancadmin` actually holds local administrator rights, not just a valid logon.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Group/Privilege tested | BUILTIN\Administrators (SID S-1-5-32-544) |
| Relationship confirmed | Whether sancadmin is a member of the local Administrators group |
| Host | NPT-WS01 |

### 💡 Why it matters
Shows deliberate, careful privilege verification by SID rather than name — evidence of a practiced operator methodically confirming capability before acting further.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "npt-ws01"
| where AccountName =~ "sancadmin"
| where ProcessCommandLine has_any ("S-1-5-32-544","whoami")
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```

### 🖼️ Screenshot
<Insert screenshot>

</details>

---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps
- Failed-logon volume alerting created a decoy effect, burying the single clean successful entry that mattered most
- No alerting on NTLM `RemoteDeviceName` consistency across sessions/hosts, despite it being a durable attacker artifact
- Network telemetry (`DeviceNetworkEvents`) missed 2 of 3 active C2 domains entirely; process-level command-line inspection was required to complete the picture
- No detection triggered on `HKCU\...\Run` persistence writes referencing hidden windows or bypassed execution policy
- No baseline differentiating expected automated PowerShell parent processes from genuine interactive (`explorer.exe`-parented) activity

### Recommendations
- Shift detection logic from failed-logon volume to success/failure ratio per source IP, especially for external RDP/NTLM
- Implement automated Base64 decoding for all `-EncodedCommand` PowerShell invocations at ingestion
- Add behavioral alerting for `HKCU`-scoped Run-key writes combined with `-WindowStyle Hidden` or `-ExecutionPolicy Bypass`
- Build a beaconing-interval detection (regular timing to the same domain) independent of payload/domain reputation
- Require MFA or step-up authentication on privileged RDP sessions to eliminate reliance on password-only "clean" authentication as a trust signal

---

## 🧾 Final Assessment

This intrusion demonstrates a capable, patient operator prioritizing stealth over speed: no exploits, no brute force, no security-tool tampering — only a single valid credential and native administrative tooling sustained over several hours across three hosts. The attacker's discipline (fileless recon, SID-based privilege verification, disguised persistence, partially obfuscated C2, staged multi-session exfiltration) reflects above-average operational tradecraft. The environment's security stack remained fully intact throughout, underscoring that detection failure here was a visibility and correlation gap — not a defensive-tooling failure. Prioritizing the recommendations above would materially close the gaps that allowed this operator to remain unnoticed for the full duration of the intrusion.

---

## 📎 Analyst Notes

- Report structured for interview and portfolio review
- Evidence reproducible via advanced hunting in the law-cyber-range Sentinel workspace
- Techniques mapped directly to MITRE ATT&CK
- All telemetry scoped strictly to NPT-WS01, NPT-SRV01, NPT-LINUX01, 2026-06-16T20:00Z → 2026-06-17T00:30Z, account `sancadmin`
- Flag numbering above reflects sequential discovery order during the hunt; some flags were revisited with additional clues before reaching a confirmed answer

---

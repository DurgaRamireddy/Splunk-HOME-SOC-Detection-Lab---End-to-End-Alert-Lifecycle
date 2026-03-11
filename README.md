# Splunk-HOME-SOC-Detection-Lab---End-to-End-Alert-Lifecycle

**Tools:** Splunk 9.3.2 · Windows 10 · Kali Linux · Ubuntu 22.04 · Hydra · PowerShell  
**MITRE ATT&CK:** T1110 · T1078 · T1059.001 · T1547.001 · T1059  
**Type:** Home Lab · Blue Team · Threat Detection · Incident Response
> ⚠️ **Disclaimer:** This project was conducted entirely in an isolated VMware lab environment for educational purposes only. No real systems, networks, or individuals were targeted. All IP addresses are private VMware Host-Only addresses that exist solely within the local lab.

---

## Overview

This project simulates a real SOC Tier 1 analyst workflow end-to-end:

1. Deploy Splunk as a SIEM on Ubuntu
2. Forward Windows 10 security logs to Splunk via HTTP Event Collector
3. Simulate a multi-stage attack from Kali Linux
4. Detect every attack stage using SPL queries
5. Build a SOC operational dashboard
6. Write a formal incident report with MITRE ATT&CK mapping

---

## Lab Architecture

```
┌──────────────────────────────────────────────────────┐
│             VMware Host-Only Network                 │
│                 192.168.161.0/24                     │
│                                                      │
│  ┌─────────────┐    ┌─────────────┐    ┌──────────┐  │
│  │  Ubuntu VM  │    │ Windows 10  │    │  Kali    │  │
│  │Splunk 9.3.2 │◄───│ Log Source  │    │ Attacker │  │
│  │.130 : 8000  │    │    .131     │◄───│   .153   │  │
│  │  HEC: 8088  │    │             │    │  Hydra   │  │
│  └─────────────┘    └─────────────┘    └──────────┘  │
└──────────────────────────────────────────────────────┘
```

| VM | OS | IP | Role |
|---|---|---|---|
| Ubuntu | Ubuntu 22.04 LTS | 192.168.161.130 | Splunk SIEM |
| Windows 10 | Windows 10 | 192.168.161.131 | Victim / Log Source |
| Kali Linux | Kali 2024 | 192.168.161.153 | Attacker |

---
## Attack Chain & Detections

| Phase | MITRE TTP | Technique | EventID | Result |
|---|---|---|---|---|
| 1 | T1110 | Brute Force via Hydra | 4625 | 49 failed logons detected |
| 2 | T1078 | Valid Account logons | 4624 | 77 successful logons monitored |
| 3 | T1059.001 | PowerShell encoded command | 4104 | 6 script block events captured |
| 4 | T1547.001 | Registry Run key persistence | 4104 | Updater key detected |
| 5 | T1059 | Process creation | 4688 | 52 process events logged |

---
## Setup

### Step 1 - Splunk on Ubuntu

```bash
# Install
sudo dpkg -i splunk-9.3.2.deb
sudo /opt/splunk/bin/splunk start --accept-license
sudo /opt/splunk/bin/splunk enable boot-start

# Enable HEC
# Settings → Data Inputs → HTTP Event Collector → Global Settings → Enable → Port 8088
# New Token → name: winlogbeat → index: main → copy token
```

### Step 2 - Windows Audit Policy

```powershell
# Enable critical audit categories
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

# Enable PowerShell Script Block Logging
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $path -Force
Set-ItemProperty -Path $path -Name "EnableScriptBlockLogging" -Value 1
```
### Step 3 - Windows Log Forwarding via HEC

```powershell
# splunk-forward.ps1
$splunkUrl = "http://192.168.161.130:8088/services/collector"
$token = "YOUR-HEC-TOKEN-HERE"
$headers = @{Authorization = "Splunk $token"}

Get-WinEvent -LogName Security -MaxEvents 50 | ForEach-Object {
    $event = @{
        event = @{
            EventID      = $_.Id
            TimeCreated  = $_.TimeCreated.ToString()
            Message      = $_.Message
            Computer     = $_.MachineName
        }
        sourcetype = "WinEventLog:Security"
        index      = "main"
    }
    $body = $event | ConvertTo-Json -Compress
    Invoke-RestMethod -Uri $splunkUrl -Method Post -Headers $headers -Body $body
}
```

---
## Attack Simulation

### T1110 - Brute Force (Kali → Windows)

```bash
# Extract wordlist
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# Run Hydra brute force
hydra -l Durga -P /usr/share/wordlists/rockyou.txt smb://192.168.161.131 -t 2 -v
```

```powershell
# Simulate failed logons locally on Windows
1..20 | ForEach-Object {
    $cred = New-Object System.Management.Automation.PSCredential(
        "FakeUser", (ConvertTo-SecureString "wrongpassword$_" -AsPlainText -Force))
    try { Start-Process cmd -Credential $cred -ErrorAction Stop } catch {}
}
```

### T1547.001 + T1059.001 - Persistence via Registry

```powershell
# Write malicious autostart registry key
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
    -Name "Updater" `
    -Value "powershell.exe -ExecutionPolicy Bypass -enc SGVsbG8gV29ybGQ="

# Verify it was written
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
```

---
## Splunk Detection Queries (SPL)

### Brute Force Detection - T1110
```spl
index=main EventID=4625
| stats count by Computer
| where count > 3
| sort -count
```

### Successful Logon Monitoring - T1078
```spl
index=main EventID=4624
| stats count by Computer
```

### PowerShell Abuse Detection - T1059.001
```spl
index=main sourcetype="WinEventLog:PowerShell" EventID=4104
| table TimeCreated Computer Message
```

### Full Attack Timeline
```spl
index=main (EventID=4625 OR EventID=4624 OR EventID=4104 OR EventID=4688)
| timechart count by EventID
```

---

## Splunk Dashboard

4-panel SOC operational dashboard built in Splunk:

| Panel | Query | Chart Type |
|---|---|---|
| Brute Force Failed Logons | EventID=4625 stats by Computer | Bar Chart |
| Successful Logons | EventID=4624 stats by Computer | Table |
| PowerShell Executions | EventID=4104 table | Table |
| Attack Timeline | timechart by EventID | Line Chart |

---

## Key Results

| Metric | Count |
|---|---|
| Total events ingested | 350+ |
| Failed logon events (4625) | 49 |
| Successful logon events (4624) | 77 |
| PowerShell execution events (4104) | 6 |
| Process creation events (4688) | 52 |
| IOCs identified | 8 |
| MITRE TTPs covered | 5 |

---
## Files in this Repo

```
splunk-soc-lab/
├── README.md
├── Home SOC Lab Report - Splunk SOC Detection.docx
├── scripts/
│   ├── splunk-forward.ps1        # Windows → Splunk log forwarding
│   └── audit-policy-setup.ps1   # Windows audit policy config
├── splunk/
│   └── detection-queries.spl    # All SPL detection searches
└── screenshots/
    ├── splunk-dashboard.png
    ├── 4625-brute-force.png
    ├── 4624-valid-accounts.png
    ├── 4104-powershell.png
    └── attack-timeline.png
```
---

## Skills Demonstrated

- Splunk Enterprise deployment and configuration on Linux
- Log pipeline engineering via HTTP Event Collector (HEC)
- Windows Security Event Log analysis (EventID taxonomy)
- Audit policy configuration via `auditpol` and Group Policy
- Threat simulation using Hydra, PowerShell, and registry manipulation
- SPL query writing for threat detection
- SOC dashboard creation in Splunk
- Incident documentation with IOCs and MITRE ATT&CK mapping

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [Splunk Documentation](https://docs.splunk.com)
- [Windows Security Event IDs](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)

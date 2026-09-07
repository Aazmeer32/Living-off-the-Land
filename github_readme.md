# Detection Engineering & SOAR Automation Lab: Living-off-the-Land (LotL) Triage & Response

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Splunk](https://img.shields.io/badge/SIEM-Splunk--Enterprise-orange.svg)](https://www.splunk.com/)
[![Sysmon](https://img.shields.io/badge/Telemetry-Microsoft--Sysmon-blue.svg)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
[![Python](https://img.shields.io/badge/SOAR%20Engine-Python--3.11-blue.svg)](https://www.python.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red.svg)](https://attack.mitre.org/)

---

## 📌 Executive Summary

Modern adversary tactics increasingly rely on **Living-off-the-Land (LotL)** techniques—leveraging native administrative tools (`certutil.exe`, `powershell.exe`, `wmic.exe`, `bitsadmin.exe`) to evade traditional signature-based security controls.

This project implements a complete, end-to-end **Detection Engineering and SOAR Automation Pipeline**. It captures granular endpoint events via Microsoft Sysmon, ingests and parses telemetry through a Splunk Universal Forwarder into Splunk Enterprise, triggers custom SPL alert rules mapped to the MITRE ATT&CK framework, and offloads actionable alerts to a custom **Python SOAR Engine** for automated enrichment, threat scoring, and containment.

```
       [ Victim / Windows Endpoint ]
                     │
  (Sysmon Event Logs / System Telemetry)
                     │
                     ▼
      [ Splunk Universal Forwarder ]
                     │ (Port 9997 / Encrypted Stream)
                     ▼
        [ Splunk Enterprise (SIEM) ]
                     │
           (SPL Alerts / Webhook)
                     │
                     ▼
       [ Automated Python SOAR Engine ]
      ┌──────────────┴──────────────┐
      ▼                             ▼
(Threat Intel / Enrichment)   (Response / Ticket / Block)
```

---

## 🎯 Architecture & Pipeline Overview

1. **Endpoint Visibility Layer:**
   * **Microsoft Sysmon v15.0+** deployed with SwiftOnSecurity / Olaf Hartong modular configuration.
   * Fine-tuned event filtering focusing on Process Creation (`Event ID 1`), Network Connections (`Event ID 3`), Process Access (`Event ID 10`), and Image Loads (`Event ID 7`).
2. **Telemetry Ingestion Layer:**
   * **Splunk Universal Forwarder (UF)** reading `Microsoft-Windows-Sysmon/Operational`.
   * Dynamic field extraction and index routing defined in `inputs.conf` and `props.conf`.
3. **Detection & Correlation Layer:**
   * Splunk Search Processing Language (SPL) alert rules designed to flag suspicious command-line parameters, parent-child anomalies, and dual-use binary misuse.
4. **Automated Triage & Response Layer:**
   * Alert-triggered Webhook pushing JSON payloads to a custom **Python SOAR Service**.
   * VirusTotal & IPQualityScore API integration for automatic hash/IP reputation scoring.
   * Dynamic risk score calculation determining automated host isolation or incident ticket generation.

---

## 🛠️ Lab Topology & Component Matrix

| Tier | Component | Technology / Tool | Configuration Specs |
| :--- | :--- | :--- | :--- |
| **Endpoint** | Target Workstation | Windows 11 Enterprise | Sysmon v15.x, Defender baseline |
| **Forwarder** | Log Collector | Splunk Universal Forwarder v9.x | Monitored Channel: Sysmon Operational |
| **SIEM** | Analytics & Indexer | Splunk Enterprise (Local / Virtual Machine) | Index: `endpoint`, Listening Port: `9997` |
| **Automation** | SOAR Service | Python 3.11 / Flask Server | REST API Webhook Listener |
| **Enrichment** | Threat Intelligence | VirusTotal REST API v3, AbuseIPDB | External Threat API integration |

---

## 🔍 Detection Engineering Focus: LotL Attacks

This lab targets four primary Living-off-the-Land tactics heavily leveraged by ransomware operators and APTs:

### 1. `certutil.exe` File Download / Ingress Tool Transfer
* **MITRE ATT&CK:** [T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
* **Behavior:** Adversaries abuse `certutil` command-line flags (`-urlcache`, `-split`, `-f`) to fetch external payloads directly onto disk.

### 2. PowerShell Encoded Command Execution
* **MITRE ATT&CK:** [T1059.001 - Scripting: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
* **Behavior:** Execution of obfuscated or base64-encoded scripts via `-EncodedCommand` or `-e` flags to bypass perimeter content inspection.

### 3. `wmic.exe` Remote Process Creation & Reconnaissance
* **MITRE ATT&CK:** [T1047 - Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)
* **Behavior:** Misuse of WMI command line to spawn processes on local/remote systems or execute stealthy queries.

### 4. `bitsadmin.exe` Asynchronous Persistence / Transfer
* **MITRE ATT&CK:** [T1197 - BITS Jobs](https://attack.mitre.org/techniques/T1197/)
* **Behavior:** Creation of background intelligent transfer service jobs to download malicious executables undetected.

---

## ⚙️ Configuration Details

### 1. Endpoint Splunk Universal Forwarder (`inputs.conf`)

Located at: `%ProgramFiles%\SplunkUniversalForwarder\etc\system\local\inputs.conf`

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
renderXml = true
index = endpoint
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon
```

### 2. Splunk Field Extraction & Parsing (`props.conf` & `transforms.conf`)

Located on Indexer at: `$SPLUNK_HOME/etc/system/local/props.conf`

```ini
[XmlWinEventLog:Microsoft-Windows-Sysmon]
KV_MODE = xml
SHOULD_LINEMERGE = false
TIME_PREFIX = <TimeCreated SystemTime='
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%fZ
TZ = UTC
```

---

## 📊 Splunk Search Processing Language (SPL) Detections

### Detection 1: Certutil Suspicious Download Activity

```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon" EventCode=1
| eval ImagePath=lower(Image)
| where match(ImagePath, "\\certutil\.exe$")
| where match(CommandLine, "(?i)(-urlcache|-split|-f)")
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, User, ParentImage, Image, CommandLine, Hashes
| convert ctime(firstTime) ctime(lastTime)
| eval risk_score=75, technique="T1105 - Ingress Tool Transfer"
```

### Detection 2: Obfuscated / Encoded PowerShell Execution

```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon" EventCode=1
| eval ImagePath=lower(Image)
| where match(ImagePath, "\\(powershell|pwsh)\.exe$")
| where match(CommandLine, "(?i)(-enc|-encodedcommand|-e\s)")
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, User, ParentImage, Image, CommandLine, Hashes
| convert ctime(firstTime) ctime(lastTime)
| eval risk_score=80, technique="T1059.001 - PowerShell Obfuscation"
```

---

## 🐍 SOAR Python Automated Triage Engine

The Python automation framework runs a REST Webhook listener that processes incoming Splunk alert triggers, queries threat intelligence APIs, calculates dynamic risk scores, and routes alerting metadata.

### Project Architecture
```
soar_engine/
├── app.py                 # Flask REST Webhook Receiver
├── requirements.txt       # Dependencies
├── config.yaml            # Config & API Keys
└── modules/
    ├── threat_intel.py    # VirusTotal & AbuseIPDB Connectors
    ├── enricher.py        # Log Parsing & Score Engine
    └── responder.py       # Automated Action Framework
```

### Script: Flask Webhook Receiver & Enrichment Core (`app.py`)

```python
import os
import re
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

VT_API_KEY = os.getenv("VT_API_KEY", "YOUR_VIRUSTOTAL_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/files/"

def check_file_hash(file_hash):
    """Query VirusTotal API v3 for file hash reputation."""
    if not file_hash or len(file_hash) not in [32, 40, 64]:
        return {"status": "skipped", "positives": 0}

    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(f"{VT_URL}{file_hash}", headers=headers, timeout=5)
        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            return {
                "status": "success",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0)
            }
    except Exception as e:
        print(f"[!] Threat Intel Lookup Error: {e}")
    return {"status": "error", "positives": 0}

def parse_hashes(hash_string):
    """Extract SHA256 or MD5 hash from standard Sysmon Hashes string."""
    if not hash_string:
        return None
    sha256_match = re.search(r'SHA256=([A-Fa-f0-9]{64})', hash_string)
    if sha256_match:
        return sha256_match.group(1)
    md5_match = re.search(r'MD5=([A-Fa-f0-9]{32})', hash_string)
    if md5_match:
        return md5_match.group(1)
    return None

@app.route('/api/v1/alert', methods=['POST'])
def handle_splunk_alert():
    """Receives Webhook payload from Splunk SIEM."""
    data = request.json
    if not data:
        return jsonify({"status": "error", "message": "No payload provided"}), 400

    print("\n[+] --- NEW ALERT INGESTED FROM SPLUNK ---")
    host = data.get("Computer", "Unknown")
    user = data.get("User", "Unknown")
    cmd = data.get("CommandLine", "N/A")
    raw_hash = data.get("Hashes", "")
    technique = data.get("technique", "Unknown LotL Technique")
    base_risk = int(data.get("risk_score", 50))

    extracted_hash = parse_hashes(raw_hash)
    vt_results = check_file_hash(extracted_hash) if extracted_hash else {"positives": 0}

    # Dynamic Scoring Logic
    malicious_votes = vt_results.get("malicious", 0)
    adjusted_risk = base_risk + (malicious_votes * 10)

    triage_summary = {
        "host": host,
        "user": user,
        "technique": technique,
        "command_line": cmd,
        "hash_analyzed": extracted_hash,
        "vt_malicious_count": malicious_votes,
        "final_risk_score": min(adjusted_risk, 100),
        "action_taken": "ISOLATE_HOST" if adjusted_risk >= 85 else "LOG_AND_TICKET"
    }

    print(f"[*] Host: {host} | User: {user}")
    print(f"[*] Command: {cmd}")
    print(f"[*] Calculated Risk Score: {triage_summary['final_risk_score']}/100")
    print(f"[*] Executed Action: {triage_summary['action_taken']}")
    print("------------------------------------------\n")

    return jsonify({"status": "success", "summary": triage_summary}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
```

---

## 🧪 Simulation & Attack Validation Steps

To validate the end-to-end telemetry flow, execute the following commands inside an isolated sandbox VM:

### Attack 1: Emulate Certutil Ingress File Transfer
```cmd
certutil.exe -urlcache -split -f "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE" %temp%\test_payload.txt
```

### Attack 2: Emulate PowerShell Base64 Encoded Execution
```powershell
powershell.exe -EncodedCommand AABvAHcAZQByAHMAaABlAGwAbAAgAC0ATgBvAFAA
```

---

## 📈 Verification & Audit Workflow

1. **Sysmon Event Generation:** Observe Event ID `1` in Windows Event Viewer under `Microsoft-Windows-Sysmon/Operational`.
2. **Splunk Ingestion Verification:**
   Query Splunk search interface:
   ```spl
   index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon" Certutil.exe
   ```
3. **Webhook Triggering:** Verify that the SPL alert fires and posts payload to `http://<SOAR_IP>:5000/api/v1/alert`.
4. **SOAR Console Output:** Confirm hash extraction, VirusTotal enrichment lookup, dynamic risk assessment, and automated response decisions in the terminal logs.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
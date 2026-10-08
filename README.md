# 🛡️ Deep SOC Lab

A hands-on Security Operations Center (SOC) home lab focused on endpoint detection, network monitoring, threat intelligence enrichment, and incident investigation.

## 🔎 Project Overview

Deep SOC Lab combines Wazuh, Zeek, MISP, Sysmon, and SentinelX Python automation to demonstrate endpoint detection, network monitoring, threat intelligence enrichment, and incident investigation.

## 🏗️ Architecture

```text
Windows 11 Endpoint
        │
        │ Sysmon / Security Events
        ▼
      Wazuh
        │
        │ Alerts
        ▼
   SentinelX Python
        │
        │ IOC Enrichment
        ▼
      MISP
        │
        └── IOC Match / No Match

Network Traffic
        │
        ▼
      Zeek
        │
        │ conn.log / http.log
        ▼
   SentinelX Python
        │
        ▼
      MISP
        │
        ▼
Enrichment Evidence
```

## ✅ Validated Detection Flow

A controlled IOC validation test was performed using 192.0.2.123.

The Windows endpoint generated HTTP traffic to the Ubuntu SOC server with the controlled IOC placed in the HTTP Host field.

Zeek detected the HTTP request and SentinelX queried MISP for enrichment.

The controlled IOC was successfully matched in MISP.

## 🧩 SentinelX Components

### MISP IOC Lookup

scripts/python/misp_ioc_lookup.py

Performs direct IOC lookups against MISP using PyMISP.

### Zeek to MISP Enricher

scripts/python/zeek_misp_enricher.py

Reads Zeek HTTP logs, extracts network indicators, queries MISP, and produces JSON enrichment evidence.

### Wazuh to MISP Enricher

scripts/python/sentinelx/wazuh_misp_enricher.py

Processes Wazuh alerts, extracts indicators including hashes and network values, and enriches them using MISP.

### MISP Client

scripts/python/sentinelx/misp_client.py

Provides reusable MISP client functionality for SentinelX.

## 📁 Repository Structure

```text
attacks/       Attack validation scenarios
configs/       Wazuh and Sysmon configuration notes
dashboards/    Dashboard documentation
detections/    Detection engineering documentation
docs/          Architecture and setup documentation
evidence/      Investigation evidence
incidents/     Incident documentation
reports/       SOC lab reports
screenshots/   Detection screenshots
scripts/       Bash, PowerShell, and Python tooling
```

## 🧰 Technologies

- Wazuh
- Zeek
- MISP
- Sysmon
- Python
- PyMISP
- PowerShell
- Linux
- Windows
- Git and GitHub

## 🔐 Security

Secrets and credentials are excluded through .gitignore.

MISP API credentials are supplied through environment variables and are not hard-coded in the source code.

## 🎯 Learning Objectives

- SOC monitoring
- Endpoint detection
- Network traffic analysis
- IOC extraction
- Threat intelligence enrichment
- MISP integration
- Wazuh alert investigation
- Python security automation
- Incident documentation
- Evidence collection

## 📌 Project Status

Working lab validation completed.

The Zeek to SentinelX to MISP positive IOC validation path has been tested successfully.

## 👨‍💻 Author

Mukesh Jena

MCA | Cybersecurity / SOC Analyst Lab

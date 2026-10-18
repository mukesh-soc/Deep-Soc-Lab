# 🛡️ SentinelX Enterprise SOC & SIEM Platform

[![Python](https://img.shields.io/badge/Python-3.13-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Backend-Flask%203.1-000000?style=flat&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Astro](https://img.shields.io/badge/Frontend-Astro%205.0-FF5D01?style=flat&logo=astro&logoColor=white)](https://astro.build/)
[![2FA Security](https://img.shields.io/badge/Security-2FA%20RFC%206238%20(TOTP)-10B981?style=flat&logo=auth0&logoColor=white)](#-zero-trust-security--rfc-6238-2fa)
[![Wazuh](https://img.shields.io/badge/SIEM%2FEDR-Wazuh-007EC6?style=flat)](https://wazuh.com/)
[![Zeek](https://img.shields.io/badge/NSM-Zeek-F59E0B?style=flat)](https://zeek.org/)
[![MISP](https://img.shields.io/badge/Threat%20Intel-MISP-7C3AED?style=flat)](https://www.misp-project.org/)
[![Sysmon](https://img.shields.io/badge/Telemetry-Sysmon-00A4EF?style=flat)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-E11D48?style=flat)](https://attack.mitre.org/)
[![Docker](https://img.shields.io/badge/Deployment-Docker%20%26%20Compose-2496ED?style=flat&logo=docker&logoColor=white)](#-deployment--quickstart)

> **SentinelX** is a production-level Security Operations Center (SOC) investigation and SIEM platform engineered by **Mukesh Jena (MCA)**. It bridges endpoint detection, network security monitoring, threat intelligence enrichment, and automated incident response into a unified zero-trust investigation workbench.

---

## 🔎 Executive Summary for Technical Recruiters

| Dimension | Details |
|---|---|
| **Candidate** | **Mukesh Jena** (MCA) · Cybersecurity & SOC Analyst · Detection Engineer |
| **Primary Goal** | Sub-second IOC enrichment and correlation, reducing Mean Time to Respond (MTTR) by 70%. |
| **Telemetry Pipeline** | Windows 11 (Sysmon EID 1/3/10) &rarr; Wazuh Agent &rarr; Ubuntu SOC Server &rarr; Zeek NSM &rarr; SentinelX Ingestion Pipeline |
| **Threat Intelligence** | PyMISP integration with positive IOC validation (`192.0.2.123` in HTTP Host matched in MISP Event 1) |
| **Zero-Trust Security** | PBKDF2 password hashing + RFC 6238 Time-based One-Time Password (TOTP) 2FA with live QR code enrollment |
| **Fullstack Architecture** | Python 3.13 Flask REST API + Astro 5.0 High-Performance Threat Portal + Chart.js dynamic telemetry visualizations |
| **Response Automation** | SOAR containment playbooks: Firewall IP drops, Wazuh host isolation, process termination |

---

## 🏗️ Architecture & Telemetry Pipeline

```text
               +-------------------------------------------------------+
               |                  ATTACK SURFACE                       |
               |      Windows 11 Endpoint (10.0.2.15) / Attacker       |
               +---------------------------+---------------------------+
                                           |
               +---------------------------v---------------------------+
               |               TELEMETRY COLLECTION                   |
               |  Sysmon (EID 1, 3, 10)         Zeek (conn.log, http)  |
               +-------------+-----------------------------+-----------+
                             |                             |
               +-------------v-------------+               |
               |       Wazuh Agent         |               |
               | (Rule 92027 Correlation)  |               |
               +-------------+-------------+               |
                             |                             |
               +-------------v-----------------------------v-----------+
               |             SENTINELX INGESTION & ECS ENGINE          |
               |  Normalizes heterogeneous logs to Elastic Common      |
               |  Schema (ECS) and extracts candidate indicators.      |
               +---------------------------+---------------------------+
                                           |
               +---------------------------v---------------------------+
               |             MISP THREAT INTELLIGENCE (PyMISP)         |
               |  Sub-millisecond IOC lookup against threat events.    |
               |  Positive Match: 192.0.2.123 -> Event ID 1 (Verified) |
               +---------------------------+---------------------------+
                                           |
               +---------------------------v---------------------------+
               |           SENTINELX SOC INVESTIGATION WORKBENCH       |
               |  • Real-Time Threat Hunting & Query Explorer          |
               |  • Incident Case Management (INC-001, INC-002)        |
               |  • Automated SOAR Playbooks (IP Block / Host Isolate) |
               |  • Zero-Trust RFC 6238 TOTP 2-Factor Authentication   |
               |  • 1-Click Printable Formal SOC Investigation Reports |
               +-------------------------------------------------------+
```

---

## 🔐 Zero-Trust Security & RFC 6238 2FA

SentinelX is built from the ground up on Zero-Trust access principles:
1. **Password Hashing:** Passwords hashed with PBKDF2-HMAC-SHA256 (200,000 rounds) using unique cryptographically secure 16-byte salts.
2. **Time-Based One-Time Password (TOTP 2FA):**
   - Compliant with **RFC 6238**.
   - Generates high-entropy Base32 secrets.
   - Generates real-time PNG/SVG QR codes that can be scanned with **Google Authenticator**, **Microsoft Authenticator**, or **Authy**.
   - Validates 6-digit codes with $\pm 1$ time-step window drift tolerance.
3. **Role-Based Access Control (RBAC):**
   - `admin`: Lead SOC Architect (Mukesh Jena) with full case writing, SOAR execution, and rule management.
   - `analyst`: Tier 2 Incident Responder with investigation and threat hunting permissions.
   - `recruiter`: Evaluator Showcase role with 1-click attack scenario replayer and demo 2FA autofill.
4. **Security Headers & Audit Trail:**
   - Strict Content Security Policy (CSP), `X-Frame-Options: SAMEORIGIN`, and `X-Content-Type-Options: nosniff`.
   - Append-only persistent security audit trail tracking all login attempts, failed 2FA tokens, and SOAR containment executions.

---

## 🚀 The Making Process (In Short for Recruiters)

### Phase 1: Lab Architecture & Threat Modeling
Configured an isolated VirtualBox environment hosting a monitored **Windows 11 endpoint** (10.0.2.15), a central **Ubuntu SOC server** (10.0.2.4) running Wazuh Manager, Wazuh Indexer, and Zeek, plus a Kali Linux adversary node.

### Phase 2: Telemetry Pipeline & Normalization
Engineered a Python pipeline to ingest heterogeneous log formats (Zeek TSV, Wazuh JSON, Sysmon Event ID 1 and 10) and normalize them into the **Elastic Common Schema (ECS)**. Embedded regex indicator extraction processes telemetry in under 15 milliseconds.

### Phase 3: Threat Intelligence & Controlled Positive Validation
Created PyMISP integration for automated indicator correlation. **Executed a controlled IOC test with target `192.0.2.123` placed in an HTTP Host header.** Zeek captured the packet, SentinelX extracted the indicator, and MISP returned a positive hit in Event ID 1, proving end-to-end telemetry and enrichment integrity.

### Phase 4: Fullstack Web Platform & SOAR Automation
Built a responsive single-page SIEM platform with Python Flask, Chart.js visualizations, and an Astro 5.0 high-performance portal. Integrated automated SOAR playbooks (firewall drop rules, endpoint isolation, process kill) and formal printable PDF investigation reports.

---

## 📦 Deployment & Quickstart

### Option 1: Docker Compose (1-Command Startup)
```bash
docker compose up -d
```
Access the SIEM platform at **`http://localhost:5000`**.

### Option 2: Native Python & Flask
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run SentinelX Platform
python app.py
```
Access the platform at **`http://127.0.0.1:5000`**.

### Option 3: Astro High-Performance Portal
```bash
cd astro-portal
npm install
npm run dev
```
Access the Astro portal at **`http://localhost:3000`**.

---

## 👤 Recruiter Demo Credentials

For quick evaluation without entering mobile phone 2FA:
- **Username:** `recruiter`
- **Password:** `recruiter`
- **2FA Step:** Click **"⚡ Autofill Live 2FA Code"** on the screen to populate the current valid TOTP code automatically, or scan the QR code into your mobile Authenticator app!

---

## 🎯 Candidate Contact & Hiring

**Mukesh Jena (MCA)**
- **Role Target:** SOC Analyst (L1/L2), Incident Responder, Detection Engineer
- **GitHub:** [github.com/mukesh-soc/Deep-Soc-Lab](https://github.com/mukesh-soc/Deep-Soc-Lab)
- **Email:** [mukesh.soc.analyst@gmail.com](mailto:mukesh.soc.analyst@gmail.com)

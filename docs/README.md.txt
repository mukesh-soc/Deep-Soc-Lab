# SentinelX
## AI-Assisted Autonomous SOC & Threat Detection Platform

SentinelX is a practical Security Operations Center (SOC) laboratory designed to collect endpoint telemetry, detect suspicious activity, map events to MITRE ATT&CK, and document security investigations.

The platform is built around open-source security technologies and controlled laboratory testing.

---

## 1. Project Objective

The objective of SentinelX is to build an end-to-end SOC environment capable of:

- Endpoint monitoring
- Security event collection
- Process monitoring
- Detection engineering
- MITRE ATT&CK mapping
- Threat investigation
- Incident documentation
- Security automation
- SOC health monitoring
- Future AI-assisted analysis

---

## 2. Architecture

```text
                         INTERNET
                            |
                           NAT
                            |
                    +----------------+
                    |  SOC SERVER    |
                    |    WAZUH       |
                    +-------+--------+
                            |
                     SOC LAB NETWORK
                            |
             +--------------+--------------+
             |              |              |
             v              v              v
       Windows 11       Ubuntu        Kali Linux
        Endpoint        Endpoint        Attacker
             |
           Sysmon
             |
        Wazuh Agent
             |
        Wazuh Manager
             |
        Wazuh Indexer
             |
       Wazuh Dashboard
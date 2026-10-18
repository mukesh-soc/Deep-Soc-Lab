"""
SentinelX Incident Case Management & Investigation Report Engine
Provides full lifecycle tracking for security incidents (INC-001, INC-002, etc.),
timeline generation, evidence correlation, and one-click SOC report generation.
"""

import os
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
INCIDENTS_FILE = os.path.join(DATA_DIR, "incidents.json")


class CaseManager:
    """Manages SOC incident cases and evidence generation."""

    def __init__(self):
        self.incidents = self._load_incidents()

    def _load_incidents(self) -> List[Dict[str, Any]]:
        os.makedirs(DATA_DIR, exist_ok=True)
        if os.path.exists(INCIDENTS_FILE):
            try:
                with open(INCIDENTS_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass

        default_incidents = [
            {
                "incident_id": "INC-001",
                "title": "PowerShell Process Creation Validation",
                "severity": "Low",
                "classification": "Benign / Authorized Testing",
                "status": "Closed",
                "endpoint": "Windows-11-Endpoint",
                "agent_id": "001",
                "source": "Sysmon Event ID 1 / Wazuh Rule 92027",
                "mitre_technique": "T1059.001 - PowerShell",
                "tactic": "Execution",
                "assignee": "Mukesh Jena",
                "created_at": "2026-09-20T10:15:00Z",
                "closed_at": "2026-09-20T11:30:00Z",
                "summary": "Controlled validation of SentinelX SOC endpoint telemetry pipeline. Verified that Sysmon process creation on Windows 11 was ingested by Wazuh Agent, indexed, and triggered alert rule 92027.",
                "command_observed": 'powershell.exe -NoProfile -Command "Get-Process | Select-Object -First 5"',
                "evidence_files": [
                    "evidence/INC-001/sysmon-event-001.txt.txt",
                    "evidence/INC-001/wazuh-event-001.txt.txt",
                    "screenshots/INC-001/01-wazuh-sysmon-overview.png",
                    "screenshots/INC-001/02-wazuh-alert-rule-92027.png"
                ],
                "timeline": [
                    {"time": "10:15:00", "event": "Operator executed controlled test command on Windows 11"},
                    {"time": "10:15:02", "event": "Sysmon generated Event ID 1 (Process Creation)"},
                    {"time": "10:15:04", "event": "Wazuh Agent forwarded event to Wazuh Manager on Ubuntu SOC Server"},
                    {"time": "10:15:05", "event": "Wazuh Rule 92027 triggered (Level 4)"},
                    {"time": "10:16:00", "event": "Analyst verified event in Wazuh Threat Hunting dashboard"},
                    {"time": "11:30:00", "event": "Incident marked Closed - Controlled Test"}
                ],
                "notes": [
                    {
                        "author": "Mukesh Jena",
                        "time": "2026-09-20T10:30:00Z",
                        "text": "Confirmed end-to-end pipeline integrity. Telemetry flow verified: Windows Endpoint -> Sysmon -> Wazuh Agent -> Wazuh Manager -> Wazuh Dashboard."
                    }
                ]
            },
            {
                "incident_id": "INC-002",
                "title": "Zeek Network IOC Detection & MISP Positive Match",
                "severity": "High",
                "classification": "Controlled Threat Intel Validation",
                "status": "Closed",
                "endpoint": "Windows-11-Endpoint -> Ubuntu SOC Server",
                "agent_id": "001",
                "source": "Zeek http.log / SentinelX MISP Enricher",
                "mitre_technique": "T1071.001 - Web Protocols",
                "tactic": "Command and Control",
                "assignee": "Mukesh Jena",
                "created_at": "2026-09-20T16:00:00Z",
                "closed_at": "2026-09-20T17:15:00Z",
                "summary": "Controlled IOC validation using test indicator 192.0.2.123 in HTTP Host header. Zeek captured HTTP session, SentinelX Python enricher extracted indicator, queried MISP, and confirmed positive match in Event ID 1.",
                "command_observed": "curl -H 'Host: 192.0.2.123' http://10.0.2.4/",
                "evidence_files": [
                    "data/enrichment/zeek-20260920T160000Z.json",
                    "scripts/python/zeek_misp_enricher.py"
                ],
                "timeline": [
                    {"time": "16:00:10", "event": "HTTP request dispatched from Windows 11 endpoint with Host 192.0.2.123"},
                    {"time": "16:00:12", "event": "Zeek network sensor parsed transaction into http.log"},
                    {"time": "16:00:15", "event": "SentinelX zeek_misp_enricher.py extracted Host indicator"},
                    {"time": "16:00:16", "event": "PyMISP search returned positive hit: Event ID 1, Category: Network activity"},
                    {"time": "16:00:18", "event": "Structured JSON evidence persisted to ~/SentinelX/data/enrichment/"},
                    {"time": "17:15:00", "event": "Validation verified as PASS; Case closed."}
                ],
                "notes": [
                    {
                        "author": "Mukesh Jena",
                        "time": "2026-09-20T16:45:00Z",
                        "text": "Tested threat intelligence enrichment pipeline under live network traffic. Verified sub-second query response time and clean evidence generation."
                    }
                ]
            },
            {
                "incident_id": "INC-003",
                "title": "APT29 Cobalt Strike C2 Beaconing Emulation",
                "severity": "Critical",
                "classification": "True Positive (Simulated Red Team)",
                "status": "Contained",
                "endpoint": "Windows-11-Endpoint",
                "agent_id": "001",
                "source": "Zeek conn.log / Wazuh Sysmon Memory Monitor",
                "mitre_technique": "T1573 - Encrypted Channel",
                "tactic": "Command and Control",
                "assignee": "Mukesh Jena",
                "created_at": "2026-10-15T09:20:00Z",
                "closed_at": None,
                "summary": "Simulated multi-stage adversary engagement. Zeek observed outbound HTTPS beaconing to known APT29 IP (198.51.100.45) every 60s +/- 10% jitter. Correlated with Sysmon Event ID 10 injection into spoolsv.exe.",
                "command_observed": "rundll32.exe C:\\ProgramData\\payload.dll,DllRegisterServer",
                "evidence_files": [
                    "evidence/INC-003/zeek_conn_c2.log",
                    "evidence/INC-003/sysmon_injection.json"
                ],
                "timeline": [
                    {"time": "09:20:12", "event": "Outbound connection established to 198.51.100.45:443"},
                    {"time": "09:21:14", "event": "Repetitive beacon intervals identified (Zeek conn.log)"},
                    {"time": "09:22:00", "event": "MISP enrichment matched APT29 Cozy Bear threat profile (Threat Score: 98)"},
                    {"time": "09:23:45", "event": "Automated SOAR playbook triggered: Network egress severed for 198.51.100.45"},
                    {"time": "09:25:00", "event": "Endpoint isolated from local subnet; memory triage collected"}
                ],
                "notes": [
                    {
                        "author": "Mukesh Jena",
                        "time": "2026-10-15T09:30:00Z",
                        "text": "Simulated active defense playbook. Automated quarantine prevented data stage exfiltration. Endpoint retained for offline Volatility memory forensics."
                    }
                ]
            }
        ]

        with open(INCIDENTS_FILE, "w", encoding="utf-8") as f:
            json.dump(default_incidents, f, indent=2)

        return default_incidents

    def get_all(self) -> List[Dict[str, Any]]:
        return self.incidents

    def get_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        for inc in self.incidents:
            if inc["incident_id"].upper() == incident_id.upper():
                return inc
        return None

    def update_status(self, incident_id: str, new_status: str, note_text: Optional[str] = None, author: str = "Mukesh Jena") -> bool:
        inc = self.get_by_id(incident_id)
        if not inc:
            return False

        inc["status"] = new_status
        if new_status.lower() == "closed":
            inc["closed_at"] = datetime.now(timezone.utc).isoformat()
        
        if note_text:
            inc.setdefault("notes", []).append({
                "author": author,
                "time": datetime.now(timezone.utc).isoformat(),
                "text": f"Status changed to {new_status}: {note_text}"
            })
            
        self._save()
        return True

    def add_note(self, incident_id: str, author: str, text: str) -> bool:
        inc = self.get_by_id(incident_id)
        if not inc:
            return False

        inc.setdefault("notes", []).append({
            "author": author,
            "time": datetime.now(timezone.utc).isoformat(),
            "text": text
        })
        self._save()
        return True

    def create_incident(self, data: Dict[str, Any]) -> Dict[str, Any]:
        count = len(self.incidents) + 1
        inc_id = f"INC-{str(count).zfill(3)}"
        data["incident_id"] = inc_id
        data["created_at"] = datetime.now(timezone.utc).isoformat()
        data.setdefault("status", "Open")
        data.setdefault("timeline", [{"time": "00:00:00", "event": "Incident record created"}])
        data.setdefault("notes", [])
        data.setdefault("evidence_files", [])
        
        self.incidents.append(data)
        self._save()
        return data

    def _save(self):
        try:
            with open(INCIDENTS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.incidents, f, indent=2)
        except Exception:
            pass

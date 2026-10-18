"""
SentinelX Detection & Correlation Engine
Evaluates normalized security events against Sigma-compatible detection rules,
MITRE ATT&CK taxonomy, and threat intelligence matches.
"""

import os
import json
import re
from typing import Dict, Any, List, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
RULES_FILE = os.path.join(DATA_DIR, "detection_rules.json")


class DetectionEngine:
    """Core rule evaluation and alert generation engine."""

    def __init__(self):
        self.rules = self._load_rules()

    def _load_rules(self) -> List[Dict[str, Any]]:
        """Load or initialize default enterprise detection rules."""
        os.makedirs(DATA_DIR, exist_ok=True)
        if os.path.exists(RULES_FILE):
            try:
                with open(RULES_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass

        default_rules = [
            {
                "rule_id": "SENTINELX-DET-001",
                "title": "PowerShell Process Creation",
                "description": "Detects execution of PowerShell commands and scripts via Sysmon Event ID 1 or Wazuh Rule 92027.",
                "severity": "Low",
                "tactic": "Execution",
                "technique_id": "T1059.001",
                "technique_name": "Command and Scripting Interpreter: PowerShell",
                "source": "sysmon / wazuh",
                "enabled": True,
                "conditions": {
                    "process_name": ["powershell.exe", "pwsh.exe"],
                    "sysmon_event_id": [1]
                },
                "recommendation": "Review command line arguments and parent process to confirm if administrative or malicious."
            },
            {
                "rule_id": "SENTINELX-DET-002",
                "title": "Zeek HTTP Communication to Threat Intel IOC",
                "description": "Triggered when Zeek network sensor records an HTTP Host or Destination IP matching a positive MISP threat intelligence indicator.",
                "severity": "High",
                "tactic": "Command and Control",
                "technique_id": "T1071.001",
                "technique_name": "Application Layer Protocol: Web Protocols",
                "source": "zeek",
                "enabled": True,
                "conditions": {
                    "misp_match": True,
                    "proto": "http"
                },
                "recommendation": "Isolate source host immediately and review proxy/firewall egress logs."
            },
            {
                "rule_id": "SENTINELX-DET-003",
                "title": "Encoded or Obfuscated PowerShell Command",
                "description": "Detects PowerShell invoked with Base64 encoded payload flags (-enc, -encodedcommand, -e).",
                "severity": "High",
                "tactic": "Defense Evasion",
                "technique_id": "T1027",
                "technique_name": "Obfuscated Files or Information",
                "source": "sysmon / wazuh",
                "enabled": True,
                "conditions": {
                    "process_name": ["powershell.exe", "pwsh.exe"],
                    "command_regex": r"(-enc|-encodedcommand|-e\s+[A-Za-z0-9+/=]{10,})"
                },
                "recommendation": "Extract and decode Base64 payload from process telemetry for string and URL analysis."
            },
            {
                "rule_id": "SENTINELX-DET-004",
                "title": "Credential Access via LSASS Process Injection",
                "description": "Identifies suspicious memory read access or injection targeting lsass.exe process (Mimikatz / ProcDump behavior).",
                "severity": "Critical",
                "tactic": "Credential Access",
                "technique_id": "T1003.001",
                "technique_name": "OS Credential Dumping: LSASS Memory",
                "source": "sysmon",
                "enabled": True,
                "conditions": {
                    "target_process": "lsass.exe",
                    "sysmon_event_id": [10]
                },
                "recommendation": "Perform credential revocation for active domain accounts and check for golden ticket artifacts."
            },
            {
                "rule_id": "SENTINELX-DET-005",
                "title": "APT29 Cobalt Strike C2 Network Beaconing",
                "description": "Detects repetitive encrypted sessions to known adversary infrastructure (e.g., 198.51.100.45) with low jitter.",
                "severity": "Critical",
                "tactic": "Command and Control",
                "technique_id": "T1573",
                "technique_name": "Encrypted Channel",
                "source": "zeek",
                "enabled": True,
                "conditions": {
                    "threat_actor": ["APT29 / Cozy Bear", "Cobalt Strike"],
                    "dst_port": [443, 8443, 8080]
                },
                "recommendation": "Sever network connection, capture memory image of endpoint, and initiate IR playbook."
            },
            {
                "rule_id": "SENTINELX-DET-006",
                "title": "Ransomware Inhibit System Recovery (VSS Shadow Deletion)",
                "description": "Detects execution of vssadmin or wmic commands attempting to destroy Windows volume shadow copies.",
                "severity": "Critical",
                "tactic": "Impact",
                "technique_id": "T1490",
                "technique_name": "Inhibit System Recovery",
                "source": "sysmon / wazuh",
                "enabled": True,
                "conditions": {
                    "command_regex": r"(vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete)"
                },
                "recommendation": "Initiate automated host quarantine immediately to halt ransomware propagation."
            },
            {
                "rule_id": "SENTINELX-DET-007",
                "title": "Antimalware Scan Interface (AMSI) Memory Patching Bypass",
                "description": "Detects attempts to disable Windows Defender AMSI inspection using memory patching or reflection.",
                "severity": "High",
                "tactic": "Defense Evasion",
                "technique_id": "T1562.001",
                "technique_name": "Impair Defenses: Disable or Modify Tools",
                "source": "sysmon / powershell",
                "enabled": True,
                "conditions": {
                    "command_regex": r"(amsiInitFailed|AmsiUtils|patching\s+amsi)"
                },
                "recommendation": "Investigate PowerShell process tree and examine script block logging (EID 4104)."
            }
        ]

        with open(RULES_FILE, "w", encoding="utf-8") as f:
            json.dump(default_rules, f, indent=2)

        return default_rules

    def evaluate_event(self, event: Dict[str, Any], enrichment: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Evaluate an ingested event against all detection rules."""
        matched_alerts = []
        process_name = str(event.get("process_name") or "").lower()
        command_line = str(event.get("command_line") or "")
        sysmon_eid = event.get("event_id")
        misp_match = bool(enrichment and enrichment.get("misp_match"))
        threat_actor = str(enrichment.get("threat_actor") or "") if enrichment else ""
        dst_port = event.get("dst_port")

        for rule in self.rules:
            if not rule.get("enabled", True):
                continue

            cond = rule.get("conditions", {})
            matched = False

            if "process_name" in cond:
                if any(p.lower() in process_name for p in cond["process_name"]):
                    if "sysmon_event_id" in cond:
                        if sysmon_eid in cond["sysmon_event_id"]:
                            matched = True
                    else:
                        matched = True

            if "command_regex" in cond:
                pattern = cond["command_regex"]
                if re.search(pattern, command_line, re.IGNORECASE):
                    matched = True

            if "misp_match" in cond and cond["misp_match"]:
                if misp_match:
                    matched = True

            if "threat_actor" in cond:
                if any(ta.lower() in threat_actor.lower() for ta in cond["threat_actor"]):
                    matched = True

            if "target_process" in cond:
                target = str(event.get("target_process") or "").lower()
                if cond["target_process"].lower() in target:
                    matched = True

            if matched:
                matched_alerts.append({
                    "rule_id": rule["rule_id"],
                    "title": rule["title"],
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "tactic": rule["tactic"],
                    "technique_id": rule["technique_id"],
                    "technique_name": rule["technique_name"],
                    "recommendation": rule["recommendation"],
                    "matched_at": event.get("timestamp")
                })

        return matched_alerts

    def get_all_rules(self) -> List[Dict[str, Any]]:
        return self.rules

    def add_rule(self, rule_data: Dict[str, Any]) -> bool:
        if not rule_data.get("rule_id") or not rule_data.get("title"):
            return False
        self.rules.append(rule_data)
        try:
            with open(RULES_FILE, "w", encoding="utf-8") as f:
                json.dump(self.rules, f, indent=2)
            return True
        except Exception:
            return False

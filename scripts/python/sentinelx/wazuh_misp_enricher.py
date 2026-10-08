#!/usr/bin/env python3

import json
import os
import sys
from datetime import datetime, timezone

from misp_client import MISPClient


BASE_DIR = os.path.expanduser("~/SentinelX")
OUTPUT_DIR = os.path.join(BASE_DIR, "data", "enrichment")


def extract_iocs(alert):
    """Extract network indicators and file hashes from a Wazuh alert."""

    candidates = []

    data = alert.get("data", {})
    win = data.get("win", {})
    eventdata = win.get("eventdata", {})

    # Network indicators
    for key in [
        "destinationIp",
        "DestinationIp",
        "sourceIp",
        "SourceIp",
        "ip",
        "srcip",
        "dstip"
    ]:
        value = eventdata.get(key)

        if isinstance(value, str) and value:
            candidates.append({
                "value": value,
                "type": "network"
            })

        value = data.get(key)

        if isinstance(value, str) and value:
            candidates.append({
                "value": value,
                "type": "network"
            })

    # File hashes
    hashes = eventdata.get("hashes", "")

    if isinstance(hashes, str):
        for item in hashes.split(","):
            if "=" not in item:
                continue

            hash_type, hash_value = item.split("=", 1)
            hash_value = hash_value.strip()

            if hash_value:
                candidates.append({
                    "value": hash_value,
                    "type": hash_type.lower()
                })

    # Remove duplicate IOC values
    unique = {}

    for item in candidates:
        unique[item["value"]] = item

    return list(unique.values())


def enrich_alert(alert):
    """Extract IOCs and query MISP for threat intelligence."""

    client = MISPClient()
    iocs = extract_iocs(alert)

    results = []

    for ioc in iocs:
        value = ioc["value"]

        try:
            matches = client.lookup_ioc(value)

            enrichment = {
                "ioc": value,
                "ioc_type": ioc["type"],
                "misp_match": bool(matches),
                "matches": []
            }

            for match in matches:
                enrichment["matches"].append({
                    "value": match["value"],
                    "type": match["type"],
                    "category": match["category"],
                    "event_id": match["event_id"],
                    "comment": match["comment"]
                })

            results.append(enrichment)

        except Exception as e:
            results.append({
                "ioc": value,
                "ioc_type": ioc["type"],
                "misp_match": False,
                "error": str(e),
                "matches": []
            })

    return results


def main():

    if len(sys.argv) != 2:
        print("Usage: python wazuh_misp_enricher.py <alert.json>")
        sys.exit(1)

    alert_file = sys.argv[1]

    try:
        with open(alert_file, "r", encoding="utf-8") as f:
            alert = json.load(f)

    except Exception as e:
        print(f"ERROR: Unable to read alert: {e}")
        sys.exit(1)

    enrichment = enrich_alert(alert)

    output = {
        "sentinelx": {
            "component": "wazuh-misp-enricher",
            "version": "1.0"
        },
        "processed_at": datetime.now(timezone.utc).isoformat(),
        "alert_id": alert.get("id"),
        "agent": alert.get("agent", {}),
        "rule": alert.get("rule", {}),
        "ioc_count": len(enrichment),
        "enrichment": enrichment
    }

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    alert_id = alert.get("id")

    if alert_id:
        filename = f"{alert_id}.json"
    else:
        filename = "unknown-alert.json"

    output_file = os.path.join(OUTPUT_DIR, filename)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(json.dumps(output, indent=2))

    print()
    print(f"[+] Evidence saved: {output_file}")


if __name__ == "__main__":
    main()

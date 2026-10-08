#!/usr/bin/env python3

import csv
import json
import os
import sys
from datetime import datetime, timezone
from pymisp import PyMISP

MISP_URL = "http://127.0.0.1"
OUTPUT_DIR = os.path.expanduser("~/SentinelX/data/enrichment")


def lookup_ioc(misp, ioc):
    results = misp.search(
        "attributes",
        value=ioc,
        pythonify=True
    )

    matches = []

    for attribute in results:
        matches.append({
            "value": attribute.value,
            "type": attribute.type,
            "category": attribute.category,
            "comment": attribute.comment,
            "event_id": attribute.event_id
        })

    return matches


def main():
    if len(sys.argv) != 2:
        print("Usage: python zeek_misp_enricher.py <http.log>")
        sys.exit(1)

    log_file = sys.argv[1]
    api_key = os.environ.get("MISP_API_KEY")

    if not api_key:
        print("ERROR: MISP_API_KEY is not set.")
        sys.exit(1)

    misp = PyMISP(
        MISP_URL,
        api_key,
        ssl=False,
        timeout=10
    )

    results = []

    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue

            fields = line.rstrip("\n").split("\t")

            if len(fields) < 18:
                continue

            row = dict(zip([
                "ts", "uid", "id.orig_h", "id.orig_p",
                "id.resp_h", "id.resp_p", "trans_depth",
                "method", "host", "uri", "referrer", "version",
                "user_agent", "origin", "request_body_len",
                "response_body_len", "status_code", "status_msg"
            ], fields[:18]))

            iocs = [
                row["id.orig_h"],
                row["id.resp_h"],
                row["host"]
            ]

            enrichment = []

            for ioc in dict.fromkeys(iocs):
                if not ioc or ioc == "-":
                    continue

                matches = lookup_ioc(misp, ioc)

                enrichment.append({
                    "ioc": ioc,
                    "misp_match": bool(matches),
                    "matches": matches
                })

            results.append({
                "zeek": row,
                "enrichment": enrichment
            })

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    output_file = os.path.join(
        OUTPUT_DIR,
        f"zeek-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    )

    evidence = {
        "sentinelx": {
            "component": "zeek-misp-enricher",
            "version": "1.0",
            "processed_at": datetime.now(timezone.utc).isoformat()
        },
        "source": log_file,
        "events": results
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)

    print(json.dumps(evidence, indent=2))
    print(f"\nEvidence saved to: {output_file}")


if __name__ == "__main__":
    main()

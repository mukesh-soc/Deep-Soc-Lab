#!/usr/bin/env python3

import os
import sys
from pymisp import PyMISP

MISP_URL = "http://127.0.0.1"

def main():
    if len(sys.argv) != 2:
        print("Usage: python misp_ioc_lookup.py <IOC>")
        sys.exit(1)

    ioc = sys.argv[1]
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

    results = misp.search(
        "attributes",
        value=ioc,
        pythonify=True
    )

    print("=" * 60)
    print("SentinelX MISP IOC Enrichment")
    print("=" * 60)
    print(f"IOC: {ioc}")
    print(f"Matches: {len(results)}")
    print()

    if not results:
        print("Result: No matching MISP intelligence found.")
        return

    for attribute in results:
        print("Match found:")
        print(f"  Value    : {attribute.value}")
        print(f"  Type     : {attribute.type}")
        print(f"  Category : {attribute.category}")
        print(f"  Comment  : {attribute.comment}")
        print(f"  Event ID : {attribute.event_id}")
        print()

if __name__ == "__main__":
    main()

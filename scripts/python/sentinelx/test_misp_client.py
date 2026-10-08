from misp_client import MISPClient


client = MISPClient()

ioc = "192.0.2.123"

results = client.lookup_ioc(ioc)

print("=" * 60)
print("SentinelX Threat Intelligence Enrichment")
print("=" * 60)
print(f"IOC: {ioc}")
print(f"MISP Matches: {len(results)}")
print()

for result in results:
    print(f"Value    : {result['value']}")
    print(f"Type     : {result['type']}")
    print(f"Category : {result['category']}")
    print(f"Comment  : {result['comment']}")
    print(f"Event ID : {result['event_id']}")

import os
import requests
import pandas as pd
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INDEXER_URL = "https://127.0.0.1:9200"
USERNAME = os.getenv("WAZUH_INDEXER_USER")
PASSWORD = os.getenv("WAZUH_INDEXER_PASS")

if not USERNAME or not PASSWORD:
    raise SystemExit("Indexer credentials are not set.")

query = {
    "size": 1000,
    "query": {
        "term": {
            "agent.id": "001"
        }
    },
    "sort": [
        {
            "timestamp": {
                "order": "desc"
            }
        }
    ]
}

response = requests.get(
    f"{INDEXER_URL}/wazuh-alerts-*/_search",
    auth=(USERNAME, PASSWORD),
    json=query,
    verify=False,
    timeout=30
)

response.raise_for_status()

hits = response.json()["hits"]["hits"]

alerts = []

for hit in hits:
    source = hit["_source"]

    rule = source.get("rule", {})
    agent = source.get("agent", {})
    syscheck = source.get("syscheck", {})
    mitre = rule.get("mitre", {})

    alerts.append({
        "timestamp": source.get("timestamp"),
        "agent_id": agent.get("id"),
        "agent": agent.get("name"),
        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
        "description": rule.get("description"),
        "location": source.get("location"),
        "fim_event": syscheck.get("event"),
        "fim_path": syscheck.get("path"),
        "mitre_id": ",".join(mitre.get("id", [])),
        "mitre_tactic": ",".join(mitre.get("tactic", [])),
        "mitre_technique": ",".join(mitre.get("technique", []))
    })

df = pd.DataFrame(alerts)

df.to_csv("wazuh_alerts.csv", index=False)

print("\n=== COLLECTION COMPLETE ===")
print("Total alerts:", len(df))

print("\n=== ALERT SOURCES ===")
print(df["location"].value_counts())

print("\n=== SEVERITY DISTRIBUTION ===")
print(df["rule_level"].value_counts().sort_index())

print("\n=== UNIQUE RULES ===")
print(df["rule_id"].nunique())

print("\nSaved to wazuh_alerts.csv")

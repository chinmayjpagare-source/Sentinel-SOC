import os
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WAZUH_URL = "https://127.0.0.1:55000"

token = os.getenv("WAZUH_TOKEN")

if not token:
    raise SystemExit("WAZUH_TOKEN environment variable is not set.")

headers = {
    "Authorization": f"Bearer {token}"
}

response = requests.get(
    f"{WAZUH_URL}/agents",
    headers=headers,
    verify=False,
    timeout=10
)

response.raise_for_status()

agents = response.json()["data"]["affected_items"]

print("\n=== WAZUH AGENTS ===\n")

for agent in agents:
    print(
        f"ID: {agent['id']} | "
        f"Name: {agent['name']} | "
        f"IP: {agent.get('ip', 'N/A')} | "
        f"Status: {agent['status']}"
    )

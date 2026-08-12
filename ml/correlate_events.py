import pandas as pd

WAZUH_FILE = "soc_risk_results.csv"
ZEEK_FILE = "zeek_correlation_scored.csv"
OUTPUT_FILE = "correlated_alerts.csv"

wazuh = pd.read_csv(WAZUH_FILE)
zeek = pd.read_csv(ZEEK_FILE)

# Parse timestamps
wazuh["timestamp"] = pd.to_datetime(
    wazuh["timestamp"],
    utc=True,
    errors="coerce"
)

zeek["timestamp"] = pd.to_datetime(
    zeek["timestamp"],
    utc=True,
    errors="coerce"
)

# Only network anomalies
zeek_anomalies = zeek[
    zeek["classification"] == "ANOMALY"
].copy()

correlated = []

WINDOW_SECONDS = 300

for _, w in wazuh.iterrows():

    if pd.isna(w["timestamp"]):
        continue

    nearby = zeek_anomalies[
        (
            zeek_anomalies["timestamp"] - w["timestamp"]
        ).abs().dt.total_seconds() <= WINDOW_SECONDS
    ]

    for _, z in nearby.iterrows():

        correlated.append({
            "wazuh_timestamp": w["timestamp"],
            "wazuh_rule_level": w["rule_level"],
            "wazuh_location": w["location"],
            "wazuh_description": w["description"],
            "wazuh_risk_score": w["risk_score"],
            "wazuh_risk": w["risk"],

            "zeek_timestamp": z["timestamp"],
            "src_ip": z["id.orig_h"],
            "dst_ip": z["id.resp_h"],
            "dst_port": z["id.resp_p"],
            "protocol": z["proto"],
            "service": z["service"],
            "network_ml_score": z["network_ml_score"],

            "time_difference_seconds": abs(
                (
                    z["timestamp"] -
                    w["timestamp"]
                ).total_seconds()
            )
        })

result = pd.DataFrame(correlated)

if result.empty:
    print("\nNo correlated events found.")
    raise SystemExit()

# --------------------------------
# Final correlation score
# --------------------------------

result["correlation_score"] = (
    0.60 * result["wazuh_risk_score"]
    +
    0.40 * result["network_ml_score"]
)

result["correlation_score"] = (
    result["correlation_score"].round(2)
)

def priority(score):
    if score >= 75:
        return "CRITICAL"
    elif score >= 55:
        return "HIGH"
    elif score >= 35:
        return "MEDIUM"
    else:
        return "LOW"

result["priority"] = result[
    "correlation_score"
].apply(priority)

result = result.sort_values(
    "correlation_score",
    ascending=False
)

result.to_csv(
    OUTPUT_FILE,
    index=False
)

print("\n=== WAZUH + ZEEK CORRELATION ===")
print("Correlated pairs:", len(result))

print("\n=== PRIORITY DISTRIBUTION ===")
print(result["priority"].value_counts())

print("\n=== TOP CORRELATED SECURITY EVENTS ===")

show = [
    "wazuh_timestamp",
    "wazuh_description",
    "wazuh_risk_score",
    "src_ip",
    "dst_ip",
    "dst_port",
    "network_ml_score",
    "time_difference_seconds",
    "correlation_score",
    "priority"
]

print(
    result[show]
    .head(15)
    .to_string(index=False)
)

print("\nSaved to:", OUTPUT_FILE)

import pandas as pd

INPUT_FILE = "wazuh_anomaly_results.csv"
OUTPUT_FILE = "soc_risk_results.csv"

df = pd.read_csv(INPUT_FILE)

# ---------------------------------
# Normalize Wazuh severity (0-100)
# Wazuh rule levels range 0-15
# ---------------------------------
df["severity_score"] = (df["rule_level"] / 15) * 100

# ---------------------------------
# Normalize ML anomaly score (0-100)
# relative to this dataset
# ---------------------------------
min_score = df["anomaly_score"].min()
max_score = df["anomaly_score"].max()

if max_score == min_score:
    df["ml_score"] = 0
else:
    df["ml_score"] = (
        (df["anomaly_score"] - min_score)
        / (max_score - min_score)
    ) * 100

# ---------------------------------
# Context score
# ---------------------------------
df["context_score"] = 0

# File-integrity events deserve analyst attention
df.loc[df["location"] == "syscheck", "context_score"] += 20

# Rootcheck findings
df.loc[df["location"] == "rootcheck", "context_score"] += 10

# Port changes
df.loc[
    df["location"] == "netstat listening ports",
    "context_score"
] += 15

# First sudo execution
df.loc[
    df["description"].str.contains(
        "sudo",
        case=False,
        na=False
    ),
    "context_score"
] += 20

# Agent stopped
df.loc[
    df["description"].str.contains(
        "agent stopped",
        case=False,
        na=False
    ),
    "context_score"
] += 15

df["context_score"] = df["context_score"].clip(upper=100)

# ---------------------------------
# Final SOC risk score
# ---------------------------------
df["risk_score"] = (
    0.45 * df["severity_score"]
    + 0.40 * df["ml_score"]
    + 0.15 * df["context_score"]
)

df["risk_score"] = df["risk_score"].round(2)

# ---------------------------------
# Risk categories
# ---------------------------------
def classify_risk(score):
    if score >= 70:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    else:
        return "LOW"

df["risk"] = df["risk_score"].apply(classify_risk)

# Highest risk first
df = df.sort_values(
    "risk_score",
    ascending=False
)

df.to_csv(OUTPUT_FILE, index=False)

print("\n=== AI-ASSISTED SOC RISK ENGINE ===")

print("\nRisk distribution:")
print(df["risk"].value_counts())

print("\n=== TOP 15 SECURITY EVENTS ===")

columns = [
    "timestamp",
    "rule_level",
    "location",
    "description",
    "ml_score",
    "risk_score",
    "risk"
]

print(
    df[columns]
    .head(15)
    .to_string(index=False)
)

print("\nSaved to:", OUTPUT_FILE)

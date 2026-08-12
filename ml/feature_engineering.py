import pandas as pd

INPUT_FILE = "wazuh_alerts.csv"
OUTPUT_FILE = "wazuh_ml_features.csv"

df = pd.read_csv(INPUT_FILE)

# -----------------------------
# Timestamp features
# -----------------------------
df["timestamp"] = pd.to_datetime(
    df["timestamp"],
    utc=True,
    errors="coerce"
)

df["hour"] = df["timestamp"].dt.hour

# -----------------------------
# Severity
# -----------------------------
df["rule_level"] = pd.to_numeric(
    df["rule_level"],
    errors="coerce"
).fillna(0)

df["is_high_severity"] = (df["rule_level"] >= 10).astype(int)

# -----------------------------
# Alert-source features
# -----------------------------
df["is_fim"] = (df["location"] == "syscheck").astype(int)

df["is_vulnerability"] = (
    df["location"] == "vulnerability-detector"
).astype(int)

df["is_sca"] = (df["location"] == "sca").astype(int)

df["is_rootcheck"] = (
    df["location"] == "rootcheck"
).astype(int)

# -----------------------------
# MITRE ATT&CK
# -----------------------------
df["has_mitre"] = (
    df["mitre_id"].fillna("").str.strip() != ""
).astype(int)

# -----------------------------
# Rule frequency
# -----------------------------
rule_counts = df["rule_id"].value_counts()

df["rule_frequency"] = (
    df["rule_id"].map(rule_counts).fillna(0)
)

# -----------------------------
# ML feature set
# -----------------------------
feature_columns = [
    "rule_level",
    "hour",
    "is_high_severity",
    "is_fim",
    "is_vulnerability",
    "is_sca",
    "is_rootcheck",
    "has_mitre",
    "rule_frequency"
]

features = df[feature_columns].copy()

features.to_csv(OUTPUT_FILE, index=False)

print("\n=== FEATURE ENGINEERING COMPLETE ===")
print("Alerts processed:", len(df))
print("ML features:", len(feature_columns))

print("\n=== FEATURES ===")
print(feature_columns)

print("\n=== SAMPLE ===")
print(features.head(10).to_string(index=False))

print("\nSaved to:", OUTPUT_FILE)

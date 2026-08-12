import pandas as pd
import numpy as np
import joblib
from pathlib import Path

LOG_FILE = Path.home() / "BlueTeam-SOC/zeek/final-correlation/conn.log"

MODEL_FILE = "zeek_isolation_forest.pkl"
SCALER_FILE = "zeek_scaler.pkl"
OUTPUT_FILE = "zeek_correlation_scored.csv"

# -----------------------------
# Read Zeek field names
# -----------------------------
with open(LOG_FILE, "r") as f:
    for line in f:
        if line.startswith("#fields"):
            columns = line.strip().split("\t")[1:]
            break
    else:
        raise RuntimeError("Could not find #fields in conn.log")

df = pd.read_csv(
    LOG_FILE,
    sep="\t",
    comment="#",
    names=columns,
    na_values=["-", "(empty)"]
)

# -----------------------------
# Numeric cleanup
# -----------------------------
numeric_cols = [
    "id.orig_p",
    "id.resp_p",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts"
]

for col in numeric_cols:
    df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

df["timestamp"] = pd.to_datetime(
    df["ts"],
    unit="s",
    utc=True,
    errors="coerce"
)

df["total_bytes"] = (
    df["orig_bytes"] + df["resp_bytes"]
)

df["total_packets"] = (
    df["orig_pkts"] + df["resp_pkts"]
)

# -----------------------------
# Recreate EXACT training features
# -----------------------------
features = pd.DataFrame()

features["duration"] = df["duration"]
features["src_port"] = df["id.orig_p"]
features["dst_port"] = df["id.resp_p"]

features["orig_bytes"] = df["orig_bytes"]
features["resp_bytes"] = df["resp_bytes"]
features["total_bytes"] = df["total_bytes"]

features["orig_pkts"] = df["orig_pkts"]
features["resp_pkts"] = df["resp_pkts"]
features["total_packets"] = df["total_packets"]

features["is_tcp"] = (df["proto"] == "tcp").astype(int)
features["is_udp"] = (df["proto"] == "udp").astype(int)
features["is_icmp"] = (df["proto"] == "icmp").astype(int)

service = df["service"].fillna("unknown").astype(str)

features["is_dns"] = service.str.contains("dns", case=False).astype(int)
features["is_ssl"] = service.str.contains("ssl", case=False).astype(int)
features["is_http"] = service.str.contains("http", case=False).astype(int)

state = df["conn_state"].fillna("UNKNOWN")

features["state_sf"] = (state == "SF").astype(int)
features["state_rej"] = (state == "REJ").astype(int)
features["state_s0"] = (state == "S0").astype(int)
features["state_rst"] = state.str.startswith("RST").astype(int)

features["bytes_per_packet"] = (
    features["total_bytes"] /
    features["total_packets"].replace(0, 1)
)

features["bytes_per_second"] = (
    features["total_bytes"] /
    features["duration"].replace(0, 0.001)
)

features["packet_rate"] = (
    features["total_packets"] /
    features["duration"].replace(0, 0.001)
)

features["byte_ratio"] = (
    (features["orig_bytes"] + 1) /
    (features["resp_bytes"] + 1)
)

dst_frequency = df["id.resp_h"].value_counts()
features["destination_frequency"] = (
    df["id.resp_h"].map(dst_frequency).fillna(0)
)

port_frequency = df["id.resp_p"].value_counts()
features["port_frequency"] = (
    df["id.resp_p"].map(port_frequency).fillna(0)
)

features = features.replace(
    [np.inf, -np.inf],
    0
).fillna(0)

# Ensure training column order
training_columns = pd.read_csv(
    "zeek_ml_features.csv",
    nrows=1
).columns.tolist()

features = features[training_columns]

# -----------------------------
# Load trained model
# -----------------------------
model = joblib.load(MODEL_FILE)
scaler = joblib.load(SCALER_FILE)

X = scaler.transform(features)

predictions = model.predict(X)
scores = -model.decision_function(X)

df["classification"] = [
    "ANOMALY" if x == -1 else "NORMAL"
    for x in predictions
]

df["network_anomaly_score"] = scores

# Normalize to 0-100 for display
minimum = scores.min()
maximum = scores.max()

if maximum == minimum:
    df["network_ml_score"] = 0
else:
    df["network_ml_score"] = (
        (scores - minimum) /
        (maximum - minimum)
    ) * 100

df["network_ml_score"] = df["network_ml_score"].round(2)

df.to_csv(OUTPUT_FILE, index=False)

anomalies = df[df["classification"] == "ANOMALY"].copy()

print("\n=== NEW ZEEK CAPTURE SCORED ===")
print("Connections:", len(df))
print("Anomalies:", len(anomalies))

print("\n=== ANOMALOUS CONNECTIONS ===")

show = [
    "timestamp",
    "id.orig_h",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "duration",
    "total_bytes",
    "classification",
    "network_ml_score"
]

print(
    anomalies.sort_values(
        "network_ml_score",
        ascending=False
    )[show].to_string(index=False)
)

print("\nSaved to:", OUTPUT_FILE)

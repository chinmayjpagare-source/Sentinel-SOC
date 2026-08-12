import pandas as pd
import numpy as np

INPUT_FILE = "zeek_connections.csv"
OUTPUT_FILE = "zeek_ml_features.csv"

df = pd.read_csv(INPUT_FILE)

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
    "resp_pkts",
    "total_bytes",
    "total_packets"
]

for col in numeric_cols:
    df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

# -----------------------------
# Basic network features
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

# -----------------------------
# Protocol features
# -----------------------------
features["is_tcp"] = (df["proto"] == "tcp").astype(int)
features["is_udp"] = (df["proto"] == "udp").astype(int)
features["is_icmp"] = (df["proto"] == "icmp").astype(int)

# -----------------------------
# Service features
# -----------------------------
service = df["service"].fillna("unknown").astype(str)

features["is_dns"] = service.str.contains(
    "dns", case=False
).astype(int)

features["is_ssl"] = service.str.contains(
    "ssl", case=False
).astype(int)

features["is_http"] = service.str.contains(
    "http", case=False
).astype(int)

# -----------------------------
# Connection-state features
# -----------------------------
state = df["conn_state"].fillna("UNKNOWN")

features["state_sf"] = (state == "SF").astype(int)
features["state_rej"] = (state == "REJ").astype(int)
features["state_s0"] = (state == "S0").astype(int)
features["state_rst"] = state.str.startswith("RST").astype(int)

# -----------------------------
# Derived behavioral features
# -----------------------------

# Prevent division by zero
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

# Outbound/inbound byte relationship
features["byte_ratio"] = (
    (features["orig_bytes"] + 1) /
    (features["resp_bytes"] + 1)
)

# Destination frequency
dst_frequency = df["id.resp_h"].value_counts()

features["destination_frequency"] = (
    df["id.resp_h"]
    .map(dst_frequency)
    .fillna(0)
)

# Destination-port frequency
port_frequency = df["id.resp_p"].value_counts()

features["port_frequency"] = (
    df["id.resp_p"]
    .map(port_frequency)
    .fillna(0)
)

# -----------------------------
# Replace invalid values
# -----------------------------
features = features.replace(
    [np.inf, -np.inf],
    0
).fillna(0)

features.to_csv(OUTPUT_FILE, index=False)

print("\n=== ZEEK FEATURE ENGINEERING COMPLETE ===")
print("Connections processed:", len(features))
print("ML features:", len(features.columns))

print("\n=== FEATURES ===")
print(features.columns.tolist())

print("\n=== SAMPLE ===")
print(features.head(10).to_string(index=False))

print("\nSaved to:", OUTPUT_FILE)

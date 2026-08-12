import pandas as pd
from pathlib import Path

LOG_FILE = Path.home() / "BlueTeam-SOC/zeek/baseline/conn.log"
OUTPUT_FILE = "zeek_connections.csv"

# Read Zeek column names from #fields
with open(LOG_FILE, "r") as f:
    for line in f:
        if line.startswith("#fields"):
            columns = line.strip().split("\t")[1:]
            break
    else:
        raise RuntimeError("Could not find #fields in conn.log")

# Read connection records
df = pd.read_csv(
    LOG_FILE,
    sep="\t",
    comment="#",
    names=columns,
    na_values=["-", "(empty)"]
)

# Convert useful fields to numbers
numeric_columns = [
    "id.orig_p",
    "id.resp_p",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
    "orig_ip_bytes",
    "resp_ip_bytes"
]

for col in numeric_columns:
    df[col] = pd.to_numeric(df[col], errors="coerce")

# Convert Unix timestamp
df["timestamp"] = pd.to_datetime(
    df["ts"],
    unit="s",
    errors="coerce"
)

# Create useful network features
df["total_bytes"] = (
    df["orig_bytes"].fillna(0)
    + df["resp_bytes"].fillna(0)
)

df["total_packets"] = (
    df["orig_pkts"].fillna(0)
    + df["resp_pkts"].fillna(0)
)

# Mark connections originating from our Mac
df["from_mac"] = (
    df["id.orig_h"] == "192.168.0.103"
).astype(int)

# Save structured dataset
df.to_csv(OUTPUT_FILE, index=False)

print("\n=== ZEEK PARSING COMPLETE ===")
print("Connections:", len(df))

print("\n=== PROTOCOLS ===")
print(df["proto"].value_counts())

print("\n=== SERVICES ===")
print(df["service"].fillna("unknown").value_counts())

print("\n=== CONNECTION STATES ===")
print(df["conn_state"].value_counts())

print("\n=== TOP 10 CONNECTIONS BY BYTES ===")

show = [
    "timestamp",
    "id.orig_h",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "duration",
    "total_bytes",
    "total_packets"
]

print(
    df.sort_values("total_bytes", ascending=False)
      [show]
      .head(10)
      .to_string(index=False)
)

print("\nSaved to:", OUTPUT_FILE)

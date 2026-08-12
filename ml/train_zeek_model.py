import pandas as pd
import joblib

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# ==========================================
# LOAD DATA
# ==========================================

features = pd.read_csv("zeek_ml_features.csv")
connections = pd.read_csv("zeek_connections.csv")

if len(features) != len(connections):
    raise ValueError(
        f"Row mismatch: {len(features)} feature rows vs "
        f"{len(connections)} connection rows"
    )

print("\n=== ZEEK NETWORK ANOMALY DETECTOR ===")
print("Connections:", len(connections))
print("Features:", len(features.columns))


# ==========================================
# SCALE FEATURES
# ==========================================

scaler = StandardScaler()

X = scaler.fit_transform(features)


# ==========================================
# TRAIN ISOLATION FOREST
# ==========================================

model = IsolationForest(
    n_estimators=200,
    contamination=0.05,
    random_state=42,
    n_jobs=-1
)

model.fit(X)


# ==========================================
# DETECT ANOMALIES
# ==========================================

predictions = model.predict(X)

# IsolationForest decision_function:
# lower values = more anomalous
#
# Negate it so our SOC convention becomes:
# higher score = more suspicious
raw_scores = -model.decision_function(X)


connections["network_anomaly"] = predictions
connections["network_anomaly_score"] = raw_scores

connections["classification"] = connections[
    "network_anomaly"
].map({
    1: "NORMAL",
    -1: "ANOMALY"
})


# ==========================================
# NORMALIZE SCORE 0-100
# ==========================================

minimum = connections["network_anomaly_score"].min()
maximum = connections["network_anomaly_score"].max()

if maximum == minimum:
    connections["network_ml_score"] = 0.0
else:
    connections["network_ml_score"] = (
        (
            connections["network_anomaly_score"] - minimum
        )
        /
        (maximum - minimum)
        * 100
    )

connections["network_ml_score"] = (
    connections["network_ml_score"].round(2)
)


# ==========================================
# SAVE MODEL + RESULTS
# ==========================================

connections.to_csv(
    "zeek_anomaly_results.csv",
    index=False
)

joblib.dump(
    model,
    "zeek_isolation_forest.pkl"
)

joblib.dump(
    scaler,
    "zeek_scaler.pkl"
)


# ==========================================
# DISPLAY RESULTS
# ==========================================

anomalies = connections[
    connections["classification"] == "ANOMALY"
].copy()

anomalies = anomalies.sort_values(
    "network_ml_score",
    ascending=False
)

print("\n=== DETECTION SUMMARY ===")

print("Total connections:", len(connections))
print("Normal:", (connections["classification"] == "NORMAL").sum())
print("Anomalies:", len(anomalies))

print(
    "Anomaly rate:",
    round(len(anomalies) / len(connections) * 100, 2),
    "%"
)


print("\n=== TOP 15 NETWORK ANOMALIES ===")

columns = [
    "timestamp",
    "id.orig_h",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "duration",
    "total_bytes",
    "total_packets",
    "conn_state",
    "network_ml_score"
]

print(
    anomalies[columns]
    .head(15)
    .to_string(index=False)
)


print("\n=== FILES SAVED ===")
print("zeek_anomaly_results.csv")
print("zeek_isolation_forest.pkl")
print("zeek_scaler.pkl")

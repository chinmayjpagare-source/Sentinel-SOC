import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

FEATURE_FILE = "wazuh_ml_features.csv"
ALERT_FILE = "wazuh_alerts.csv"

features = pd.read_csv(FEATURE_FILE)
alerts = pd.read_csv(ALERT_FILE)

# Ensure both datasets line up
if len(features) != len(alerts):
    raise ValueError("Feature and alert datasets have different lengths.")

# -----------------------------
# Scale features
# -----------------------------
scaler = StandardScaler()
X = scaler.fit_transform(features)

# -----------------------------
# Isolation Forest
# -----------------------------
model = IsolationForest(
    n_estimators=200,
    contamination=0.05,
    random_state=42
)

model.fit(X)

# Isolation Forest:
#  1 = normal/inlier
# -1 = anomaly/outlier
predictions = model.predict(X)

# Higher value = more anomalous for easier interpretation
anomaly_score = -model.decision_function(X)

alerts["anomaly"] = predictions
alerts["anomaly_score"] = anomaly_score

alerts["classification"] = alerts["anomaly"].map({
    1: "NORMAL",
    -1: "ANOMALY"
})

# -----------------------------
# Save results
# -----------------------------
alerts.to_csv("wazuh_anomaly_results.csv", index=False)

joblib.dump(model, "isolation_forest.pkl")
joblib.dump(scaler, "scaler.pkl")

# -----------------------------
# Results
# -----------------------------
print("\n=== MODEL TRAINING COMPLETE ===")

print("Total alerts:", len(alerts))
print("Normal:", (alerts["anomaly"] == 1).sum())
print("Anomalies:", (alerts["anomaly"] == -1).sum())

print("\n=== TOP 10 ANOMALOUS ALERTS ===")

columns = [
    "timestamp",
    "rule_level",
    "location",
    "description",
    "anomaly_score"
]

top = alerts.sort_values(
    "anomaly_score",
    ascending=False
).head(10)

print(top[columns].to_string(index=False))

print("\nSaved:")
print("  wazuh_anomaly_results.csv")
print("  isolation_forest.pkl")
print("  scaler.pkl")

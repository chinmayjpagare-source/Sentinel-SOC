import os
import sys
import subprocess
from datetime import datetime


STEPS = [
    ("Fetch Wazuh Alerts", "fetch_alerts.py"),
    ("Wazuh Feature Engineering", "feature_engineering.py"),
    ("Wazuh ML Anomaly Detection", "train_model.py"),
    ("SOC Risk Scoring", "risk_engine.py"),
    ("Zeek Network ML Scoring", "score_zeek_capture.py"),
    ("Wazuh + Zeek Event Correlation", "correlate_events.py"),
    ("Critical Email Alerts", "email_alerts.py"),
]


def run_step(name, script):
    print("\n" + "=" * 65)
    print(f">>> {name}")
    print("=" * 65)

    result = subprocess.run(
        [sys.executable, script],
        cwd=os.path.dirname(os.path.abspath(__file__))
    )

    if result.returncode != 0:
        print(f"\nFAILED: {name}")
        print(f"Script: {script}")
        sys.exit(result.returncode)

    print(f"\nCOMPLETE: {name}")


def main():
    print("""
=============================================================
              SENTINEL SOC - AUTOMATED PIPELINE
=============================================================
 Endpoint + Network ML | Correlation | Risk | Alerting
=============================================================
""")

    start = datetime.now()

    for name, script in STEPS:
        if not os.path.exists(script):
            print(f"Missing script: {script}")
            sys.exit(1)

        run_step(name, script)

    finish = datetime.now()
    duration = finish - start

    print("\n" + "=" * 65)
    print("SENTINEL SOC PIPELINE COMPLETE")
    print("=" * 65)

    print(f"""
Started:  {start.strftime('%Y-%m-%d %H:%M:%S')}
Finished: {finish.strftime('%Y-%m-%d %H:%M:%S')}
Duration: {duration}

Dashboard command:
streamlit run ../dashboard/app.py
""")


if __name__ == "__main__":
    main()

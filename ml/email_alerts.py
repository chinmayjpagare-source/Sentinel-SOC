import os
import smtplib
import hashlib
import pandas as pd

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


CORRELATION_FILE = "correlated_alerts.csv"
SENT_FILE = "sent_incidents.txt"

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

EMAIL_USER = os.getenv("SOC_EMAIL_USER")
EMAIL_PASSWORD = os.getenv("SOC_EMAIL_PASSWORD")
EMAIL_TO = os.getenv("SOC_EMAIL_TO")


def incident_id(row):
    """Generate a repeatable ID for an incident."""

    data = "|".join([
        str(row.get("wazuh_timestamp", "")),
        str(row.get("wazuh_description", "")),
        str(row.get("src_ip", "")),
        str(row.get("dst_ip", "")),
        str(row.get("dst_port", "")),
        str(row.get("priority", "")),
    ])

    return hashlib.sha256(data.encode()).hexdigest()


def load_sent_incidents():

    if not os.path.exists(SENT_FILE):
        return set()

    with open(SENT_FILE, "r") as f:
        return {
            line.strip()
            for line in f
            if line.strip()
        }


def mark_as_sent(alert_id):

    with open(SENT_FILE, "a") as f:
        f.write(alert_id + "\n")


def send_alert(row):

    subject = "[SENTINEL SOC] CRITICAL Security Incident"

    body = f"""
SENTINEL SOC
CRITICAL SECURITY INCIDENT
================================

Priority:
{row.get('priority', 'N/A')}

Correlation Score:
{row.get('correlation_score', 'N/A')}

Endpoint Alert:
{row.get('wazuh_description', 'N/A')}

Wazuh Risk Score:
{row.get('wazuh_risk_score', 'N/A')}

Source IP:
{row.get('src_ip', 'N/A')}

Destination IP:
{row.get('dst_ip', 'N/A')}

Destination Port:
{row.get('dst_port', 'N/A')}

Protocol:
{row.get('proto', 'N/A')}

Network ML Score:
{row.get('network_ml_score', 'N/A')}

Time Difference:
{row.get('time_difference_seconds', 'N/A')} seconds

================================

Recommended Action:

Review the correlated endpoint and network activity
in the Sentinel SOC dashboard and determine whether
incident escalation is required.
"""

    message = MIMEMultipart()

    message["From"] = EMAIL_USER
    message["To"] = EMAIL_TO
    message["Subject"] = subject

    message.attach(MIMEText(body, "plain"))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        server.send_message(message)


def main():

    print("=== SENTINEL SOC EMAIL ALERT ENGINE ===")

    if not EMAIL_USER or not EMAIL_PASSWORD or not EMAIL_TO:
        print("Email configuration missing.")
        return

    if not os.path.exists(CORRELATION_FILE):
        print(f"{CORRELATION_FILE} not found.")
        return

    df = pd.read_csv(CORRELATION_FILE)

    if "priority" not in df.columns:
        print("Priority column not found.")
        return

    critical = df[
        df["priority"]
        .astype(str)
        .str.upper()
        .eq("CRITICAL")
    ].copy()

    print("Critical incidents:", len(critical))

    if critical.empty:
        print("No CRITICAL incidents.")
        return

    sent = load_sent_incidents()

    new_incidents = []

    for _, row in critical.iterrows():

        alert_id = incident_id(row)

        if alert_id not in sent:
            new_incidents.append((alert_id, row))

    print("New critical incidents:", len(new_incidents))

    if not new_incidents:
        print("No new incidents. No email sent.")
        return

    # Highest priority incident first
    if "correlation_score" in critical.columns:
        new_incidents.sort(
            key=lambda x: float(x[1].get("correlation_score", 0)),
            reverse=True
        )

    for alert_id, incident in new_incidents:

        send_alert(incident)

        # Only mark it after email succeeds
        mark_as_sent(alert_id)

        print(
            "Email sent:",
            incident.get("wazuh_description", "Critical incident")
        )

    print("\nAlert processing complete.")


if __name__ == "__main__":
    main()

from pathlib import Path
from datetime import datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="Sentinel SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path.home() / "BlueTeam-SOC" / "ml"

WAZUH_FILE = BASE_DIR / "soc_risk_results.csv"
CORRELATED_FILE = BASE_DIR / "correlated_alerts.csv"
ZEEK_FILE = BASE_DIR / "zeek_correlation_scored.csv"


# ============================================================
# CSS
# ============================================================

st.markdown(
    """
    <style>

    /* Main app */
    .stApp {
        background:
            radial-gradient(circle at 15% 10%, rgba(24, 88, 120, 0.12), transparent 25%),
            radial-gradient(circle at 85% 20%, rgba(98, 55, 140, 0.10), transparent 25%),
            #071018;
        color: #e7edf4;
    }

    .block-container {
        padding-top: 1.4rem;
        padding-bottom: 3rem;
        max-width: 1500px;
    }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background: #09131d;
        border-right: 1px solid rgba(255,255,255,0.08);
    }

    [data-testid="stSidebar"] * {
        color: #dce6ef;
    }

    /* Hide Streamlit chrome */
    #MainMenu {
        visibility: hidden;
    }

    footer {
        visibility: hidden;
    }

    /* Header */
    .soc-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 4px 2px 18px 2px;
    }

    .soc-title {
        font-size: 31px;
        font-weight: 750;
        letter-spacing: 1px;
        margin: 0;
        color: #f3f7fb;
    }

    .soc-subtitle {
        color: #8295a7;
        font-size: 14px;
        margin-top: 3px;
    }

    .online {
        border: 1px solid rgba(74, 222, 128, 0.35);
        background: rgba(74, 222, 128, 0.08);
        padding: 7px 13px;
        border-radius: 30px;
        color: #86efac;
        font-size: 12px;
        font-weight: 700;
        letter-spacing: .5px;
    }

    /* Metric cards */
    .metric-card {
        background: rgba(13, 26, 38, 0.92);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 14px;
        padding: 19px 20px;
        min-height: 125px;
        box-shadow: 0px 8px 25px rgba(0,0,0,0.15);
    }

    .metric-label {
        color: #8194a7;
        font-size: 12px;
        font-weight: 650;
        letter-spacing: .7px;
    }

    .metric-value {
        color: #f5f8fb;
        font-size: 35px;
        font-weight: 750;
        margin-top: 8px;
        line-height: 1;
    }

    .metric-note {
        color: #64788a;
        font-size: 11px;
        margin-top: 12px;
    }

    /* Section headings */
    .section-title {
        font-size: 17px;
        font-weight: 700;
        color: #eaf0f6;
        margin-top: 10px;
        margin-bottom: 3px;
    }

    .section-subtitle {
        color: #718598;
        font-size: 12px;
        margin-bottom: 15px;
    }

    /* Incident cards */
    .incident {
        background: rgba(12, 25, 37, 0.92);
        border: 1px solid rgba(255,255,255,0.07);
        border-radius: 12px;
        padding: 15px;
        margin-bottom: 9px;
    }

    .critical {
        border-left: 4px solid #ef4444;
    }

    .high {
        border-left: 4px solid #f59e0b;
    }

    .medium {
        border-left: 4px solid #38bdf8;
    }

    .low {
        border-left: 4px solid #64748b;
    }

    .badge {
        display: inline-block;
        border-radius: 5px;
        padding: 3px 7px;
        font-size: 10px;
        font-weight: 750;
        margin-right: 8px;
    }

    .badge-critical {
        color: #fecaca;
        background: rgba(239,68,68,.16);
    }

    .badge-high {
        color: #fde68a;
        background: rgba(245,158,11,.15);
    }

    .badge-medium {
        color: #bae6fd;
        background: rgba(56,189,248,.14);
    }

    .badge-low {
        color: #cbd5e1;
        background: rgba(100,116,139,.16);
    }

    .incident-description {
        color: #d9e3ec;
        font-size: 13px;
        font-weight: 550;
    }

    .incident-meta {
        color: #718598;
        font-size: 11px;
        margin-top: 9px;
    }

    /* Dataframes */
    [data-testid="stDataFrame"] {
        border: 1px solid rgba(255,255,255,0.07);
        border-radius: 10px;
        overflow: hidden;
    }

    /* Buttons */
    .stButton > button {
        background: #102232;
        color: #dce8f2;
        border: 1px solid rgba(255,255,255,0.10);
        border-radius: 8px;
    }

    .stButton > button:hover {
        border-color: #38bdf8;
        color: #ffffff;
    }

    hr {
        border-color: rgba(255,255,255,0.07);
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# DATA
# ============================================================

@st.cache_data
def load_data():
    wazuh = pd.read_csv(WAZUH_FILE)
    correlated = pd.read_csv(CORRELATED_FILE)
    zeek = pd.read_csv(ZEEK_FILE)

    return wazuh, correlated, zeek


try:
    wazuh, correlated, zeek = load_data()
except Exception as exc:
    st.error(f"Unable to load SOC datasets: {exc}")
    st.stop()


# ============================================================
# HELPERS
# ============================================================

def metric_card(label, value, note):
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
            <div class="metric-note">{note}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def section(title, subtitle=""):
    st.markdown(
        f"""
        <div class="section-title">{title}</div>
        <div class="section-subtitle">{subtitle}</div>
        """,
        unsafe_allow_html=True,
    )


def priority_badge(priority):
    priority = str(priority).upper()

    mapping = {
        "CRITICAL": "badge-critical",
        "HIGH": "badge-high",
        "MEDIUM": "badge-medium",
        "LOW": "badge-low",
    }

    css = mapping.get(priority, "badge-low")

    return f'<span class="badge {css}">{priority}</span>'


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown("## 🛡️ SENTINEL")
    st.caption("AI-Assisted Blue Team SOC")

    st.divider()

    page = st.radio(
        "Navigation",
        [
            "Overview",
            "Incidents",
            "Endpoint",
            "Network",
            "ML Analytics",
        ],
        label_visibility="collapsed",
    )

    st.divider()

    st.caption("DETECTION STACK")
    st.markdown("**Wazuh** · Endpoint")
    st.markdown("**Zeek** · Network")
    st.markdown("**Isolation Forest** · ML")
    st.markdown("**Python** · Correlation")

    st.divider()

    if st.button("↻ Refresh SOC Data", use_container_width=True):
        st.cache_data.clear()
        st.rerun()


# ============================================================
# HEADER
# ============================================================

st.markdown(
    """
    <div class="soc-header">
        <div>
            <div class="soc-title">SENTINEL SOC</div>
            <div class="soc-subtitle">
                AI-Assisted Security Operations & Threat Correlation Platform
            </div>
        </div>
        <div class="online">● DATA LOADED</div>
    </div>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# COMMON VALUES
# ============================================================

total_alerts = len(wazuh)

if "classification" in wazuh.columns:
    ml_anomalies = int(
        wazuh["classification"]
        .astype(str)
        .str.upper()
        .eq("ANOMALY")
        .sum()
    )
else:
    ml_anomalies = 0

critical_count = (
    int(correlated["priority"].astype(str).str.upper().eq("CRITICAL").sum())
    if "priority" in correlated.columns
    else 0
)

high_count = (
    int(correlated["priority"].astype(str).str.upper().eq("HIGH").sum())
    if "priority" in correlated.columns
    else 0
)


# ============================================================
# OVERVIEW
# ============================================================

if page == "Overview":

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        metric_card(
            "TOTAL WAZUH ALERTS",
            f"{total_alerts:,}",
            "Endpoint security events collected",
        )

    with c2:
        metric_card(
            "ML ANOMALIES",
            f"{ml_anomalies:,}",
            "Events flagged by anomaly detection",
        )

    with c3:
        metric_card(
            "CRITICAL",
            critical_count,
            "Immediate investigation recommended",
        )

    with c4:
        metric_card(
            "HIGH PRIORITY",
            high_count,
            "Correlated events requiring review",
        )

    st.write("")

    left, right = st.columns([1.15, 1])

    with left:

        section(
            "Threat Risk Overview",
            "Risk classification across Wazuh endpoint events",
        )

        if "risk" in wazuh.columns:

            risk_counts = (
                wazuh["risk"]
                .astype(str)
                .str.upper()
                .value_counts()
                .reset_index()
            )

            risk_counts.columns = ["Risk", "Events"]

            fig = px.bar(
                risk_counts,
                x="Risk",
                y="Events",
                text="Events",
            )

            fig.update_layout(
                height=350,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#9fb0bf",
                showlegend=False,
                margin=dict(l=10, r=10, t=15, b=10),
                xaxis_title=None,
                yaxis_title=None,
            )

            fig.update_traces(
                marker_color="#38bdf8",
                marker_line_width=0,
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
                config={"displayModeBar": False},
            )

    with right:

        section(
            "Correlation Priority",
            "Combined Wazuh and Zeek incident prioritization",
        )

        if "priority" in correlated.columns:

            priority_counts = (
                correlated["priority"]
                .astype(str)
                .str.upper()
                .value_counts()
                .reset_index()
            )

            priority_counts.columns = ["Priority", "Events"]

            fig = go.Figure(
                data=[
                    go.Pie(
                        labels=priority_counts["Priority"],
                        values=priority_counts["Events"],
                        hole=0.67,
                        textinfo="label+value",
                    )
                ]
            )

            fig.update_layout(
                height=350,
                paper_bgcolor="rgba(0,0,0,0)",
                font_color="#9fb0bf",
                margin=dict(l=10, r=10, t=15, b=10),
                showlegend=False,
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
                config={"displayModeBar": False},
            )

    st.divider()

    section(
        "🚨 Security Incident Queue",
        "Highest-priority host and network correlations",
    )

    if "correlation_score" in correlated.columns:

        top_incidents = (
            correlated
            .sort_values("correlation_score", ascending=False)
            .head(8)
        )

        for _, row in top_incidents.iterrows():

            priority = str(row.get("priority", "UNKNOWN")).upper()

            css_class = (
                priority.lower()
                if priority in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
                else "low"
            )

            description = row.get(
                "wazuh_description",
                "Security event",
            )

            score = row.get(
                "correlation_score",
                "N/A",
            )

            destination = row.get(
                "dst_ip",
                "N/A",
            )

            port = row.get(
                "dst_port",
                "N/A",
            )

            delta = row.get(
                "time_difference_seconds",
                "N/A",
            )

            st.markdown(
                f"""
                <div class="incident {css_class}">
                    {priority_badge(priority)}
                    <span class="incident-description">
                        {description}
                    </span>
                    <div class="incident-meta">
                        Correlation score: {score}
                        &nbsp; • &nbsp;
                        Destination: {destination}:{port}
                        &nbsp; • &nbsp;
                        Δt: {delta}s
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )


# ============================================================
# INCIDENTS
# ============================================================

elif page == "Incidents":

    section(
        "🚨 Incident Investigation",
        "Investigate correlated endpoint and network detections",
    )

    if correlated.empty:
        st.info("No correlated incidents available.")

    else:

        priorities = (
            sorted(correlated["priority"].dropna().astype(str).unique())
            if "priority" in correlated.columns
            else []
        )

        selected_priorities = st.multiselect(
            "Priority",
            priorities,
            default=priorities,
        )

        incidents = correlated.copy()

        if selected_priorities:
            incidents = incidents[
                incidents["priority"].isin(selected_priorities)
            ]

        if "correlation_score" in incidents.columns:
            incidents = incidents.sort_values(
                "correlation_score",
                ascending=False,
            )

        display_columns = [
            "wazuh_timestamp",
            "wazuh_description",
            "wazuh_risk_score",
            "src_ip",
            "dst_ip",
            "dst_port",
            "network_ml_score",
            "time_difference_seconds",
            "correlation_score",
            "priority",
        ]

        display_columns = [
            col for col in display_columns
            if col in incidents.columns
        ]

        st.dataframe(
            incidents[display_columns],
            use_container_width=True,
            hide_index=True,
        )

        st.divider()

        section(
            "Analyst Investigation",
            "Select an incident to inspect the underlying correlation",
        )

        if len(incidents) > 0:

            options = list(incidents.index)

            selected_index = st.selectbox(
                "Incident",
                options,
                format_func=lambda i: (
                    f"{incidents.loc[i].get('priority', 'N/A')} | "
                    f"{incidents.loc[i].get('wazuh_description', 'Security event')} | "
                    f"Score {incidents.loc[i].get('correlation_score', 'N/A')}"
                ),
            )

            incident = incidents.loc[selected_index]

            a, b, c = st.columns(3)

            a.metric(
                "Correlation Score",
                incident.get("correlation_score", "N/A"),
            )

            b.metric(
                "Wazuh Risk",
                incident.get("wazuh_risk_score", "N/A"),
            )

            c.metric(
                "Network ML",
                incident.get("network_ml_score", "N/A"),
            )

            st.markdown("#### Endpoint Detection")
            st.write(
                incident.get(
                    "wazuh_description",
                    "No endpoint description available.",
                )
            )

            st.markdown("#### Network Context")

            st.code(
                f"""Source:      {incident.get("src_ip", "N/A")}
Destination: {incident.get("dst_ip", "N/A")}
Port:        {incident.get("dst_port", "N/A")}
Protocol:    {incident.get("proto", "N/A")}
Time delta:  {incident.get("time_difference_seconds", "N/A")} seconds"""
            )

            st.markdown("#### Analyst Assessment")

            st.info(
                "Endpoint security activity occurred close in time to "
                "network behavior identified as anomalous by the ML model. "
                "Review the endpoint event, initiating process, destination "
                "IP, and surrounding network activity before escalation."
            )


# ============================================================
# ENDPOINT
# ============================================================

elif page == "Endpoint":

    section(
        "🖥 Endpoint Detection",
        "Wazuh alerts, FIM activity and host risk scoring",
    )

    if "risk" in wazuh.columns:

        risks = sorted(
            wazuh["risk"]
            .dropna()
            .astype(str)
            .unique()
        )

        selected = st.multiselect(
            "Risk Level",
            risks,
            default=risks,
        )

        endpoint = wazuh[
            wazuh["risk"].isin(selected)
        ].copy()

    else:
        endpoint = wazuh.copy()

    endpoint_columns = [
        "timestamp",
        "rule_level",
        "location",
        "description",
        "fim_event",
        "fim_path",
        "ml_score",
        "risk_score",
        "risk",
    ]

    endpoint_columns = [
        c for c in endpoint_columns
        if c in endpoint.columns
    ]

    if "risk_score" in endpoint.columns:
        endpoint = endpoint.sort_values(
            "risk_score",
            ascending=False,
        )

    st.dataframe(
        endpoint[endpoint_columns],
        use_container_width=True,
        hide_index=True,
    )

    st.divider()

    section(
        "File Integrity Monitoring",
        "Host file changes observed by Wazuh Syscheck",
    )

    if "location" in wazuh.columns:

        fim = wazuh[
            wazuh["location"]
            .astype(str)
            .str.lower()
            .eq("syscheck")
        ]

        fim_columns = [
            "timestamp",
            "description",
            "fim_event",
            "fim_path",
            "risk_score",
            "risk",
        ]

        fim_columns = [
            c for c in fim_columns
            if c in fim.columns
        ]

        st.dataframe(
            fim[fim_columns],
            use_container_width=True,
            hide_index=True,
        )


# ============================================================
# NETWORK
# ============================================================

elif page == "Network":

    section(
        "🌐 Network Detection",
        "Zeek telemetry and machine-learning anomaly detection",
    )

    network = zeek.copy()

    if "network_ml_score" in network.columns:
        network = network.sort_values(
            "network_ml_score",
            ascending=False,
        )

    network_columns = [
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
        "classification",
        "network_ml_score",
    ]

    network_columns = [
        c for c in network_columns
        if c in network.columns
    ]

    st.dataframe(
        network[network_columns],
        use_container_width=True,
        hide_index=True,
    )

    st.divider()

    left, right = st.columns(2)

    with left:

        section(
            "Top Destinations",
            "Most frequently observed destination addresses",
        )

        if "id.resp_h" in zeek.columns:

            destinations = (
                zeek["id.resp_h"]
                .value_counts()
                .head(10)
                .reset_index()
            )

            destinations.columns = [
                "Destination",
                "Connections",
            ]

            fig = px.bar(
                destinations,
                x="Connections",
                y="Destination",
                orientation="h",
            )

            fig.update_layout(
                height=380,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#9fb0bf",
                showlegend=False,
                margin=dict(l=5, r=5, t=10, b=5),
            )

            fig.update_traces(
                marker_color="#38bdf8",
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
                config={"displayModeBar": False},
            )

    with right:

        section(
            "Protocol Activity",
            "Observed network protocol distribution",
        )

        if "proto" in zeek.columns:

            protocols = (
                zeek["proto"]
                .fillna("unknown")
                .value_counts()
                .reset_index()
            )

            protocols.columns = [
                "Protocol",
                "Connections",
            ]

            fig = go.Figure(
                go.Pie(
                    labels=protocols["Protocol"],
                    values=protocols["Connections"],
                    hole=0.65,
                )
            )

            fig.update_layout(
                height=380,
                paper_bgcolor="rgba(0,0,0,0)",
                font_color="#9fb0bf",
                showlegend=True,
                margin=dict(l=5, r=5, t=10, b=5),
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
                config={"displayModeBar": False},
            )


# ============================================================
# ML ANALYTICS
# ============================================================

elif page == "ML Analytics":

    section(
        "🤖 Machine Learning Analytics",
        "Isolation Forest anomaly scoring across endpoint and network telemetry",
    )

    c1, c2 = st.columns(2)

    with c1:

        st.markdown("#### Endpoint ML Scores")

        if "ml_score" in wazuh.columns:

            fig = px.histogram(
                wazuh,
                x="ml_score",
                nbins=25,
            )

            fig.update_layout(
                height=350,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#9fb0bf",
                xaxis_title="ML Score",
                yaxis_title="Events",
                margin=dict(l=5, r=5, t=10, b=5),
            )

            fig.update_traces(
                marker_color="#38bdf8",
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
                config={"displayModeBar": False},
            )

    with c2:

        st.markdown("#### Network ML Scores")

        if "network_ml_score" in zeek.columns:

            fig = px.histogram(
                zeek,
                x="network_ml_score",
                nbins=25,
            )

            fig.update_layout(
                height=350,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#9fb0bf",
                xaxis_title="Network ML Score",
                yaxis_title="Connections",
                margin=dict(l=5, r=5, t=10, b=5),
            )

            fig.update_traces(
                marker_color="#a78bfa",
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
                config={"displayModeBar": False},
            )

    st.divider()

    section(
        "Detection Architecture",
        "How Sentinel combines host and network telemetry",
    )

    st.code(
        """
macOS Endpoint
      │
      ├──────────── Wazuh ────────────┐
      │                               │
      │     FIM / SCA / CVE / Logs    │
      │               ↓               │
      │       Feature Engineering     │
      │               ↓               │
      │        Isolation Forest       │
      │               ↓               │
      │          Risk Engine          │
      │                               │
      └──────────── Zeek ─────────────┤
                      │               │
                Network Traffic       │
                      ↓               │
              Feature Engineering     │
                      ↓               │
               Isolation Forest       │
                      ↓               │
              Network ML Score        │
                                      ↓
                              Event Correlation
                                      ↓
                         MEDIUM / HIGH / CRITICAL
        """
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    f"Sentinel SOC • Wazuh + Zeek + Isolation Forest • "
    f"Dashboard loaded {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
)

import pandas as pd
import streamlit as st
import plotly.express as px


# ============================================================
# CONFIG
# ============================================================
st.set_page_config(
    page_title="AI-Assisted Blue Team SOC",
    page_icon="🛡️",
    layout="wide"
)

BASE_DIR = Path.home() / "BlueTeam-SOC" / "ml"

WAZUH_RISK_FILE = BASE_DIR / "soc_risk_results.csv"
CORRELATED_FILE = BASE_DIR / "correlated_alerts.csv"
ZEEK_FILE = BASE_DIR / "zeek_correlation_scored.csv"


# ============================================================
# DATA LOADING
# ============================================================

@st.cache_data
def load_data():
    wazuh = pd.read_csv(WAZUH_RISK_FILE)
    correlated = pd.read_csv(CORRELATED_FILE)
    zeek = pd.read_csv(ZEEK_FILE)

    return wazuh, correlated, zeek


try:
    wazuh, correlated, zeek = load_data()
except Exception as e:
    st.error(f"Unable to load SOC data: {e}")
    st.stop()


# ============================================================
# TITLE
# ============================================================

st.title("🛡️ AI-Assisted Blue Team SOC")

st.caption(
    "Endpoint monitoring + network anomaly detection + "
    "risk scoring + Wazuh/Zeek event correlation"
)


# ============================================================
# SUMMARY METRICS
# ============================================================

total_wazuh = len(wazuh)

wazuh_anomalies = (
    wazuh["classification"].eq("ANOMALY").sum()
    if "classification" in wazuh.columns
    else 0
)

critical = (
    correlated["priority"].eq("CRITICAL").sum()
    if "priority" in correlated.columns
    else 0
)

high = (
    correlated["priority"].eq("HIGH").sum()
    if "priority" in correlated.columns
    else 0
)

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Wazuh Alerts",
    total_wazuh
)

col2.metric(
    "ML Anomalies",
    wazuh_anomalies
)

col3.metric(
    "Critical Correlations",
    critical
)

col4.metric(
    "High Correlations",
    high
)


st.divider()


# ============================================================
# RISK DISTRIBUTION
# ============================================================

left, right = st.columns(2)

with left:
    st.subheader("Wazuh Risk Distribution")

    risk_counts = (
        wazuh["risk"]
        .value_counts()
        .reset_index()
    )

    risk_counts.columns = [
        "Risk",
        "Count"
    ]

    fig = px.bar(
        risk_counts,
        x="Risk",
        y="Count",
        title="Endpoint Alert Risk Levels"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )


with right:
    st.subheader("Correlation Priority Distribution")

    correlation_counts = (
        correlated["priority"]
        .value_counts()
        .reset_index()
    )

    correlation_counts.columns = [
        "Priority",
        "Count"
    ]

    fig2 = px.pie(
        correlation_counts,
        names="Priority",
        values="Count",
        title="Wazuh + Zeek Correlation Priority"
    )

    st.plotly_chart(
        fig2,
        use_container_width=True
    )


st.divider()


# ============================================================
# TOP CORRELATED EVENTS
# ============================================================

st.subheader("🚨 Top Correlated Security Events")

correlation_columns = [
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

available_columns = [
    col for col in correlation_columns
    if col in correlated.columns
]

top_correlated = (
    correlated
    .sort_values(
        "correlation_score",
        ascending=False
    )
    .head(20)
)

st.dataframe(
    top_correlated[available_columns],
    use_container_width=True,
    hide_index=True
)


st.divider()


# ============================================================
# ENDPOINT ALERTS
# ============================================================

st.subheader("🖥️ Endpoint Security Alerts")

severity_filter = st.multiselect(
    "Filter by risk",
    options=sorted(
        wazuh["risk"].dropna().unique()
    ),
    default=sorted(
        wazuh["risk"].dropna().unique()
    )
)

filtered_wazuh = wazuh[
    wazuh["risk"].isin(
        severity_filter
    )
]

endpoint_columns = [
    "timestamp",
    "rule_level",
    "location",
    "description",
    "ml_score",
    "risk_score",
    "risk"
]

endpoint_columns = [
    col for col in endpoint_columns
    if col in filtered_wazuh.columns
]

st.dataframe(
    filtered_wazuh[
        endpoint_columns
    ].sort_values(
        "risk_score",
        ascending=False
    ),
    use_container_width=True,
    hide_index=True
)


st.divider()


# ============================================================
# NETWORK ANOMALIES
# ============================================================

st.subheader("🌐 Zeek Network Anomalies")

if "classification" in zeek.columns:
    network_anomalies = zeek[
        zeek["classification"] == "ANOMALY"
    ].copy()
else:
    network_anomalies = zeek.copy()

network_columns = [
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

network_columns = [
    col for col in network_columns
    if col in network_anomalies.columns
]

if "network_ml_score" in network_anomalies.columns:
    network_anomalies = (
        network_anomalies
        .sort_values(
            "network_ml_score",
            ascending=False
        )
    )

st.dataframe(
    network_anomalies[
        network_columns
    ],
    use_container_width=True,
    hide_index=True
)


st.divider()


# ============================================================
# TOP NETWORK DESTINATIONS
# ============================================================

st.subheader("📡 Top Destination IPs")

if "id.resp_h" in zeek.columns:

    destinations = (
        zeek["id.resp_h"]
        .value_counts()
        .head(10)
        .reset_index()
    )

    destinations.columns = [
        "Destination IP",
        "Connections"
    ]

    fig3 = px.bar(
        destinations,
        x="Destination IP",
        y="Connections",
        title="Most Frequent Network Destinations"
    )

    st.plotly_chart(
        fig3,
        use_container_width=True
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "Prototype SOC lab built with Wazuh, Zeek, Python, "
    "Scikit-learn Isolation Forest and Streamlit."
)

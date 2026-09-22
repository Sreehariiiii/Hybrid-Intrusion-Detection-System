"""
Streamlit UI Dashboard for Signature-Based Intrusion Detection System
Features Password Authentication, Offline PCAP Replay, Replay Injection Simulator,
Confusion Matrix Heatmap, Per-Category Attribution, and Rule Hot-Reloading.
"""

import os
import sys
import time
import json
import sqlite3
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Ensure root directory is in python path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from src.benchmark import run_benchmark_pipeline
from src.evaluator import evaluate_detection_performance
from src.attack_injector import inject_attack_into_pcap_queue
from src.alert_notifier import load_rules_from_file
import src.eve_ingestor as eve_ingestor
from src.eve_ingestor import (
    count_pcap_packets, start_suricata_subprocess, ingest_eve_to_sqlite, run_pipeline_ingestion
)

st.set_page_config(
    page_title="Signature IDS Engine | Suricata + SQLite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -------------------------------------------------------------
# STEP 5: SESSION-PASSWORD AUTHENTICATION GATE
# -------------------------------------------------------------
DASHBOARD_PASSWORD = os.environ.get("IDS_DASHBOARD_PASS", "admin")

if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

if not st.session_state["authenticated"]:
    st.markdown("## 🔒 Signature-Based IDS Dashboard Login")
    st.markdown("Please enter the administrator session password to access telemetry.")
    pwd_input = st.text_input("Enter Password", type="password")
    if st.button("Unlock Dashboard", type="primary"):
        if pwd_input == DASHBOARD_PASSWORD:
            st.session_state["authenticated"] = True
            st.success("Authentication successful!")
            st.rerun()
        else:
            st.error("Invalid password. (Default is 'admin' or set IDS_DASHBOARD_PASS)")
    st.stop()


# Custom Styling
st.markdown("""
<style>
    .metric-card {
        background-color: #0e1117;
        border: 1px solid #262730;
        border-radius: 8px;
        padding: 16px;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)


# Target Dataset & Engine Configuration
REAL_PCAP_PATH = r"C:\Users\venug\Downloads\Thursday-WorkingHours.pcap"
PCAP_PATH = REAL_PCAP_PATH if os.path.exists(REAL_PCAP_PATH) else os.path.join(ROOT_DIR, "data", "slice_test", "thursday_sample_500k.pcap")
DB_PATH = os.path.join(ROOT_DIR, "database", "alerts.db")
GT_CSV_PATH = os.path.join(ROOT_DIR, "data", "ground_truth.csv")
RULE_PATH = os.path.join(ROOT_DIR, "config", "custom_rules.rules")


def load_db_data():
    if not os.path.exists(DB_PATH):
        return pd.DataFrame(), pd.DataFrame(), pd.DataFrame()
    conn = sqlite3.connect(DB_PATH)
    try:
        alerts_df = pd.read_sql_query("SELECT * FROM alerts ORDER BY id DESC", conn)
    except Exception:
        alerts_df = pd.DataFrame()
    try:
        flows_df = pd.read_sql_query("SELECT * FROM evaluation_flows", conn)
    except Exception:
        flows_df = pd.DataFrame()
    try:
        bench_df = pd.read_sql_query("SELECT * FROM benchmark_metrics ORDER BY created_at DESC LIMIT 1", conn)
    except Exception:
        bench_df = pd.DataFrame()
    conn.close()
    return alerts_df, flows_df, bench_df


# Sidebar Controls
st.sidebar.title("🛡️ IDS Operations")
pcap_size_gb = os.path.getsize(PCAP_PATH) / (1024**3) if os.path.exists(PCAP_PATH) else 0.0
st.sidebar.markdown(f"**Target Dataset:** `{os.path.basename(PCAP_PATH)}` ({pcap_size_gb:.2f} GB)")
st.sidebar.markdown("**Engine:** Genuine Suricata 8.0.7 Multi-Condition Rules")
st.sidebar.markdown("**Evaluation Mode:** Real PCAP Replay & EVE Telemetry")

# Live Alerts Toast Toggle & Fixed 3-Second Auto-Refresh
show_toast_popups = st.sidebar.checkbox("🔔 Show live alert popups", value=True)
auto_refresh = st.sidebar.checkbox("🔄 Live Real-Time Auto-Refresh", value=True)
refresh_interval = 3 if auto_refresh else 0

# Replay State Management
if "replay_running" not in st.session_state:
    st.session_state["replay_running"] = False
if "last_replay_status" not in st.session_state:
    st.session_state["last_replay_status"] = None

def run_pipeline_with_progress(pcap_path, gt_csv, db_path, task_label="Replay Processing", status_container=None):
    """Runs Suricata with a dynamic packet progress bar and heartbeat monitoring."""
    if status_container is None:
        status_container = st.container()

    with status_container:
        progress_placeholder = st.empty()
        status_placeholder = st.empty()

        with status_placeholder.container():
            st.info(f"⏳ Pre-calculating total packets for {os.path.basename(pcap_path)}...")
        
        total_pkts = count_pcap_packets(pcap_path)
        total_pkts = max(1, total_pkts)

        with status_placeholder.container():
            st.info(f"🚀 Launching Suricata engine ({total_pkts:,} packets to process)...")

        proc = start_suricata_subprocess(pcap_path=pcap_path)
        eve_path = "logs/eve.json"
        start_time = time.time()
        last_update_time = time.time()
        current_pkts = 0

        prog_bar = progress_placeholder.progress(0.0)

        from src.eve_ingestor import LiveEveTailer
        tailer = LiveEveTailer(eve_path=eve_path, db_path=db_path)
        tailer.start_tailing()

        shown_toasts = 0

        while proc.poll() is None:
            time.sleep(1.0)
            now_t = time.time()
            elapsed = now_t - start_time

            # Parse latest stats from eve.json
            if os.path.exists(eve_path):
                try:
                    with open(eve_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            if '"event_type":"stats"' in line:
                                st_evt = json.loads(line.strip())
                                dec = st_evt.get("stats", {}).get("decoder", {}).get("pkts", 0)
                                if dec > current_pkts:
                                    current_pkts = dec
                                    last_update_time = now_t
                except Exception:
                    pass

            # Live toast popups while dataset is running
            if show_toast_popups and tailer.new_alerts_buffer:
                while tailer.new_alerts_buffer and shown_toasts < 30:
                    na = tailer.new_alerts_buffer.pop(0)
                    sev_icon = "🚨" if na["severity"] == 1 else "⚠️"
                    st.toast(f"{sev_icon} **{na['signature']}** detected from `{na['src_ip']}` -> `{na['dest_ip']}:{na['dest_port']}`", icon="🔥")
                    shown_toasts += 1

            fraction = min(0.99, current_pkts / total_pkts) if total_pkts > 0 else 0.0
            prog_bar.progress(fraction)

            # ETA and Rate
            pkt_rate = current_pkts / elapsed if elapsed > 0 else 0
            rem_pkts = max(0, total_pkts - current_pkts)
            eta_sec = rem_pkts / pkt_rate if pkt_rate > 0 else 0
            idle_sec = int(now_t - last_update_time)

            heartbeat_msg = f"Last updated: {idle_sec}s ago"
            if idle_sec >= 15:
                heartbeat_msg += " ⚠️ (possibly waiting on I/O burst)"

            with status_placeholder.container():
                st.markdown(
                    f"**{task_label}**: `{current_pkts:,} / {total_pkts:,} pkts` ({fraction*100:.1f}%) | "
                    f"**Live Alerts Ingested:** `{tailer.total_streamed:,}` | "
                    f"**Elapsed:** `{elapsed:.1f}s` | **ETA:** `{eta_sec:.1f}s` | *{heartbeat_msg}*"
                )

        tailer.stop()
        stdout, stderr = proc.communicate()
        if proc.returncode != 0:
            prog_bar.progress(0.0)
            status_placeholder.error(f"❌ Suricata process failed (exit code {proc.returncode}): {stderr}")
            return False

        prog_bar.progress(1.0)
        status_placeholder.success(f"✅ Suricata processing complete in {time.time()-start_time:.1f}s! Ingested {tailer.total_streamed:,} alerts. Computing performance metrics...")
        time.sleep(0.5)

        evaluate_detection_performance(gt_csv, db_path)
        return True


if st.sidebar.button("⚡ Run Full Dataset Replay & Evaluation", type="primary", use_container_width=True):
    st.session_state["replay_running"] = True
    st.session_state["last_replay_status"] = None
    st.rerun()

st.sidebar.divider()
st.sidebar.markdown("### 🔍 Alert Filters")
sev_filter = st.sidebar.multiselect("Filter Severity", [1, 2, 3], default=[1, 2, 3])
proto_filter = st.sidebar.multiselect("Filter Protocol", ["TCP", "UDP"], default=["TCP", "UDP"])

if st.sidebar.button("🚪 Logout", use_container_width=True):
    st.session_state["authenticated"] = False
    st.rerun()

# Main Header
st.title("🛡️ Signature-Based Intrusion Detection System")
st.markdown("##### Offline Dataset Replay, Suricata EVE Telemetry & Deterministic Attribution")

# Persistent Progress & Status Container across tabs
progress_container = st.container()

if st.session_state.get("replay_running", False):
    with progress_container:
        st.markdown("#### ⚡ Full Dataset Replay & Evaluation In Progress")
        success = run_pipeline_with_progress(PCAP_PATH, GT_CSV_PATH, DB_PATH, task_label=f"Replaying {os.path.basename(PCAP_PATH)}", status_container=progress_container)
        st.session_state["replay_running"] = False
        if success:
            st.session_state["last_replay_status"] = f"✅ Full Dataset Replay & Evaluation completed successfully ({time.strftime('%H:%M:%S')})!"
        else:
            st.session_state["last_replay_status"] = "❌ Replay run encountered an error."
        st.rerun()
elif st.session_state.get("last_replay_status"):
    with progress_container:
        st.success(st.session_state["last_replay_status"])

alerts_df, flows_df, bench_df = load_db_data()

# Track new incoming alerts in session state and trigger browser notifications/toasts if enabled
if "last_seen_alert_id" not in st.session_state:
    st.session_state["last_seen_alert_id"] = int(alerts_df["id"].max()) if not alerts_df.empty else 0

current_max_id = int(alerts_df["id"].max()) if not alerts_df.empty else 0
if current_max_id > st.session_state["last_seen_alert_id"]:
    new_alerts = alerts_df[alerts_df["id"] > st.session_state["last_seen_alert_id"]]
    if show_toast_popups:
        for _, na in new_alerts.head(3).iterrows():
            sev_icon = "🚨" if na["severity"] == 1 else ("⚠️" if na["severity"] == 2 else "ℹ️")
            st.toast(f"{sev_icon} **{na['signature']}** detected from `{na['src_ip']}` -> `{na['dest_ip']}:{na['dest_port']}`", icon="🔥")
    st.session_state["last_seen_alert_id"] = current_max_id

# Auto-initialize dataset if empty
if alerts_df.empty or flows_df.empty:
    with st.spinner("Initializing dataset and running first benchmark pass..."):
        run_benchmark_pipeline(PCAP_PATH, GT_CSV_PATH, DB_PATH)
        alerts_df, flows_df, bench_df = load_db_data()

# Evaluate Metrics on Test Set
eval_res = evaluate_detection_performance(GT_CSV_PATH, DB_PATH)
cat_metrics_df = eval_res["category_metrics"]
attribution_df = eval_res["attribution_metrics"]
cm_df = eval_res["confusion_matrix"]

# 1. System Benchmark KPI Cards
st.subheader("📊 System Benchmark & Performance KPIs")
col1, col2, col3, col4, col5, col6 = st.columns(6)

if not bench_df.empty:
    b = bench_df.iloc[0]
    col1.metric("⚡ Replay Speed", f"{b['throughput_mb_s']} MB/s")
    col2.metric("🔄 Flow Rate", f"{b['throughput_flows_s']} flows/s")
    col3.metric("🧠 Peak RSS RAM", f"{b['peak_memory_rss_mb']} MB")
    col4.metric("📦 Total Alerts", f"{len(alerts_df)}")
else:
    col1.metric("⚡ Replay Speed", "N/A")
    col2.metric("🔄 Flow Rate", "N/A")
    col3.metric("🧠 Peak RSS RAM", "N/A")
    col4.metric("📦 Total Alerts", f"{len(alerts_df)}")

# Calculate Global F1 and Global FPR
if not cat_metrics_df.empty:
    non_benign = cat_metrics_df[cat_metrics_df["Category"] != "Benign"]
    global_tp = non_benign["TP"].sum()
    global_fp = non_benign["FP"].sum()
    global_fn = non_benign["FN"].sum()
    global_tn = cat_metrics_df[cat_metrics_df["Category"] == "Benign"]["TN"].sum()
    
    prec = global_tp / (global_tp + global_fp) if (global_tp + global_fp) > 0 else 0
    rec = global_tp / (global_tp + global_fn) if (global_tp + global_fn) > 0 else 0
    f1 = 2 * (prec * rec) / (prec + rec) if (prec + rec) > 0 else 0
    fpr = global_fp / (global_fp + global_tn) if (global_fp + global_tn) > 0 else 0

    col5.metric("🎯 Detection F1", f"{f1*100:.1f}%")
    col6.metric("⚠️ False Positive Rate", f"{fpr*100:.2f}%")
else:
    col5.metric("🎯 Detection F1", "N/A")
    col6.metric("⚠️ False Positive Rate", "N/A")

st.divider()

# -------------------------------------------------------------
# PART 1: 4-TAB SIMPLIFIED LAYOUT
# -------------------------------------------------------------
tab_live, tab_metrics, tab_cm, tab_coverage = st.tabs([
    "🚨 Live Alerts",
    "📈 Metrics",
    "🔲 Confusion Matrix",
    "🎯 Rule Coverage"
])

# -------------------------------------------------------------
# TAB 1: LIVE ALERTS (Merged Injection Simulator + Alert Feed)
# -------------------------------------------------------------
with tab_live:
    # 1. Replay Attack Injection Simulator Controls (Top)
    st.markdown("##### 💉 Replay Attack Injection Simulator")
    st.caption("Constructs real Scapy network packets, appends them to the PCAP replay queue, and triggers the detection engine (simulated via PCAP injection).")

    col_s1, col_s2, col_s3 = st.columns([2, 2, 1])
    sim_choices = [
        "WebAttack-SQLi",
        "WebAttack-XSS",
        "DoS-LOIC-UDP",
        "PortScan-TCP-SYN",
        "BruteForce-SSH",
        "Botnet-C2-Beacon",
        "Infiltration-SMB"
    ]
    chosen_attack = col_s1.selectbox("Select Attack Pattern", sim_choices)
    target_host = col_s2.text_input("Target Host IP", value="192.168.1.10")

    if col_s3.button("🚀 Inject & Replay", type="primary", use_container_width=True):
        # Progress handled inside injection pipeline
        with st.spinner(f"Constructing packets for {chosen_attack} and executing replay..."):
            res = inject_attack_into_pcap_queue(chosen_attack, target_host, PCAP_PATH, GT_CSV_PATH)
            time.sleep(0.5)
        st.success(f"Injected {res['packets_injected']} packets for {chosen_attack}! Evaluated {res['total_alerts']} alerts.")
        st.rerun()

    st.divider()

    # 2. Live Alert Feed (Below Injection Controls)
    st.markdown("##### 🚨 Live Alert Telemetry & Dynamic Explainability")
    
    # Low-profile search bar at the top of the feed
    search_query = st.text_input("🔎 Search alert payload, reason, IP, or signature...", "", label_visibility="collapsed")

    if not alerts_df.empty:
        filtered_alerts = alerts_df[
            (alerts_df["severity"].isin(sev_filter)) &
            (alerts_df["proto"].isin(proto_filter))
        ]

        if search_query:
            filtered_alerts = filtered_alerts[
                filtered_alerts.apply(lambda r: search_query.lower() in str(r.values).lower(), axis=1)
            ]

        st.caption(f"Displaying {len(filtered_alerts)} of {len(alerts_df)} recorded alerts")

        for _, alert in filtered_alerts.iterrows():
            sev = int(alert["severity"])
            sev_badge = "🔴 HIGH (Sev 1)" if sev == 1 else ("🟠 MEDIUM (Sev 2)" if sev == 2 else "🔵 LOW (Sev 3)")
            
            with st.expander(f"**[{sev_badge}]** {alert['signature']} (SID: {alert['signature_id']}) — `{alert['src_ip']}:{alert['src_port']} ➔ {alert['dest_ip']}:{alert['dest_port']}` [{alert['timestamp']}]"):
                st.markdown(f"**Protocol:** `{alert['proto']}` | **Category:** `{alert['category']}`")
                st.info(f"**Deterministic Explainability Proof:**\n\n{alert['reason']}")
                st.markdown(
                    f"- **Flow Telemetry:** Packets: `{alert['pkts_toserver']}` | Bytes: `{alert['bytes_toserver']}` bytes"
                )

        with st.expander("📄 Raw SQLite Table View"):
            st.dataframe(
                filtered_alerts[["id", "timestamp", "src_ip", "src_port", "dest_ip", "dest_port", "proto", "signature_id", "signature", "severity", "reason"]],
                use_container_width=True
            )
    else:
        st.warning("No alerts stored in database.")


# -------------------------------------------------------------
# TAB 2: METRICS (Per-Category Table Only, No Redundant Chart)
# -------------------------------------------------------------
with tab_metrics:
    st.markdown("### 📈 Per-Category Detection Performance & False Positive Rate")
    st.markdown(r"Evaluated against aligned ground-truth flow 5-tuples within $\pm 2.0$s tolerance on the held-out test split.")
    
    st.dataframe(
        cat_metrics_df.style.format({
            "Precision": "{:.4f}",
            "Recall": "{:.4f}",
            "F1_Score": "{:.4f}",
            "FP_Rate": "{:.4f}"
        }),
        use_container_width=True
    )


# -------------------------------------------------------------
# TAB 3: CONFUSION MATRIX (Kept with Missed Column)
# -------------------------------------------------------------
with tab_cm:
    st.markdown("### 🔲 Multi-Class Detection Confusion Matrix")
    st.markdown(
        "Features the explicit **'No Rule Matched (Missed)'** column representing zero-day / uncovered attacks "
        "that signature-based systems deterministically leave unflagged without statistical guessing."
    )

    fig_cm = px.imshow(
        cm_df.values,
        x=list(cm_df.columns),
        y=list(cm_df.index),
        labels=dict(x="Signature Prediction", y="Ground Truth Label", color="Flow Count"),
        color_continuous_scale="Blues",
        text_auto=True,
        aspect="auto"
    )
    fig_cm.update_layout(
        title="Full Multi-Class Detection Matrix",
        xaxis_tickangle=-45,
        height=550
    )
    st.plotly_chart(fig_cm, use_container_width=True)


# -------------------------------------------------------------
# TAB 4: RULE COVERAGE (Attribution Table + Active Rules Expander)
# -------------------------------------------------------------
with tab_coverage:
    st.markdown("### 🎯 Rule-Level Attribution Matrix")
    st.markdown("Tracks individual rule fidelity, true positive counts, and false positives.")
    
    st.dataframe(
        attribution_df.style.format({
            "Rule_Precision": "{:.4f}"
        }),
        use_container_width=True
    )

    # Collapsible Active Rules & Hot-Reload Expander at bottom
    with st.expander("📜 Active Rules Inspector & Hot-Reloading", expanded=False):
        st.markdown("Rules are loaded dynamically from `config/custom_rules.rules` without needing application redeployment.")

        if st.button("🔄 Hot-Reload Rules from Disk"):
            st.success("Rules reloaded from disk!")
            st.rerun()

        active_rules_list = load_rules_from_file(RULE_PATH)
        st.markdown(f"**Total Loaded Rules:** `{len(active_rules_list)}`")
        
        for r in active_rules_list:
            st.code(f"Line {r['line_number']}: {r['raw_rule']}", language="bash")


# -------------------------------------------------------------
# LIVE REAL-TIME STREAM AUTO-REFRESH (Fixed 3s Interval)
# -------------------------------------------------------------
if auto_refresh and refresh_interval > 0:
    time.sleep(refresh_interval)
    st.rerun()

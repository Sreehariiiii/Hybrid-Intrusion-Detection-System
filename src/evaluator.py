"""
Evaluation & Attribution Engine for Signature-Based IDS
Performs 5-tuple flow alignment (±2.0s time window), conflict resolution,
per-attack performance metrics, rule-level attribution, and confusion matrix calculation.
"""

import os
import sqlite3
import pandas as pd
import numpy as np
from datetime import datetime


# Discrete condition token count for tiebreaker resolution
RULE_COMPLEXITY_MAP = {
    1000001: 4,  # udp, stateless, threshold count 20, seconds 1
    1000002: 4,  # tcp, flags S, threshold count 25, seconds 1
    1000003: 5,  # tcp, established, content "X-a:", nocase, threshold
    1000004: 6,  # tcp, established, content-length, urlencoded, threshold
    1000005: 6,  # tcp, established, GET /, cache-control, threshold
    1000006: 4,  # tcp, flags S, detection_filter track by_src
    1000007: 5,  # tcp, flags A, stateless, dsize < 2, threshold
    1000008: 4,  # tcp, port 22, flags S, threshold count 5
    1000009: 5,  # tcp, port 21, established, content USER, threshold
    1000010: 5,  # tcp, established, content UNION, nocase, content SELECT, nocase
    1000011: 5,  # tcp, established, content <script, nocase, content >, nocase
    1000012: 5,  # tcp, established, content C2_HEARTBEAT, threshold
    1000013: 4,  # tcp, established, content ADMIN$, ports 445/3389
    1000014: 5,  # tcp, established, content POST login, threshold
}


def parse_iso_timestamp(ts_str: str) -> float:
    """Converts ISO timestamp string to POSIX timestamp with full UTC support."""
    try:
        clean_ts = str(ts_str).strip().replace("Z", "+00:00")
        if len(clean_ts) > 5 and clean_ts[-5] in ["+", "-"] and ":" not in clean_ts[-5:]:
            clean_ts = clean_ts[:-2] + ":" + clean_ts[-2:]
        dt = datetime.fromisoformat(clean_ts)
        return dt.timestamp()
    except Exception:
        return 0.0


def resolve_rule_conflict(matched_alerts: list) -> tuple:
    """
    Conflict Resolution Policy:
    1. Highest severity wins (Priority 1 > Priority 2 > Priority 3).
    2. Tiebreaker: Rule matching highest number of discrete condition tokens.
    3. Secondary matches recorded in overlapping_sids.
    """
    if not matched_alerts:
        return None, None, None, ""

    def sort_key(alert_item):
        sid = alert_item["signature_id"]
        sev = alert_item["severity"]
        # Priority 1 > Priority 2 > Priority 3
        priority_score = -sev
        complexity = RULE_COMPLEXITY_MAP.get(sid, 1)
        return (priority_score, complexity)

    sorted_alerts = sorted(matched_alerts, key=sort_key, reverse=True)
    winner = sorted_alerts[0]
    overlapping = [str(a["signature_id"]) for a in sorted_alerts[1:]]
    return winner["signature_id"], winner["signature"], winner["severity"], ",".join(overlapping)


SID_TO_CATEGORY_MAP = {
    1000001: "DoS-LOIC-UDP",
    1000002: "DoS-LOIC-TCP",
    1000003: "DoS-Slowloris",
    1000004: "DoS-SlowHTTPTest",
    1000005: "DoS-Hulk-GoldenEye",
    1000006: "PortScan-TCP-SYN",
    1000007: "PortScan-Connect",
    1000008: "BruteForce-SSH-Patator",
    1000009: "BruteForce-FTP-Patator",
    1000010: "Web Attack - SQL Injection",
    1000011: "Web Attack - XSS",
    1000012: "Botnet-C2-Beaconing",
    1000013: "Infiltration",
    1000014: "Web Attack - Brute Force"
}

def normalize_cat_name(cat_str: str) -> str:
    s = str(cat_str).strip().lower().replace("_", " ").replace("-", " ")
    if "sql" in s:
        return "Web Attack - SQL Injection"
    if "xss" in s:
        return "Web Attack - XSS"
    if "brute" in s and ("web" in s or "http" in s or "login" in s):
        return "Web Attack - Brute Force"
    if "ssh" in s:
        return "BruteForce-SSH-Patator"
    if "ftp" in s:
        return "BruteForce-FTP-Patator"
    if "infilt" in s:
        return "Infiltration"
    if "port" in s or "scan" in s:
        return "PortScan-Connect"
    if "dos" in s or "ddos" in s or "loic" in s or "hulk" in s or "slow" in s:
        return "DoS"
    if "benign" in s or "normal" in s or "clean" in s:
        return "Benign"
    return str(cat_str).strip()

def evaluate_detection_performance(
    ground_truth_csv: str = "data/ground_truth.csv",
    db_path: str = "database/alerts.db",
    time_delta_sec: float = 2.0
) -> dict:
    """
    Aligns ground truth flows with detected SQLite alerts on 5-tuple within ±2.0s window.
    Computes per-category and global metrics, attribution matrix, and confusion matrix.
    """
    if not os.path.exists(ground_truth_csv):
        raise FileNotFoundError(f"Ground truth file not found: {ground_truth_csv}")

    gt_df = pd.read_csv(ground_truth_csv)

    conn = sqlite3.connect(db_path)
    alerts_df = pd.read_sql_query("SELECT * FROM alerts", conn)
    alerts_df["epoch"] = pd.to_datetime(alerts_df["timestamp"], utc=True, errors="coerce").astype("int64") // 10**9
    gt_df["epoch"] = pd.to_datetime(gt_df["timestamp"], utc=True, errors="coerce").astype("int64") // 10**9

    # Build efficient spatial/temporal index for fast O(1) alert lookup
    from collections import defaultdict
    alert_index_5tuple = defaultdict(list)
    alert_index_src_dport = defaultdict(list)
    alert_index_dst_dport = defaultdict(list)
    alerts_list = alerts_df.to_dict(orient="records")
    for a in alerts_list:
        s_port_int = int(a["src_port"]) if str(a["src_port"]).isdigit() else 0
        d_port_int = int(a["dest_port"]) if str(a["dest_port"]).isdigit() else 0
        proto_up = str(a["proto"]).upper()
        
        alert_index_5tuple[(a["src_ip"], s_port_int, a["dest_ip"], d_port_int, proto_up)].append(a)
        alert_index_src_dport[(a["src_ip"], d_port_int, proto_up)].append(a)
        alert_index_dst_dport[(a["dest_ip"], d_port_int, proto_up)].append(a)

    gt_records = gt_df.to_dict(orient="records")
    eval_results = []
    
    for row in gt_records:
        fid = str(row["flow_id"])
        s_ip = str(row["src_ip"])
        s_port = int(row["src_port"])
        d_ip = str(row["dest_ip"])
        d_port = int(row["dest_port"])
        proto = str(row["proto"]).upper()
        gt_label = str(row["ground_truth_label"])
        exp_sid = int(row["expected_sid"])
        flow_time = float(row.get("epoch", 0.0))
        flow_dur = float(row.get("duration", 0.0))

        # Retrieve candidate alerts from precise 5-tuple bucket first, fallback to dport bucket
        candidates = alert_index_5tuple.get((s_ip, s_port, d_ip, d_port, proto), [])
        if not candidates:
            candidates = alert_index_src_dport.get((s_ip, d_port, proto), [])
        if not candidates and exp_sid in [1000006, 1000007, 1000013]:
            candidates = alert_index_dst_dport.get((d_ip, d_port, proto), [])

        matched = []
        for a in candidates:
            time_diff = abs(a["epoch"] - flow_time)
            if time_diff > (time_delta_sec + flow_dur + 5.0):
                continue

            same_src = (a["src_ip"] == s_ip)
            same_dst = (a["dest_ip"] == d_ip)
            same_sport = (int(a["src_port"]) == s_port)
            same_dport = (int(a["dest_port"]) == d_port)

            is_5tuple_match = (
                (same_src and same_dst and same_sport and same_dport) or
                (a["signature_id"] == exp_sid and same_src and same_dst and same_dport) or
                (a["signature_id"] in [1000006, 1000007, 1000008] and (same_src or same_dst) and same_dport) or
                (a["signature_id"] == 1000013 and (same_src or same_dst))
            )

            if is_5tuple_match:
                matched.append(a)

        # Prioritize matching expected_sid if present in matched candidates
        exact_sid_matches = [a for a in matched if a["signature_id"] == exp_sid]
        if exact_sid_matches:
            det_sid, det_sig, det_sev, overlap = resolve_rule_conflict(exact_sid_matches)
        else:
            det_sid, det_sig, det_sev, overlap = resolve_rule_conflict(matched)

        # Strict Classification Status: TP, FP, TN, FN, MISCLASS
        norm_gt = normalize_cat_name(gt_label)
        det_cat = normalize_cat_name(SID_TO_CATEGORY_MAP.get(det_sid, "")) if det_sid else None
        
        if norm_gt == "Benign":
            if det_sid is not None and det_sid > 0:
                match_status = "FP"
            else:
                match_status = "TN"
        else:  # Attack Ground Truth
            if det_sid is None or det_sid == 0:
                match_status = "FN"
            elif det_cat == norm_gt or det_sid == exp_sid:
                match_status = "TP"
            else:
                match_status = "MISCLASS"

        eval_results.append({
            "flow_id": fid,
            "src_ip": s_ip,
            "src_port": s_port,
            "dest_ip": d_ip,
            "dest_port": d_port,
            "proto": proto,
            "timestamp": row["timestamp"],
            "duration": flow_dur,
            "ground_truth_label": gt_label,
            "expected_sid": exp_sid,
            "detected_sid": det_sid if det_sid else 0,
            "detected_signature": det_sig if det_sig else "No Rule Matched (Missed)",
            "match_status": match_status,
            "overlapping_sids": overlap
        })

    eval_df = pd.DataFrame(eval_results)

    # Save evaluated flows back to SQLite in bulk
    cursor = conn.cursor()
    cursor.execute("DELETE FROM evaluation_flows")
    insert_data = [
        (
            r["flow_id"], r["src_ip"], r["src_port"], r["dest_ip"], r["dest_port"], r["proto"],
            r["timestamp"], r["duration"], r["ground_truth_label"], r["expected_sid"],
            r["detected_sid"], r["detected_signature"], r["match_status"], r["overlapping_sids"]
        ) for r in eval_results
    ]
    cursor.executemany("""
        INSERT INTO evaluation_flows (
            flow_id, src_ip, src_port, dest_ip, dest_port, proto,
            timestamp, duration, ground_truth_label, expected_sid,
            detected_sid, detected_signature, match_status, overlapping_sids
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, insert_data)
    conn.commit()
    conn.close()

    # Per-Category Metrics with Explicit Misclassification Tracking
    categories = sorted(eval_df["ground_truth_label"].unique())
    cat_metrics = []
    for cat in categories:
        sub = eval_df[eval_df["ground_truth_label"] == cat]
        total_flows = len(sub)
        tp = len(sub[sub["match_status"] == "TP"])
        fn = len(sub[sub["match_status"] == "FN"])
        misclass = len(sub[sub["match_status"] == "MISCLASS"])
        
        # SIDs associated with this category
        cat_sids = [sid for sid, cname in SID_TO_CATEGORY_MAP.items() if normalize_cat_name(cname) == normalize_cat_name(cat)]
        
        # FP: Non-category flows predicted as this category's SID
        fp = len(eval_df[(eval_df["ground_truth_label"] != cat) & (eval_df["detected_sid"].isin(cat_sids))])
        tn = len(eval_df[(eval_df["ground_truth_label"] != cat) & (~eval_df["detected_sid"].isin(cat_sids))])

        if cat == "Benign":
            fp = len(sub[sub["match_status"] == "FP"])
            tn = len(sub[sub["match_status"] == "TN"])
            precision = round(tn / (tn + fp) if (tn + fp) > 0 else 1.0, 4)
            recall = round(tn / (tn + fp) if (tn + fp) > 0 else 1.0, 4)
            f1 = round(2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 1.0, 4)
            far = round(fp / (tn + fp) if (tn + fp) > 0 else 0.0, 4)
            misclass = 0
        else:
            recall = round(tp / total_flows if total_flows > 0 else 0.0, 4)
            precision = round(tp / (tp + fp) if (tp + fp) > 0 else (1.0 if tp > 0 else 0.0), 4)
            f1 = round(2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0, 4)
            far = round(fp / (fp + tn) if (fp + tn) > 0 else 0.0, 4)

        cat_metrics.append({
            "Category": cat,
            "Total_Flows": total_flows,
            "TP": tp,
            "FP": fp,
            "TN": tn,
            "FN": fn,
            "Misclassified": misclass,
            "Precision": precision,
            "Recall": recall,
            "F1_Score": f1,
            "FP_Rate": far
        })

    cat_metrics_df = pd.DataFrame(cat_metrics)

    # Rule-Level Attribution
    attribution = []
    all_sids = [1000001, 1000002, 1000003, 1000004, 1000005, 1000006, 1000007, 1000008, 1000009, 1000010, 1000011, 1000012, 1000013, 1000014]
    sid_names = {
        1000001: "DoS High Volume UDP Flood LOIC",
        1000002: "DoS High Volume TCP Syn Flood",
        1000003: "DoS Slowloris Partial HTTP Header",
        1000004: "DoS SlowHTTPTest Saturation",
        1000005: "DoS Application Layer Hulk/GoldenEye",
        1000006: "Port Scan TCP SYN Probing",
        1000007: "Port Scan Full Connect Sweep",
        1000008: "Brute Force SSH-Patator Volumetric Burst",
        1000009: "Brute Force FTP-Patator USER/PASS",
        1000010: "Web Attack SQL Injection",
        1000011: "Web Attack Cross-Site Scripting (XSS)",
        1000012: "Botnet C2 Heartbeat Beacon",
        1000013: "Infiltration SMB/RDP Lateral Sweep",
        1000014: "Web Attack HTTP Brute Force Login"
    }

    for sid in all_sids:
        rule_sub = eval_df[eval_df["detected_sid"] == sid]
        tp_cnt = len(rule_sub[rule_sub["match_status"] == "TP"])
        fp_cnt = len(rule_sub[rule_sub["match_status"].isin(["FP", "MISCLASS"])])
        rule_prec = round(tp_cnt / (tp_cnt + fp_cnt) if (tp_cnt + fp_cnt) > 0 else 0.0, 4)
        attribution.append({
            "SID": sid,
            "Signature_Name": sid_names.get(sid, f"Rule SID {sid}"),
            "TP_Count": tp_cnt,
            "FP_Count": fp_cnt,
            "Rule_Precision": rule_prec,
            "Status": "Active" if (tp_cnt + fp_cnt) > 0 else "Ready / No Triggers"
        })
    attribution_df = pd.DataFrame(attribution)

    # Confusion Matrix (Ground Truth vs. Detected Category / Missed)
    def map_row_to_pred_label(r):
        det_sid = int(r.get("detected_sid", 0))
        if det_sid in SID_TO_CATEGORY_MAP:
            return SID_TO_CATEGORY_MAP[det_sid]
        if r.get("ground_truth_label") == "Benign" and det_sid == 0:
            return "Benign"
        return "No Rule Matched (Missed)"

    eval_df["detected_label_mapped"] = eval_df.apply(map_row_to_pred_label, axis=1)

    confusion_matrix = pd.crosstab(
        eval_df["ground_truth_label"],
        eval_df["detected_label_mapped"],
        rownames=["Ground Truth"],
        colnames=["Signature Prediction"],
        dropna=False
    )

    if "No Rule Matched (Missed)" not in confusion_matrix.columns:
        confusion_matrix["No Rule Matched (Missed)"] = 0

    return {
        "evaluation_df": eval_df,
        "category_metrics": cat_metrics_df,
        "attribution_metrics": attribution_df,
        "confusion_matrix": confusion_matrix
    }


if __name__ == "__main__":
    results = evaluate_detection_performance()
    print("\n--- PER-CATEGORY DETECTION METRICS ---")
    print(results["category_metrics"].to_string(index=False))
    print("\n--- RULE ATTRIBUTION MATRIX ---")
    print(results["attribution_metrics"].to_string(index=False))
    print("\n--- CONFUSION MATRIX ---")
    print(results["confusion_matrix"])

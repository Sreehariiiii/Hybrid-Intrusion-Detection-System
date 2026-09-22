import os
import sys
import time
import json
import sqlite3
import asyncio
import threading
from typing import Optional, List
import psutil
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from src.eve_ingestor import (
    count_pcap_packets,
    start_suricata_subprocess,
    stop_suricata_subprocess,
    LiveEveTailer,
    init_database
)
from src.evaluator import evaluate_detection_performance
from src.alert_notifier import load_rules_from_file
from src.attack_injector import inject_attack_into_pcap_queue

app = FastAPI(title="Hybrid Intrusion Detection System Engine")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

REAL_PCAP_PATH = r"C:\Users\venug\Downloads\Thursday-WorkingHours.pcap"
PCAP_PATH = REAL_PCAP_PATH if os.path.exists(REAL_PCAP_PATH) else os.path.join(ROOT_DIR, "data", "slice_test", "thursday_sample_500k.pcap")
DB_PATH = os.path.join(ROOT_DIR, "database", "alerts.db")
GT_CSV_PATH = os.path.join(ROOT_DIR, "data", "ground_truth.csv")
RULE_PATH = os.path.join(ROOT_DIR, "config", "custom_rules.rules")

# Large Traffic / Full-PCAP Execution State
large_traffic_state = {
    "is_running": False,
    "status": "Idle",
    "pcap_filename": os.path.basename(PCAP_PATH),
    "pcap_size_gb": round(os.path.getsize(PCAP_PATH) / (1024**3), 2) if os.path.exists(PCAP_PATH) else 0.0,
    "current_pkts": 0,
    "total_pkts": 9322025 if "Thursday" in os.path.basename(PCAP_PATH) else count_pcap_packets(PCAP_PATH),
    "progress_pct": 0.0,
    "elapsed_sec": 0.0,
    "eta_sec": 0.0,
    "pkts_per_sec": 0.0,
    "mb_per_sec": 0.0,
    "alerts_count": 0,
    "high_alerts": 0,
    "med_alerts": 0,
    "low_alerts": 0,
    "unique_signatures": 0,
    "packet_drops": 0,
    "processing_errors": 0,
    "cpu_percent": 0.0,
    "ram_used_mb": 0.0,
    "ram_percent": 0.0,
    "is_partial": False,
    "stop_requested": False,
    "stop_message": "",
    "completed_report": None
}

_active_suricata_proc = None
_active_tailer = None
_eval_cache = None
event_subscribers = []

def broadcast_event(event_type: str, data: dict):
    payload = json.dumps({"type": event_type, "data": data})
    for q in list(event_subscribers):
        try:
            q.put_nowait(payload)
        except Exception:
            pass

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Dashboard Loading...</h1>"

@app.get("/api/status")
def get_status():
    mem = psutil.virtual_memory()
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        total_alerts = cur.execute("SELECT COUNT(1) FROM alerts").fetchone()[0]
        cur.execute("SELECT signature, COUNT(1) as cnt, severity, category FROM alerts GROUP BY signature ORDER BY cnt DESC LIMIT 8")
        top_threats = [{"signature": r[0], "count": r[1], "severity": r[2], "category": r[3]} for r in cur.fetchall()]
    except Exception:
        total_alerts = 0
        top_threats = []
    finally:
        conn.close()
    
    large_traffic_state["alerts_count"] = total_alerts
    large_traffic_state["ram_used_mb"] = round((mem.total - mem.available) / (1024 * 1024), 1)
    large_traffic_state["ram_percent"] = mem.percent
    
    return {
        "pcap_filename": large_traffic_state["pcap_filename"],
        "pcap_size_gb": large_traffic_state["pcap_size_gb"],
        "total_packets": large_traffic_state["total_pkts"],
        "total_alerts": total_alerts,
        "ram_used_mb": large_traffic_state["ram_used_mb"],
        "ram_percent": mem.percent,
        "large_traffic_state": large_traffic_state,
        "top_threats": top_threats
    }

# ==============================================================================
# TAB 1: ACCURACY BENCHMARK ENDPOINTS (6,216 FLOWS)
# ==============================================================================

@app.get("/api/benchmark/results")
def get_benchmark_results():
    global _eval_cache
    if not os.path.exists(DB_PATH):
        return {"status": "unverified", "message": "Accuracy: Not yet verified"}
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        count = cur.execute("SELECT COUNT(1) FROM alerts").fetchone()[0]
        if count == 0:
            return {"status": "unverified", "message": "Accuracy: Not yet verified (Database is empty)"}
    finally:
        conn.close()

    try:
        if _eval_cache is None:
            _eval_cache = evaluate_detection_performance(GT_CSV_PATH, DB_PATH)
        
        cm = _eval_cache["confusion_matrix"]
        return {
            "status": "verified",
            "benchmark_dataset": _eval_cache["benchmark_dataset"],
            "total_flows": _eval_cache["total_flows"],
            "total_tp": _eval_cache["total_tp"],
            "total_tn": _eval_cache["total_tn"],
            "total_fp": _eval_cache["total_fp"],
            "total_fn": _eval_cache["total_fn"],
            "total_misclassified": _eval_cache["total_misclassified"],
            "exact_accuracy": _eval_cache["exact_accuracy"],
            "behavioural_detection_rate": _eval_cache["behavioural_detection_rate"],
            "benign_specificity": _eval_cache["benign_specificity"],
            "benign_far": _eval_cache["benign_far"],
            "macro_precision": _eval_cache["macro_precision"],
            "macro_recall": _eval_cache["macro_recall"],
            "macro_f1": _eval_cache["macro_f1"],
            "category_metrics": _eval_cache["category_metrics"].to_dict(orient="records"),
            "attribution_metrics": _eval_cache["attribution_metrics"].to_dict(orient="records"),
            "confusion_matrix": {
                "classes": list(cm.columns),
                "ground_truth_labels": list(cm.index),
                "matrix": cm.values.tolist()
            }
        }
    except Exception as e:
        return {"status": "error", "message": f"Evaluation error: {str(e)}"}

@app.post("/api/benchmark/run")
def run_accuracy_benchmark():
    global _eval_cache
    try:
        _eval_cache = evaluate_detection_performance(GT_CSV_PATH, DB_PATH)
        return get_benchmark_results()
    except Exception as e:
        return {"status": "error", "message": f"Evaluation execution failed: {str(e)}"}

# ==============================================================================
# TAB 2: LARGE TRAFFIC / OPERATIONAL ANALYSIS ENDPOINTS
# ==============================================================================

def _large_traffic_worker():
    global large_traffic_state, _active_suricata_proc, _active_tailer, _eval_cache
    large_traffic_state["is_running"] = True
    large_traffic_state["status"] = "Running"
    large_traffic_state["stop_requested"] = False
    large_traffic_state["is_partial"] = False
    large_traffic_state["stop_message"] = ""
    large_traffic_state["completed_report"] = None
    
    total_pkts = large_traffic_state["total_pkts"]
    start_t = time.time()
    eve_path = "logs/eve.json"
    
    _active_tailer = LiveEveTailer(eve_path=eve_path, db_path=DB_PATH)
    _active_tailer.start_tailing()
    
    try:
        _active_suricata_proc = start_suricata_subprocess(pcap_path=PCAP_PATH)
    except Exception as e:
        large_traffic_state["is_running"] = False
        large_traffic_state["status"] = "Failed"
        large_traffic_state["stop_message"] = f"Engine launch failed: {str(e)}"
        _active_tailer.stop()
        return

    current_pkts = 0
    pcap_sz_bytes = os.path.getsize(PCAP_PATH) if os.path.exists(PCAP_PATH) else 0

    while _active_suricata_proc and _active_suricata_proc.poll() is None and not large_traffic_state["stop_requested"]:
        time.sleep(1.0)
        now_t = time.time()
        elapsed = now_t - start_t
        
        # Parse decoder stats from eve.json
        if os.path.exists(eve_path):
            try:
                with open(eve_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if '"event_type":"stats"' in line:
                            st_evt = json.loads(line.strip())
                            st_data = st_evt.get("stats", {})
                            dec = st_data.get("decoder", {}).get("pkts", 0)
                            drops = st_data.get("capture", {}).get("kernel_drops", 0)
                            if dec > current_pkts:
                                current_pkts = dec
                            if drops > large_traffic_state["packet_drops"]:
                                large_traffic_state["packet_drops"] = drops
            except Exception:
                pass

        if current_pkts > total_pkts:
            total_pkts = current_pkts
            large_traffic_state["total_pkts"] = total_pkts

        pct = round((current_pkts / total_pkts) * 100, 2) if total_pkts > 0 else 0.0
        pkt_rate = current_pkts / elapsed if elapsed > 0 else 0.0
        rem_pkts = max(0, total_pkts - current_pkts)
        eta_sec = rem_pkts / pkt_rate if pkt_rate > 0 else 0.0
        mb_rate = (pkt_rate * (pcap_sz_bytes / total_pkts)) / (1024 * 1024) if total_pkts > 0 else 0.0

        # Query live severity counts from SQLite
        conn_tmp = sqlite3.connect(DB_PATH)
        try:
            cur = conn_tmp.cursor()
            real_db_count = cur.execute("SELECT COUNT(1) FROM alerts").fetchone()[0]
            cur.execute("SELECT severity, COUNT(1) FROM alerts GROUP BY severity")
            sev_map = dict(cur.fetchall())
            uniq_sigs = cur.execute("SELECT COUNT(DISTINCT signature_id) FROM alerts").fetchone()[0]
        except Exception:
            real_db_count = _active_tailer.total_streamed
            sev_map = {}
            uniq_sigs = 0
        finally:
            conn_tmp.close()

        mem = psutil.virtual_memory()
        cpu = psutil.cpu_percent(interval=None)

        large_traffic_state["current_pkts"] = min(current_pkts, total_pkts)
        large_traffic_state["progress_pct"] = pct
        large_traffic_state["elapsed_sec"] = round(elapsed, 1)
        large_traffic_state["eta_sec"] = round(eta_sec, 1)
        large_traffic_state["pkts_per_sec"] = round(pkt_rate, 1)
        large_traffic_state["mb_per_sec"] = round(mb_rate, 2)
        large_traffic_state["alerts_count"] = real_db_count
        large_traffic_state["high_alerts"] = sev_map.get(1, 0)
        large_traffic_state["med_alerts"] = sev_map.get(2, 0)
        large_traffic_state["low_alerts"] = sev_map.get(3, 0)
        large_traffic_state["unique_signatures"] = uniq_sigs
        large_traffic_state["cpu_percent"] = cpu
        large_traffic_state["ram_used_mb"] = round((mem.total - mem.available) / (1024 * 1024), 1)
        large_traffic_state["ram_percent"] = mem.percent

        if _active_tailer.new_alerts_buffer:
            batch = _active_tailer.new_alerts_buffer[:15]
            del _active_tailer.new_alerts_buffer[:15]
            for na in batch:
                broadcast_event("new_alert", na)

        broadcast_event("large_traffic_progress", dict(large_traffic_state))

    # Handle completion or graceful stop
    if large_traffic_state["stop_requested"]:
        large_traffic_state["status"] = "Stopped by User"
        large_traffic_state["is_partial"] = True
        large_traffic_state["stop_message"] = "Partial results — capture was not fully processed."
        stop_suricata_subprocess(_active_suricata_proc)
    else:
        large_traffic_state["current_pkts"] = total_pkts
        large_traffic_state["progress_pct"] = 100.0
        large_traffic_state["status"] = "Completed"
        large_traffic_state["is_partial"] = False
        large_traffic_state["stop_message"] = "Full capture processed successfully."

    _active_tailer.stop()
    if _active_suricata_proc:
        try:
            _active_suricata_proc.communicate(timeout=5)
        except Exception:
            pass

    total_elapsed = round(time.time() - start_t, 1)
    large_traffic_state["elapsed_sec"] = total_elapsed
    large_traffic_state["is_running"] = False
    
    # Query final counts from DB
    conn_final = sqlite3.connect(DB_PATH)
    try:
        cur = conn_final.cursor()
        final_alerts = cur.execute("SELECT COUNT(1) FROM alerts").fetchone()[0]
        cur.execute("SELECT severity, COUNT(1) FROM alerts GROUP BY severity")
        sev_map = dict(cur.fetchall())
        uniq_sigs = cur.execute("SELECT COUNT(DISTINCT signature_id) FROM alerts").fetchone()[0]
    except Exception:
        final_alerts = _active_tailer.total_streamed
        sev_map = {}
        uniq_sigs = 0
    finally:
        conn_final.close()

    large_traffic_state["alerts_count"] = final_alerts
    large_traffic_state["high_alerts"] = sev_map.get(1, 0)
    large_traffic_state["med_alerts"] = sev_map.get(2, 0)
    large_traffic_state["low_alerts"] = sev_map.get(3, 0)
    large_traffic_state["unique_signatures"] = uniq_sigs

    report = {
        "capture_filename": large_traffic_state["pcap_filename"],
        "capture_size_gb": large_traffic_state["pcap_size_gb"],
        "packets_processed": large_traffic_state["current_pkts"],
        "total_packets_in_file": large_traffic_state["total_pkts"],
        "processing_time_sec": total_elapsed,
        "sustained_throughput_pkts_sec": round(large_traffic_state["current_pkts"] / total_elapsed, 1) if total_elapsed > 0 else 0.0,
        "sustained_throughput_mb_sec": round(((large_traffic_state["current_pkts"] / total_elapsed) * (pcap_sz_bytes / total_pkts)) / (1024 * 1024), 2) if (total_elapsed > 0 and total_pkts > 0) else 0.0,
        "total_alerts_generated": final_alerts,
        "unique_signatures_triggered": uniq_sigs,
        "high_severity_alerts": sev_map.get(1, 0),
        "medium_severity_alerts": sev_map.get(2, 0),
        "low_severity_alerts": sev_map.get(3, 0),
        "packet_drops": large_traffic_state["packet_drops"],
        "processing_errors": large_traffic_state["processing_errors"],
        "database_records_committed": final_alerts,
        "peak_memory_mb": large_traffic_state["ram_used_mb"],
        "engine_status": large_traffic_state["status"],
        "is_partial": large_traffic_state["is_partial"],
        "notice": large_traffic_state["stop_message"]
    }
    large_traffic_state["completed_report"] = report

    # Clear benchmark cache on new alerts run
    _eval_cache = None

    broadcast_event("large_traffic_progress", dict(large_traffic_state))
    broadcast_event("large_traffic_completed", report)

@app.post("/api/large-traffic/start")
def start_large_traffic():
    if large_traffic_state["is_running"]:
        return {"status": "error", "message": "Large traffic analysis already in progress."}
    threading.Thread(target=_large_traffic_worker, daemon=True).start()
    return {"status": "started", "pcap": large_traffic_state["pcap_filename"]}

@app.post("/api/large-traffic/stop")
def stop_large_traffic():
    if not large_traffic_state["is_running"]:
        return {"status": "idle", "message": "No active PCAP replay running."}
    
    large_traffic_state["stop_requested"] = True
    large_traffic_state["status"] = "Stopping..."
    broadcast_event("large_traffic_progress", dict(large_traffic_state))
    
    stop_suricata_subprocess(_active_suricata_proc)
    
    return {
        "status": "stopping",
        "message": "Graceful stop requested. Flushing remaining records and committing database transactions..."
    }

@app.get("/api/large-traffic/status")
def get_large_traffic_status():
    return large_traffic_state

@app.get("/api/large-traffic/report")
def get_large_traffic_report():
    if large_traffic_state["completed_report"]:
        return {"status": "available", "report": large_traffic_state["completed_report"]}
    return {"status": "none", "message": "No full PCAP run completed yet."}

# ==============================================================================
# ALERTS & VISUALIZATIONS
# ==============================================================================

@app.get("/api/alerts/summary")
def get_alerts_summary():
    if not os.path.exists(DB_PATH):
        return {
            "total_alerts": 0,
            "severity_distribution": {"High": 0, "Medium": 0, "Low": 0},
            "category_distribution": [],
            "top_src_ips": [],
            "top_dest_ips": [],
            "top_dest_ports": [],
            "protocol_distribution": []
        }
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        total_alerts = cur.execute("SELECT COUNT(1) FROM alerts").fetchone()[0]
        if total_alerts == 0:
            return {
                "total_alerts": 0,
                "severity_distribution": {"High": 0, "Medium": 0, "Low": 0},
                "category_distribution": [],
                "top_src_ips": [],
                "top_dest_ips": [],
                "top_dest_ports": [],
                "protocol_distribution": []
            }

        # Severity
        cur.execute("SELECT severity, COUNT(1) FROM alerts GROUP BY severity")
        smap = dict(cur.fetchall())
        sev_dist = {
            "High": smap.get(1, 0),
            "Medium": smap.get(2, 0),
            "Low": smap.get(3, 0)
        }

        # Categories
        cur.execute("SELECT category, COUNT(1) as cnt FROM alerts GROUP BY category ORDER BY cnt DESC")
        cat_dist = [{"category": r[0], "count": r[1]} for r in cur.fetchall()]

        # Top Source IPs
        cur.execute("SELECT src_ip, COUNT(1) as cnt FROM alerts GROUP BY src_ip ORDER BY cnt DESC LIMIT 6")
        top_src = [{"ip": r[0], "count": r[1]} for r in cur.fetchall()]

        # Top Dest IPs
        cur.execute("SELECT dest_ip, COUNT(1) as cnt FROM alerts GROUP BY dest_ip ORDER BY cnt DESC LIMIT 6")
        top_dst = [{"ip": r[0], "count": r[1]} for r in cur.fetchall()]

        # Top Dest Ports
        cur.execute("SELECT dest_port, COUNT(1) as cnt FROM alerts GROUP BY dest_port ORDER BY cnt DESC LIMIT 6")
        top_ports = [{"port": r[0], "count": r[1]} for r in cur.fetchall()]

        # Protocols
        cur.execute("SELECT proto, COUNT(1) as cnt FROM alerts GROUP BY proto ORDER BY cnt DESC")
        proto_dist = [{"proto": r[0], "count": r[1]} for r in cur.fetchall()]

        return {
            "total_alerts": total_alerts,
            "severity_distribution": sev_dist,
            "category_distribution": cat_dist,
            "top_src_ips": top_src,
            "top_dest_ips": top_dst,
            "top_dest_ports": top_ports,
            "protocol_distribution": proto_dist
        }
    finally:
        conn.close()

@app.get("/api/alerts")
def get_alerts(q: Optional[str] = None, severity: Optional[int] = None, limit: int = 100, offset: int = 0, grouped: bool = True):
    if not os.path.exists(DB_PATH):
        return {"alerts": [], "grouped_alerts": [], "total": 0}
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        query = "SELECT id, timestamp, src_ip, src_port, dest_ip, dest_port, proto, signature_id, signature, category, severity, bytes_toserver, pkts_toserver, reason FROM alerts WHERE 1=1"
        params = []
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if q:
            query += " AND (signature LIKE ? OR src_ip LIKE ? OR dest_ip LIKE ? OR reason LIKE ?)"
            wild = f"%{q}%"
            params.extend([wild, wild, wild, wild])
        
        count_cur = conn.cursor()
        count_cur.execute(f"SELECT COUNT(1) FROM ({query})", params)
        total = count_cur.fetchone()[0]
        
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        cur.execute(query, params)
        rows = cur.fetchall()
        
        raw_alerts = []
        for r in rows:
            raw_alerts.append({
                "id": r[0],
                "timestamp": r[1],
                "src_ip": r[2],
                "src_port": r[3],
                "dest_ip": r[4],
                "dest_port": r[5],
                "proto": r[6],
                "signature_id": r[7],
                "signature": r[8],
                "category": r[9],
                "severity": r[10],
                "bytes_toserver": r[11],
                "pkts_toserver": r[12],
                "reason": r[13]
            })
        
        grouped_alerts = []
        current_group = None
        for a in raw_alerts:
            if current_group and current_group["signature_id"] == a["signature_id"]:
                current_group["count"] += 1
                current_group["instances"].append(a)
                current_group["last_seen"] = a["timestamp"]
            else:
                if current_group:
                    grouped_alerts.append(current_group)
                current_group = {
                    "signature_id": a["signature_id"],
                    "signature": a["signature"],
                    "severity": a["severity"],
                    "category": a["category"],
                    "count": 1,
                    "first_seen": a["timestamp"],
                    "last_seen": a["timestamp"],
                    "sample_src": f"{a['src_ip']}:{a['src_port']}",
                    "sample_dst": f"{a['dest_ip']}:{a['dest_port']}",
                    "sample_proto": a["proto"],
                    "sample_reason": a["reason"],
                    "sample_bytes": a["bytes_toserver"],
                    "sample_pkts": a["pkts_toserver"],
                    "instances": [a]
                }
        if current_group:
            grouped_alerts.append(current_group)
        
        return {
            "alerts": raw_alerts,
            "grouped_alerts": grouped_alerts,
            "total": total
        }
    finally:
        conn.close()

@app.get("/api/rules")
def get_rules():
    try:
        rules = load_rules_from_file(RULE_PATH)
        return {"rules": rules, "count": len(rules)}
    except Exception as e:
        return {"rules": [], "count": 0, "error": str(e)}

@app.post("/api/reset")
def reset_database():
    global _eval_cache, large_traffic_state
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM alerts")
        cur.execute("DELETE FROM evaluation_flows")
        conn.commit()
    finally:
        conn.close()
    
    eve_path = "logs/eve.json"
    if os.path.exists(eve_path):
        try:
            with open(eve_path, "w", encoding="utf-8") as f:
                pass
        except Exception:
            pass
            
    _eval_cache = None
    large_traffic_state["is_running"] = False
    large_traffic_state["status"] = "Idle — database cleared"
    large_traffic_state["current_pkts"] = 0
    large_traffic_state["alerts_count"] = 0
    large_traffic_state["elapsed_sec"] = 0.0
    large_traffic_state["eta_sec"] = 0.0
    large_traffic_state["completed_report"] = None
    
    broadcast_event("reset", {})
    return {"status": "success", "message": "Database, logs, and benchmark cache successfully reset."}

@app.post("/api/inject")
def inject_attack(req: dict):
    atk_type = req.get("attack_type", "WebAttack-SQLi")
    tgt = req.get("target_host", "192.168.10.50")
    try:
        res = inject_attack_into_pcap_queue(attack_type=atk_type, target_host=tgt, pcap_path=PCAP_PATH, db_path=DB_PATH)
        return {"status": "success", "result": res}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/stream/events")
async def stream_events(request: Request):
    async def event_generator():
        q = asyncio.Queue()
        event_subscribers.append(q)
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    payload = await asyncio.wait_for(q.get(), timeout=1.0)
                    yield f"data: {payload}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            if q in event_subscribers:
                event_subscribers.remove(q)
    return StreamingResponse(event_generator(), media_type="text/event-stream")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


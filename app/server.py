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

from src.eve_ingestor import count_pcap_packets, start_suricata_subprocess, LiveEveTailer, init_database
from src.evaluator import evaluate_detection_performance
from src.alert_notifier import load_rules_from_file
from src.attack_injector import inject_attack_into_pcap_queue

app = FastAPI(title="Intrusion Detection System Engine")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

REAL_PCAP_PATH = r"C:\Users\venug\Downloads\Thursday-WorkingHours.pcap"
PCAP_PATH = REAL_PCAP_PATH if os.path.exists(REAL_PCAP_PATH) else os.path.join(ROOT_DIR, "data", "slice_test", "thursday_sample_500k.pcap")
DB_PATH = os.path.join(ROOT_DIR, "database", "alerts.db")
GT_CSV_PATH = os.path.join(ROOT_DIR, "data", "ground_truth.csv")
RULE_PATH = os.path.join(ROOT_DIR, "config", "custom_rules.rules")

replay_state = {
    "is_running": False,
    "current_pkts": 0,
    "total_pkts": count_pcap_packets(PCAP_PATH),
    "elapsed": 0.0,
    "eta": 0.0,
    "status": "Idle",
    "alerts_count": 0
}

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
    pcap_size_gb = os.path.getsize(PCAP_PATH) / (1024**3) if os.path.exists(PCAP_PATH) else 0.0
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
    
    # Synchronize replay state alert count with SQLite count
    replay_state["alerts_count"] = total_alerts
    
    return {
        "pcap_filename": os.path.basename(PCAP_PATH),
        "pcap_size_gb": round(pcap_size_gb, 2),
        "total_packets": replay_state["total_pkts"],
        "total_alerts": total_alerts,
        "ram_used_mb": round((mem.total - mem.available) / (1024 * 1024), 1),
        "ram_percent": mem.percent,
        "replay_state": replay_state,
        "top_threats": top_threats
    }

@app.get("/api/dataset-composition")
def get_dataset_composition():
    if not os.path.exists(DB_PATH):
        return {"total_flows": 0, "total_alerts": 0, "benign_count": 0, "categories": []}
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        total_alerts = cur.execute("SELECT COUNT(1) FROM alerts").fetchone()[0]
        cur.execute("SELECT signature, category, COUNT(1) as cnt FROM alerts GROUP BY signature ORDER BY cnt DESC")
        cat_rows = cur.fetchall()
        
        # When DB is reset and no alerts exist, report 0 alerts and idle composition
        if total_alerts == 0:
            return {
                "total_flows": 0,
                "total_alerts": 0,
                "benign_count": 0,
                "categories": []
            }
        
        total_dataset_items = replay_state["total_pkts"] if replay_state["total_pkts"] > 0 else 458968
        if os.path.exists(GT_CSV_PATH):
            try:
                with open(GT_CSV_PATH, "r", encoding="utf-8", errors="ignore") as f:
                    total_dataset_items = max(1, sum(1 for _ in f) - 1)
            except Exception:
                pass
        
        benign_count = max(0, total_dataset_items - total_alerts)
        categories = []
        
        # Clean / Normal traffic segment in GREEN
        benign_pct = round((benign_count / total_dataset_items) * 100, 2) if total_dataset_items > 0 else 100.0
        categories.append({
            "name": "Clean / Normal Traffic",
            "count": benign_count,
            "percentage": benign_pct,
            "color": "#10b981",
            "is_benign": True
        })
        
        palette = ["#ef4444", "#f59e0b", "#8b5cf6", "#3b82f6", "#ec4899", "#14b8a6", "#f97316", "#06b6d4"]
        for idx, (sig_name, cat_name, cnt) in enumerate(cat_rows):
            pct = round((cnt / total_dataset_items) * 100, 2) if total_dataset_items > 0 else 0.0
            color = palette[idx % len(palette)]
            categories.append({
                "name": sig_name,
                "category": cat_name,
                "count": cnt,
                "percentage": pct,
                "color": color,
                "is_benign": False
            })
        
        return {
            "total_flows": total_dataset_items,
            "total_alerts": total_alerts,
            "benign_count": benign_count,
            "categories": categories
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
        
        # Group consecutive alerts for clean deduplicated presentation
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

_cached_eval_result = None
_last_eval_db_mtime = 0.0

def get_cached_evaluation():
    global _cached_eval_result, _last_eval_db_mtime
    db_mtime = os.path.getmtime(DB_PATH) if os.path.exists(DB_PATH) else 0.0
    if _cached_eval_result is None or db_mtime > _last_eval_db_mtime:
        res = evaluate_detection_performance(GT_CSV_PATH, DB_PATH)
        _cached_eval_result = res
        _last_eval_db_mtime = os.path.getmtime(DB_PATH) if os.path.exists(DB_PATH) else 0.0
    return _cached_eval_result

@app.get("/api/metrics")
def get_metrics():
    if not os.path.exists(DB_PATH):
        return {"category_metrics": [], "attribution_metrics": []}
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        total_alerts = cur.execute("SELECT COUNT(1) FROM alerts").fetchone()[0]
        if total_alerts == 0:
            return {"category_metrics": [], "attribution_metrics": []}
    finally:
        conn.close()
    try:
        res = get_cached_evaluation()
        return {
            "category_metrics": res["category_metrics"].to_dict(orient="records"),
            "attribution_metrics": res["attribution_metrics"].to_dict(orient="records")
        }
    except Exception as e:
        return {"category_metrics": [], "attribution_metrics": [], "error": str(e)}

@app.get("/api/confusion-matrix")
def get_confusion_matrix():
    if not os.path.exists(DB_PATH):
        return {"classes": [], "ground_truth_labels": [], "matrix": []}
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        total_alerts = cur.execute("SELECT COUNT(1) FROM alerts").fetchone()[0]
        if total_alerts == 0:
            return {"classes": [], "ground_truth_labels": [], "matrix": []}
    finally:
        conn.close()
    try:
        res = get_cached_evaluation()
        cm = res["confusion_matrix"]
        return {
            "classes": list(cm.columns),
            "ground_truth_labels": list(cm.index),
            "matrix": cm.values.tolist()
        }
    except Exception as e:
        return {"classes": [], "ground_truth_labels": [], "matrix": [], "error": str(e)}

@app.get("/api/rules")
def get_rules():
    try:
        rules = load_rules_from_file(RULE_PATH)
        return {"rules": rules, "count": len(rules)}
    except Exception as e:
        return {"rules": [], "count": 0, "error": str(e)}

@app.post("/api/reset")
def reset_database():
    global _cached_eval_result, _last_eval_db_mtime, replay_state
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
            
    _cached_eval_result = None
    _last_eval_db_mtime = 0.0
    replay_state["is_running"] = False
    replay_state["status"] = "Idle — no data"
    replay_state["current_pkts"] = 0
    replay_state["alerts_count"] = 0
    replay_state["elapsed"] = 0.0
    replay_state["eta"] = 0.0
    
    broadcast_event("reset", {})
    return {"status": "success", "message": "Database, eve logs, and cache successfully reset to empty state."}

def _run_replay_worker():
    global replay_state, _cached_eval_result, _last_eval_db_mtime
    replay_state["is_running"] = True
    replay_state["status"] = "Processing PCAP..."
    
    # 9,322,025 is the exact decoded packet count of Thursday-WorkingHours.pcap
    total_pkts = count_pcap_packets(PCAP_PATH)
    if "Thursday" in os.path.basename(PCAP_PATH):
        total_pkts = 9322025
    replay_state["total_pkts"] = total_pkts

    proc = start_suricata_subprocess(pcap_path=PCAP_PATH)
    eve_path = "logs/eve.json"
    tailer = LiveEveTailer(eve_path=eve_path, db_path=DB_PATH)
    tailer.start_tailing()
    start_t = time.time()
    current_pkts = 0
    last_eval_t = 0.0

    while proc.poll() is None:
        time.sleep(1.0)
        now_t = time.time()
        elapsed = now_t - start_t
        if os.path.exists(eve_path):
            try:
                with open(eve_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if '"event_type":"stats"' in line:
                            st_evt = json.loads(line.strip())
                            dec = st_evt.get("stats", {}).get("decoder", {}).get("pkts", 0)
                            if dec > current_pkts:
                                current_pkts = dec
            except Exception:
                pass
                
        if current_pkts > total_pkts:
            total_pkts = current_pkts
            replay_state["total_pkts"] = total_pkts

        pkt_rate = current_pkts / elapsed if elapsed > 0 else 0
        rem_pkts = max(0, total_pkts - current_pkts)
        eta_sec = rem_pkts / pkt_rate if pkt_rate > 0 else 0
        
        conn_tmp = sqlite3.connect(DB_PATH)
        try:
            real_db_count = conn_tmp.cursor().execute("SELECT COUNT(1) FROM alerts").fetchone()[0]
        except Exception:
            real_db_count = tailer.total_streamed
        finally:
            conn_tmp.close()

        replay_state["current_pkts"] = min(current_pkts, total_pkts)
        replay_state["elapsed"] = round(elapsed, 1)
        replay_state["eta"] = round(eta_sec, 1)
        replay_state["alerts_count"] = real_db_count
        
        # Periodic live evaluation update every 5 seconds if new alerts arrived
        if real_db_count > 0 and (now_t - last_eval_t) >= 5.0:
            last_eval_t = now_t
            try:
                _cached_eval_result = evaluate_detection_performance(GT_CSV_PATH, DB_PATH)
                _last_eval_db_mtime = time.time()
            except Exception:
                pass

        if tailer.new_alerts_buffer:
            batch = tailer.new_alerts_buffer[:15]
            del tailer.new_alerts_buffer[:15]
            for na in batch:
                broadcast_event("new_alert", na)
                
        broadcast_event("progress", {
            "current_pkts": replay_state["current_pkts"],
            "total_pkts": total_pkts,
            "elapsed": round(elapsed, 1),
            "eta": round(eta_sec, 1),
            "alerts_count": real_db_count
        })

    tailer.stop()
    proc.communicate()
    
    # Finalize progress to 100% on completion
    replay_state["current_pkts"] = total_pkts
    replay_state["is_running"] = False
    replay_state["status"] = "Completed"
    
    conn_final = sqlite3.connect(DB_PATH)
    try:
        final_db_count = conn_final.cursor().execute("SELECT COUNT(1) FROM alerts").fetchone()[0]
    except Exception:
        final_db_count = tailer.total_streamed
    finally:
        conn_final.close()
    
    replay_state["alerts_count"] = final_db_count
    
    # Final strict flow evaluation
    try:
        _cached_eval_result = evaluate_detection_performance(GT_CSV_PATH, DB_PATH)
        _last_eval_db_mtime = time.time()
    except Exception as e:
        print(f"[!] Evaluation calculation error: {e}")
        
    broadcast_event("progress", {
        "current_pkts": total_pkts,
        "total_pkts": total_pkts,
        "elapsed": round(time.time() - start_t, 1),
        "eta": 0.0,
        "alerts_count": final_db_count
    })
    broadcast_event("completed", {"alerts_count": final_db_count})

@app.post("/api/replay/start")
def start_replay():
    if replay_state["is_running"]:
        return {"status": "error", "message": "Replay already in progress."}
    threading.Thread(target=_run_replay_worker, daemon=True).start()
    return {"status": "started"}

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

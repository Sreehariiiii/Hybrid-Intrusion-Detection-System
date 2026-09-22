"""
Resource & Throughput Benchmark Engine for Signature-Based IDS
Tracks execution runtime, data throughput (MB/s, Flows/s), and peak memory (RSS MB).
"""

import os
import time
import uuid
import sqlite3
import psutil
from datetime import datetime


def get_current_rss_mb() -> float:
    """Returns current process and child process RSS memory in Megabytes."""
    proc = psutil.Process(os.getpid())
    mem_info = proc.memory_info()
    rss_total = mem_info.rss
    try:
        for child in proc.children(recursive=True):
            rss_total += child.memory_info().rss
    except Exception:
        pass
    return round(rss_total / (1024.0 * 1024.0), 2)


def run_benchmark_pipeline(
    pcap_path: str = "data/raw_pcap/traffic_sample.pcap",
    ground_truth_csv: str = "data/ground_truth.csv",
    db_path: str = "database/alerts.db"
) -> dict:
    """
    Executes and benchmarks the complete detection, ingestion, and evaluation pipeline.
    Measures processing time, throughput (MB/s, Flows/s), and peak RSS memory.
    """
    from src.eve_ingestor import run_pipeline_ingestion
    from src.evaluator import evaluate_detection_performance

    run_id = f"RUN_{uuid.uuid4().hex[:8].upper()}"
    start_time = time.perf_counter()
    initial_mem = get_current_rss_mb()
    peak_mem = initial_mem

    pcap_size_bytes = os.path.getsize(pcap_path) if os.path.exists(pcap_path) else 0

    # Ingestion step
    t0 = time.perf_counter()
    alert_count = run_pipeline_ingestion(pcap_path=pcap_path, db_path=db_path)
    peak_mem = max(peak_mem, get_current_rss_mb())

    # Evaluation step
    eval_results = evaluate_detection_performance(ground_truth_csv=ground_truth_csv, db_path=db_path)
    peak_mem = max(peak_mem, get_current_rss_mb())
    
    total_runtime_sec = max(0.001, time.perf_counter() - start_time)
    total_flows = len(eval_results["evaluation_df"])

    # Throughput calculations
    throughput_mb_s = round((pcap_size_bytes / (1024.0 * 1024.0)) / total_runtime_sec, 2)
    throughput_flows_s = round(total_flows / total_runtime_sec, 2)

    # Estimate packet count safely without loading entire pcap into RAM
    total_packets = 0
    try:
        from scapy.all import PcapReader
        with PcapReader(pcap_path) as pcap_reader:
            for _ in pcap_reader:
                total_packets += 1
                if total_packets >= 1000000:
                    break
    except Exception:
        total_packets = total_flows * 15

    benchmark_summary = {
        "run_id": run_id,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "total_runtime_sec": round(total_runtime_sec, 4),
        "pcap_size_bytes": pcap_size_bytes,
        "total_flows": total_flows,
        "total_packets": total_packets,
        "throughput_mb_s": throughput_mb_s,
        "throughput_flows_s": throughput_flows_s,
        "peak_memory_rss_mb": peak_mem,
        "total_alerts": alert_count
    }

    # Store benchmark metrics into SQLite
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO benchmark_metrics (
            run_id, timestamp, total_runtime_sec, pcap_size_bytes,
            total_flows, total_packets, throughput_mb_s, throughput_flows_s,
            peak_memory_rss_mb, total_alerts
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        run_id, benchmark_summary["timestamp"], benchmark_summary["total_runtime_sec"],
        pcap_size_bytes, total_flows, total_packets, throughput_mb_s,
        throughput_flows_s, peak_mem, alert_count
    ))
    conn.commit()
    conn.close()

    print(f"[+] Benchmark completed for Run ID: {run_id}")
    print(f"    - Runtime: {total_runtime_sec:.4f}s | Throughput: {throughput_mb_s} MB/s ({throughput_flows_s} flows/s)")
    print(f"    - Peak RSS Memory: {peak_mem:.2f} MB | Total Alerts: {alert_count}")

    return benchmark_summary


if __name__ == "__main__":
    summary = run_benchmark_pipeline()
    print(summary)

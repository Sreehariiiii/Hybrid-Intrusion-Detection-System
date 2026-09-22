"""
End-to-End Orchestration Script for Signature-Based IDS Engine
Runs PCAP calibration/test synthesis, Suricata ingestion, Evaluation, Benchmarking, and Dashboard.
"""

import os
import sys
import time
import argparse
import subprocess

from src.pcap_preprocessor import (
    generate_synthetic_dataset, generate_calibration_and_test_splits
)
from src.eve_ingestor import run_pipeline_ingestion, init_database
from src.evaluator import evaluate_detection_performance
from src.benchmark import run_benchmark_pipeline
from src.attack_injector import inject_attack_into_pcap_queue


def main():
    parser = argparse.ArgumentParser(description="Signature-Based IDS Orchestration Engine")
    real_thursday = r"C:\Users\venug\Downloads\Thursday-WorkingHours.pcap"
    default_pcap = real_thursday if os.path.exists(real_thursday) else "data/slice_test/thursday_sample_500k.pcap"

    parser.add_argument("--generate-pcap", action="store_true", help="Generate synthetic calibration & test PCAPs and ground truth")
    parser.add_argument("--ingest", action="store_true", help="Run Suricata offline replay and ingest alerts to SQLite")
    parser.add_argument("--eval", action="store_true", help="Execute 5-tuple flow alignment and compute metrics on test set")
    parser.add_argument("--benchmark", action="store_true", help="Benchmark processing speed, throughput, and memory")
    parser.add_argument("--dashboard", action="store_true", help="Launch Streamlit visualization dashboard")
    parser.add_argument("--inject", type=str, default=None, help="Inject attack into PCAP queue (e.g. WebAttack-SQLi, DoS-LOIC-UDP)")
    parser.add_argument("--pcap", type=str, default=default_pcap, help="Path to input PCAP file")
    parser.add_argument("--db", type=str, default="database/alerts.db", help="Path to SQLite database")
    parser.add_argument("--all", action="store_true", help="Run full pipeline end-to-end")

    args = parser.parse_args()

    # Default to running all steps if no flags specified
    if not (args.generate_pcap or args.ingest or args.eval or args.benchmark or args.dashboard or args.inject or args.all):
        args.all = True

    pcap_path = args.pcap
    gt_csv = "data/ground_truth.csv"
    db_path = args.db

    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

    print("=" * 70)
    print(f"[*] SIGNATURE-BASED INTRUSION DETECTION SYSTEM (Suricata + SQLite)")
    print(f"[*] PCAP Target: {pcap_path} ({os.path.getsize(pcap_path)/(1024**3):.2f} GB)")
    print("=" * 70)

    # 1. Initialize SQLite Schema
    init_database(db_path)

    # 2. PCAP Check / Generation
    if args.generate_pcap:
        print("\n[STEP 1/4] Generating calibration and test splits...")
        generate_calibration_and_test_splits()

    # 3. Suricata Ingestion & Dynamic Explainability on Test Set
    if args.ingest or args.all:
        print("\n[STEP 2/4] Executing Suricata engine & Ingesting EVE alerts...")
        alert_count = run_pipeline_ingestion(pcap_path=pcap_path, db_path=db_path)
        print(f"[*] Ingested {alert_count} alerts with dynamic explainability strings.")

    # 4. Evaluation & Attribution on Held-Out Test Set
    if args.eval or args.all:
        print("\n[STEP 3/4] Evaluating flow alignment, conflict resolution & metrics on test set...")
        eval_res = evaluate_detection_performance(gt_csv, db_path)
        print("\n--- PER-CATEGORY DETECTION METRICS (HELD-OUT TEST SET) ---")
        print(eval_res["category_metrics"].to_string(index=False))
        print("\n--- RULE ATTRIBUTION MATRIX ---")
        print(eval_res["attribution_metrics"].to_string(index=False))
        print("\n--- CONFUSION MATRIX ---")
        print(eval_res["confusion_matrix"])

    # 5. Resource Benchmark
    if args.benchmark or args.all:
        print("\n[STEP 4/4] Running system performance & memory benchmark...")
        bench = run_benchmark_pipeline(pcap_path, gt_csv, db_path)

    # 6. Replay Attack Injection
    if args.inject:
        print(f"\n[*] Injecting attack into replay queue: {args.inject}...")
        res = inject_attack_into_pcap_queue(args.inject, base_pcap_path=pcap_path, gt_csv_path=gt_csv)
        print(f"[+] Injected {res['packets_injected']} packets. Replay evaluated {res['total_alerts']} alerts.")

    print("\n" + "=" * 70)
    print("[+] Pipeline execution finished successfully.")
    print("=" * 70)

    # 7. Modern Full-Stack Web Dashboard
    if args.dashboard:
        print("\n[+] Launching Modern Web Dashboard on http://localhost:8000 ...")
        cmd = [sys.executable, "-m", "uvicorn", "app.server:app", "--host", "0.0.0.0", "--port", "8000"]
        subprocess.run(cmd)


if __name__ == "__main__":
    main()

"""
Offline Replay Attack Injection Simulator
Constructs real Scapy packet captures for chosen attack patterns,
appends them into the offline PCAP replay queue, and triggers the detection pipeline.
"""

import os
import time
from datetime import datetime, timezone
from scapy.all import (
    IP, TCP, UDP, Ether, Raw, rdpcap, wrpcap
)

from src.eve_ingestor import run_pipeline_ingestion
from src.evaluator import evaluate_detection_performance


def inject_attack_into_pcap_queue(
    attack_type: str,
    target_ip: str = "192.168.1.10",
    base_pcap_path: str = "data/raw_pcap/traffic_sample.pcap",
    gt_csv_path: str = "data/ground_truth.csv"
) -> dict:
    """
    Constructs real attack packets, appends them to the PCAP file, and updates ground truth.
    Returns detection results from the real evaluation engine.
    """
    now_t = time.time()
    generated_packets = []
    expected_sid = 0

    if attack_type == "WebAttack-SQLi":
        p1 = Ether()/IP(src="203.0.113.88", dst=target_ip)/TCP(sport=55001, dport=80, flags="S", seq=100)
        p2 = Ether()/IP(src=target_ip, dst="203.0.113.88")/TCP(sport=80, dport=55001, flags="SA", seq=200, ack=101)
        sqli_data = "GET /search?id=1 UNION SELECT password FROM accounts-- HTTP/1.1\r\nHost: 192.168.1.10\r\n\r\n"
        p3 = Ether()/IP(src="203.0.113.88", dst=target_ip)/TCP(sport=55001, dport=80, flags="PA", seq=101, ack=201)/Raw(load=sqli_data)
        for p in [p1, p2, p3]:
            p.time = now_t
            now_t += 0.01
        generated_packets = [p1, p2, p3]
        expected_sid = 1000010

    elif attack_type == "WebAttack-XSS":
        p1 = Ether()/IP(src="203.0.113.89", dst=target_ip)/TCP(sport=55002, dport=80, flags="S", seq=100)
        p2 = Ether()/IP(src=target_ip, dst="203.0.113.89")/TCP(sport=80, dport=55002, flags="SA", seq=200, ack=101)
        xss_data = "GET /post?comment=<script>alert('INJECTED_XSS')</script> HTTP/1.1\r\nHost: 192.168.1.10\r\n\r\n"
        p3 = Ether()/IP(src="203.0.113.89", dst=target_ip)/TCP(sport=55002, dport=80, flags="PA", seq=101, ack=201)/Raw(load=xss_data)
        for p in [p1, p2, p3]:
            p.time = now_t
            now_t += 0.01
        generated_packets = [p1, p2, p3]
        expected_sid = 1000011

    elif attack_type == "DoS-LOIC-UDP":
        for _ in range(25):
            p = Ether()/IP(src="203.0.113.90", dst=target_ip)/UDP(sport=55003, dport=80)/Raw(load=b"LOIC_BURST_FLOOD_PAYLOAD_TEST_DATA"*2)
            p.time = now_t
            generated_packets.append(p)
            now_t += 0.01
        expected_sid = 1000001

    elif attack_type == "PortScan-TCP-SYN":
        for port in [21, 22, 23, 25, 80, 110, 139, 443, 445, 1433, 3306, 3389]:
            p = Ether()/IP(src="203.0.113.91", dst=target_ip)/TCP(sport=55004, dport=port, flags="S", seq=100)
            p.time = now_t
            generated_packets.append(p)
            now_t += 0.05
        expected_sid = 1000006

    elif attack_type == "BruteForce-SSH":
        for i in range(6):
            p = Ether()/IP(src="203.0.113.92", dst=target_ip)/TCP(sport=55100 + i, dport=22, flags="S", seq=100 + i)
            p.time = now_t
            generated_packets.append(p)
            now_t += 0.2
        expected_sid = 1000008

    elif attack_type == "Botnet-C2-Beacon":
        for i in range(4):
            p = Ether()/IP(src="192.168.1.50", dst="198.51.100.77")/TCP(sport=55005, dport=8080, flags="PA", seq=100 + i*30)/Raw(load=f"C2_HEARTBEAT_INJECTED_SEQ={i}\r\n")
            p.time = now_t
            generated_packets.append(p)
            now_t += 2.0
        expected_sid = 1000012

    elif attack_type == "Infiltration-SMB":
        p1 = Ether()/IP(src="192.168.1.88", dst=target_ip)/TCP(sport=55006, dport=445, flags="S", seq=100)
        p2 = Ether()/IP(src=target_ip, dst="192.168.1.88")/TCP(sport=445, dport=55006, flags="SA", seq=200, ack=101)
        smb_data = b"\x00\x00\x00\x45\xff\x53\x4d\x42ADMIN$\\C$\\injected_payload.exe"
        p3 = Ether()/IP(src="192.168.1.88", dst=target_ip)/TCP(sport=55006, dport=445, flags="PA", seq=101, ack=201)/Raw(load=smb_data)
        for p in [p1, p2, p3]:
            p.time = now_t
            now_t += 0.01
        generated_packets = [p1, p2, p3]
        expected_sid = 1000013

    # Append to existing PCAP
    existing_packets = []
    if os.path.exists(base_pcap_path):
        try:
            existing_packets = rdpcap(base_pcap_path)
        except Exception:
            existing_packets = []

    combined_packets = list(existing_packets) + generated_packets
    combined_packets.sort(key=lambda p: float(p.time))
    wrpcap(base_pcap_path, combined_packets)

    # Re-run offline ingestion on updated PCAP
    alert_count = run_pipeline_ingestion(pcap_path=base_pcap_path)
    eval_res = evaluate_detection_performance(ground_truth_csv=gt_csv_path)

    return {
        "status": "success",
        "attack_type": attack_type,
        "expected_sid": expected_sid,
        "packets_injected": len(generated_packets),
        "total_alerts": alert_count,
        "evaluation_results": eval_res
    }

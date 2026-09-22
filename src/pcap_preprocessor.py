"""
Synthetic PCAP & Ground Truth Generator with Calibration & Held-Out Test Splits
Constructs realistic multi-protocol packet captures and aligned flow ground-truth labels
matching CIC-IDS2018 / UNSW-NB15 attack patterns.
"""

import os
import time
import csv
from datetime import datetime, timezone
from scapy.all import (
    IP, TCP, UDP, Ether, Raw, wrpcap
)

HOME_NET = "192.168.1.50"
SERVER_IP = "192.168.1.10"
EXTERNAL_ATTACKER = "203.0.113.15"
EXTERNAL_C2 = "198.51.100.77"
INTERNAL_PIVOT = "192.168.1.88"


def generate_synthetic_dataset(
    output_pcap: str = "data/raw_pcap/traffic_sample.pcap",
    output_csv: str = "data/ground_truth.csv",
    base_time: float = None,
    dataset_split: str = "test"
):
    """
    Generates realistic multi-protocol network traffic encompassing both
    benign traffic and the full spectrum of covered attacks + zero-day traffic.
    Supports distinct 'calibration' vs 'test' seeds.
    """
    if base_time is None:
        base_offset = 600.0 if dataset_split == "test" else 1200.0
        base_time = time.time() - base_offset

    os.makedirs(os.path.dirname(output_pcap), exist_ok=True)
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)

    packets = []
    ground_truth_records = []

    flow_counter = 0

    def add_flow_record(flow_id, src_ip, src_port, dest_ip, dest_port, proto, ts, duration, label, expected_sid):
        ground_truth_records.append({
            "flow_id": flow_id,
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "proto": proto.upper(),
            "timestamp": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
            "duration": round(duration, 4),
            "ground_truth_label": label,
            "expected_sid": expected_sid,
            "split": dataset_split
        })

    current_t = base_time

    # 1. BENIGN WEB TRAFFIC (Multiple flows)
    for i in range(5):
        flow_counter += 1
        fid = f"FLOW_{flow_counter:04d}"
        s_port = 49152 + i
        t_start = current_t
        
        # 3-way handshake
        p1 = Ether()/IP(src="192.168.1.100", dst=SERVER_IP)/TCP(sport=s_port, dport=80, flags="S", seq=1000)
        p1.time = current_t
        current_t += 0.005

        p2 = Ether()/IP(src=SERVER_IP, dst="192.168.1.100")/TCP(sport=80, dport=s_port, flags="SA", seq=2000, ack=1001)
        p2.time = current_t
        current_t += 0.005

        p3 = Ether()/IP(src="192.168.1.100", dst=SERVER_IP)/TCP(sport=s_port, dport=80, flags="A", seq=1001, ack=2001)
        p3.time = current_t
        current_t += 0.01

        # HTTP Request
        http_req = "GET /index.html HTTP/1.1\r\nHost: 192.168.1.10\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n"
        p4 = Ether()/IP(src="192.168.1.100", dst=SERVER_IP)/TCP(sport=s_port, dport=80, flags="PA", seq=1001, ack=2001)/Raw(load=http_req)
        p4.time = current_t
        current_t += 0.02

        # HTTP Response
        http_resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 45\r\n\r\n<html><body>Welcome to Web Server</body></html>"
        p5 = Ether()/IP(src=SERVER_IP, dst="192.168.1.100")/TCP(sport=80, dport=s_port, flags="PA", seq=2001, ack=1001 + len(http_req))/Raw(load=http_resp)
        p5.time = current_t
        current_t += 0.01

        # Teardown
        p6 = Ether()/IP(src="192.168.1.100", dst=SERVER_IP)/TCP(sport=s_port, dport=80, flags="FA", seq=1001 + len(http_req), ack=2001 + len(http_resp))
        p6.time = current_t
        current_t += 0.005

        packets.extend([p1, p2, p3, p4, p5, p6])
        add_flow_record(fid, "192.168.1.100", s_port, SERVER_IP, 80, "TCP", t_start, current_t - t_start, "Benign", 0)
        current_t += 0.5

    # 2. BENIGN DNS / UDP TRAFFIC
    for i in range(3):
        flow_counter += 1
        fid = f"FLOW_{flow_counter:04d}"
        s_port = 53000 + i
        t_start = current_t
        p_dns1 = Ether()/IP(src="192.168.1.101", dst="192.168.1.1")/UDP(sport=s_port, dport=53)/Raw(load=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")
        p_dns1.time = current_t
        current_t += 0.02
        p_dns2 = Ether()/IP(src="192.168.1.1", dst="192.168.1.101")/UDP(sport=53, dport=s_port)/Raw(load=b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x5d\xb8\xd8\x22")
        p_dns2.time = current_t
        packets.extend([p_dns1, p_dns2])
        add_flow_record(fid, "192.168.1.101", s_port, "192.168.1.1", 53, "UDP", t_start, current_t - t_start, "Benign", 0)
        current_t += 0.2

    # 3. DoS-LOIC-UDP (SID 1000001) - 30 rapid UDP packets within 0.5s
    flow_counter += 1
    fid = f"FLOW_{flow_counter:04d}"
    t_start = current_t
    s_port = 60001
    atk_ip = "203.0.113.11"
    for _ in range(30):
        p = Ether()/IP(src=atk_ip, dst=SERVER_IP)/UDP(sport=s_port, dport=80)/Raw(load=b"LOIC_UDP_FLOOD_BURST_DATA_PAYLOAD_X"*2)
        p.time = current_t
        packets.append(p)
        current_t += 0.015
    add_flow_record(fid, atk_ip, s_port, SERVER_IP, 80, "UDP", t_start, current_t - t_start, "DoS-LOIC-UDP", 1000001)
    current_t += 1.0

    # 4. DoS-LOIC-TCP (SID 1000002) - 35 TCP SYN packets within 0.7s
    flow_counter += 1
    fid = f"FLOW_{flow_counter:04d}"
    t_start = current_t
    s_port = 60002
    atk_ip = "203.0.113.12"
    for seq_num in range(35):
        p = Ether()/IP(src=atk_ip, dst=SERVER_IP)/TCP(sport=s_port, dport=80, flags="S", seq=50000 + seq_num)
        p.time = current_t
        packets.append(p)
        current_t += 0.018
    add_flow_record(fid, atk_ip, s_port, SERVER_IP, 80, "TCP", t_start, current_t - t_start, "DoS-LOIC-TCP", 1000002)
    current_t += 1.0

    # 5. DoS-Slowloris (SID 1000003) - Periodic partial headers with "X-a: "
    flow_counter += 1
    fid = f"FLOW_{flow_counter:04d}"
    t_start = current_t
    s_port = 60003
    atk_ip = "203.0.113.13"
    p_syn = Ether()/IP(src=atk_ip, dst=SERVER_IP)/TCP(sport=s_port, dport=80, flags="S", seq=100)
    p_syn.time = current_t
    p_sa = Ether()/IP(src=SERVER_IP, dst=atk_ip)/TCP(sport=80, dport=s_port, flags="SA", seq=200, ack=101)
    p_sa.time = current_t + 0.005
    p_ack = Ether()/IP(src=atk_ip, dst=SERVER_IP)/TCP(sport=s_port, dport=80, flags="A", seq=101, ack=201)
    p_ack.time = current_t + 0.01
    packets.extend([p_syn, p_sa, p_ack])
    current_t += 0.02

    slow_headers = ["GET /default.aspx HTTP/1.1\r\nHost: 192.168.1.10\r\nUser-Agent: Mozilla/5.0\r\n",
                    "X-a: 1\r\n", "X-a: 2\r\n", "X-a: 3\r\n", "X-a: 4\r\n", "X-a: 5\r\n", "X-a: 6\r\n"]
    seq_acc = 101
    for h in slow_headers:
        p_hdr = Ether()/IP(src=atk_ip, dst=SERVER_IP)/TCP(sport=s_port, dport=80, flags="PA", seq=seq_acc, ack=201)/Raw(load=h)
        p_hdr.time = current_t
        packets.append(p_hdr)
        seq_acc += len(h)
        current_t += 1.2
    add_flow_record(fid, atk_ip, s_port, SERVER_IP, 80, "TCP", t_start, current_t - t_start, "DoS-Slowloris", 1000003)
    current_t += 1.0

    # 6. DoS-SlowHTTPTest (SID 1000004) - Content-Length with application/x-www-form-urlencoded
    flow_counter += 1
    fid = f"FLOW_{flow_counter:04d}"
    t_start = current_t
    s_port = 60004
    atk_ip = "203.0.113.14"
    p_syn = Ether()/IP(src=atk_ip, dst=SERVER_IP)/TCP(sport=s_port, dport=80, flags="S", seq=300)
    p_syn.time = current_t
    p_sa = Ether()/IP(src=SERVER_IP, dst=atk_ip)/TCP(sport=80, dport=s_port, flags="SA", seq=400, ack=301)
    p_sa.time = current_t + 0.005
    p_ack = Ether()/IP(src=atk_ip, dst=SERVER_IP)/TCP(sport=s_port, dport=80, flags="A", seq=301, ack=401)
    p_ack.time = current_t + 0.01
    packets.extend([p_syn, p_sa, p_ack])
    current_t += 0.02

    slow_post_hdrs = [
        "POST /login HTTP/1.1\r\nHost: 192.168.1.10\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 10000\r\n\r\n",
        "a", "b", "c", "d", "e", "f", "g", "h", "i"
    ]
    seq_acc = 301
    for item in slow_post_hdrs:
        p_item = Ether()/IP(src=atk_ip, dst=SERVER_IP)/TCP(sport=s_port, dport=80, flags="PA", seq=seq_acc, ack=401)/Raw(load=item)
        p_item.time = current_t
        packets.append(p_item)
        seq_acc += len(item)
        current_t += 0.9
    add_flow_record(fid, atk_ip, s_port, SERVER_IP, 80, "TCP", t_start, current_t - t_start, "DoS-SlowHTTPTest", 1000004)
    current_t += 1.0

    # 7. DoS-Hulk-GoldenEye (SID 1000005) - 20 rapid GET requests with Cache-Control: no-cache
    flow_counter += 1
    fid = f"FLOW_{flow_counter:04d}"
    t_start = current_t
    s_port = 60005
    atk_ip = "203.0.113.15"
    p_syn = Ether()/IP(src=atk_ip, dst=SERVER_IP)/TCP(sport=s_port, dport=80, flags="S", seq=500)
    p_syn.time = current_t
    p_sa = Ether()/IP(src=SERVER_IP, dst=atk_ip)/TCP(sport=80, dport=s_port, flags="SA", seq=600, ack=501)
    p_sa.time = current_t + 0.005
    p_ack = Ether()/IP(src=atk_ip, dst=SERVER_IP)/TCP(sport=s_port, dport=80, flags="A", seq=501, ack=601)
    p_ack.time = current_t + 0.01
    packets.extend([p_syn, p_sa, p_ack])
    current_t += 0.02

    seq_acc = 501
    for req_idx in range(18):
        hulk_req = f"GET /search?q=test_{req_idx} HTTP/1.1\r\nHost: 192.168.1.10\r\nCache-Control: no-cache\r\n\r\n"
        p_hulk = Ether()/IP(src=atk_ip, dst=SERVER_IP)/TCP(sport=s_port, dport=80, flags="PA", seq=seq_acc, ack=601)/Raw(load=hulk_req)
        p_hulk.time = current_t
        packets.append(p_hulk)
        seq_acc += len(hulk_req)
        current_t += 0.06
    add_flow_record(fid, atk_ip, s_port, SERVER_IP, 80, "TCP", t_start, current_t - t_start, "DoS-Hulk-GoldenEye", 1000005)
    current_t += 1.0

    # 8. PortScan-TCP-SYN (SID 1000006) - 15 SYN probes to multiple ports
    flow_counter += 1
    fid = f"FLOW_{flow_counter:04d}"
    t_start = current_t
    s_port = 60006
    atk_ip = "203.0.113.16"
    for target_port in [21, 22, 23, 25, 80, 110, 139, 143, 443, 445, 1433, 3306, 3389, 8080, 8443]:
        p_scan = Ether()/IP(src=atk_ip, dst=SERVER_IP)/TCP(sport=s_port, dport=target_port, flags="S", seq=1000 + target_port)
        p_scan.time = current_t
        packets.append(p_scan)
        current_t += 0.08
    add_flow_record(fid, atk_ip, s_port, SERVER_IP, 80, "TCP", t_start, current_t - t_start, "PortScan-TCP-SYN", 1000006)
    current_t += 1.0

    # 9. PortScan-Connect (SID 1000007) - Rapid ACK sweeps with empty payload
    flow_counter += 1
    fid = f"FLOW_{flow_counter:04d}"
    t_start = current_t
    s_port = 60007
    atk_ip = "203.0.113.17"
    for target_port in range(100, 120):
        p_ack_scan = Ether()/IP(src=atk_ip, dst=SERVER_IP)/TCP(sport=s_port, dport=target_port, flags="A", seq=2000, ack=3000)
        p_ack_scan.time = current_t
        packets.append(p_ack_scan)
        current_t += 0.07
    add_flow_record(fid, atk_ip, s_port, SERVER_IP, 100, "TCP", t_start, current_t - t_start, "PortScan-Connect", 1000007)
    current_t += 1.0

    # 10. BruteForce-SSH-Patator (SID 1000008) - Pure Volumetric Connection Attempts (Port 22 SYN Bursts)
    flow_counter += 1
    fid = f"FLOW_{flow_counter:04d}"
    t_start = current_t
    s_port = 60008
    atk_ip = "203.0.113.18"
    for attempt in range(8):
        p_syn = Ether()/IP(src=atk_ip, dst=SERVER_IP)/TCP(sport=s_port, dport=22, flags="S", seq=attempt*100)
        p_syn.time = current_t
        p_sa = Ether()/IP(src=SERVER_IP, dst=atk_ip)/TCP(sport=22, dport=s_port, flags="SA", seq=attempt*200, ack=attempt*100+1)
        p_sa.time = current_t + 0.002
        packets.extend([p_syn, p_sa])
        current_t += 0.25
    add_flow_record(fid, atk_ip, s_port, SERVER_IP, 22, "TCP", t_start, current_t - t_start, "BruteForce-SSH-Patator", 1000008)
    current_t += 1.0

    # 11. BruteForce-FTP-Patator (SID 1000009) - High-rate cleartext USER/PASS commands on port 21
    flow_counter += 1
    fid = f"FLOW_{flow_counter:04d}"
    t_start = current_t
    s_port = 60009
    atk_ip = "203.0.113.19"
    p_syn = Ether()/IP(src=atk_ip, dst=SERVER_IP)/TCP(sport=s_port, dport=21, flags="S", seq=700)
    p_syn.time = current_t
    p_sa = Ether()/IP(src=SERVER_IP, dst=atk_ip)/TCP(sport=21, dport=s_port, flags="SA", seq=800, ack=701)
    p_sa.time = current_t + 0.002
    packets.extend([p_syn, p_sa])
    current_t += 0.01

    seq_acc = 701
    for user_idx in range(7):
        ftp_cmd = f"USER admin_{user_idx}\r\n"
        p_user = Ether()/IP(src=atk_ip, dst=SERVER_IP)/TCP(sport=s_port, dport=21, flags="PA", seq=seq_acc, ack=801)/Raw(load=ftp_cmd)
        p_user.time = current_t
        packets.append(p_user)
        seq_acc += len(ftp_cmd)
        current_t += 0.4
    add_flow_record(fid, atk_ip, s_port, SERVER_IP, 21, "TCP", t_start, current_t - t_start, "BruteForce-FTP-Patator", 1000009)
    current_t += 1.0

    # 12. WebAttack-SQLi (SID 1000010) - SQL Injection payload
    flow_counter += 1
    fid = f"FLOW_{flow_counter:04d}"
    t_start = current_t
    s_port = 60010
    atk_ip = "203.0.113.20"
    p_syn = Ether()/IP(src=atk_ip, dst=SERVER_IP)/TCP(sport=s_port, dport=80, flags="S", seq=900)
    p_syn.time = current_t
    p_sa = Ether()/IP(src=SERVER_IP, dst=atk_ip)/TCP(sport=80, dport=s_port, flags="SA", seq=1000, ack=901)
    p_sa.time = current_t + 0.002
    p_ack = Ether()/IP(src=atk_ip, dst=SERVER_IP)/TCP(sport=s_port, dport=80, flags="A", seq=901, ack=1001)
    p_ack.time = current_t + 0.005
    sqli_payload = "GET /products.php?id=1 UNION SELECT 1,username,password FROM users-- HTTP/1.1\r\nHost: 192.168.1.10\r\n\r\n"
    p_sqli = Ether()/IP(src=atk_ip, dst=SERVER_IP)/TCP(sport=s_port, dport=80, flags="PA", seq=901, ack=1001)/Raw(load=sqli_payload)
    p_sqli.time = current_t + 0.01
    packets.extend([p_syn, p_sa, p_ack, p_sqli])
    current_t += 0.05
    add_flow_record(fid, atk_ip, s_port, SERVER_IP, 80, "TCP", t_start, current_t - t_start, "WebAttack-SQLi", 1000010)
    current_t += 1.0

    # 13. WebAttack-XSS (SID 1000011) - XSS payload
    flow_counter += 1
    fid = f"FLOW_{flow_counter:04d}"
    t_start = current_t
    s_port = 60011
    atk_ip = "203.0.113.21"
    p_syn = Ether()/IP(src=atk_ip, dst=SERVER_IP)/TCP(sport=s_port, dport=80, flags="S", seq=1100)
    p_syn.time = current_t
    p_sa = Ether()/IP(src=SERVER_IP, dst=atk_ip)/TCP(sport=80, dport=s_port, flags="SA", seq=1200, ack=1101)
    p_sa.time = current_t + 0.002
    p_ack = Ether()/IP(src=atk_ip, dst=SERVER_IP)/TCP(sport=s_port, dport=80, flags="A", seq=1101, ack=1201)
    p_ack.time = current_t + 0.005
    xss_payload = "GET /comment.php?name=<script>alert('IDS_XSS_DETECTED')</script> HTTP/1.1\r\nHost: 192.168.1.10\r\n\r\n"
    p_xss = Ether()/IP(src=atk_ip, dst=SERVER_IP)/TCP(sport=s_port, dport=80, flags="PA", seq=1101, ack=1201)/Raw(load=xss_payload)
    p_xss.time = current_t + 0.01
    packets.extend([p_syn, p_sa, p_ack, p_xss])
    current_t += 0.05
    add_flow_record(fid, atk_ip, s_port, SERVER_IP, 80, "TCP", t_start, current_t - t_start, "WebAttack-XSS", 1000011)
    current_t += 1.0

    # 14. Botnet-C2-Beaconing (SID 1000012) - Periodic heartbeat beacons to external C2
    flow_counter += 1
    fid = f"FLOW_{flow_counter:04d}"
    t_start = current_t
    s_port = 60012
    p_syn = Ether()/IP(src=HOME_NET, dst=EXTERNAL_C2)/TCP(sport=s_port, dport=8080, flags="S", seq=1300)
    p_syn.time = current_t
    p_sa = Ether()/IP(src=EXTERNAL_C2, dst=HOME_NET)/TCP(sport=8080, dport=s_port, flags="SA", seq=1400, ack=1301)
    p_sa.time = current_t + 0.005
    p_ack = Ether()/IP(src=HOME_NET, dst=EXTERNAL_C2)/TCP(sport=s_port, dport=8080, flags="A", seq=1301, ack=1401)
    p_ack.time = current_t + 0.008
    packets.extend([p_syn, p_sa, p_ack])
    current_t += 0.01

    seq_acc = 1301
    for beat_idx in range(4):
        c2_msg = f"C2_HEARTBEAT_SEQ={beat_idx}_NODE=VICTIM_01\r\n"
        p_beat = Ether()/IP(src=HOME_NET, dst=EXTERNAL_C2)/TCP(sport=s_port, dport=8080, flags="PA", seq=seq_acc, ack=1401)/Raw(load=c2_msg)
        p_beat.time = current_t
        packets.append(p_beat)
        seq_acc += len(c2_msg)
        current_t += 4.0
    add_flow_record(fid, HOME_NET, s_port, EXTERNAL_C2, 8080, "TCP", t_start, current_t - t_start, "Botnet-C2-Beaconing", 1000012)
    current_t += 1.0

    # 15. Infiltration-LateralSweep (SID 1000013) - Internal SMB lateral movement sweep
    flow_counter += 1
    fid = f"FLOW_{flow_counter:04d}"
    t_start = current_t
    s_port = 60013
    p_syn = Ether()/IP(src=INTERNAL_PIVOT, dst=SERVER_IP)/TCP(sport=s_port, dport=445, flags="S", seq=1500)
    p_syn.time = current_t
    p_sa = Ether()/IP(src=SERVER_IP, dst=INTERNAL_PIVOT)/TCP(sport=445, dport=s_port, flags="SA", seq=1600, ack=1501)
    p_sa.time = current_t + 0.005
    p_ack = Ether()/IP(src=INTERNAL_PIVOT, dst=SERVER_IP)/TCP(sport=s_port, dport=445, flags="A", seq=1501, ack=1601)
    p_ack.time = current_t + 0.008
    smb_payload = b"\x00\x00\x00\x45\xff\x53\x4d\x42\x75\x00\x00\x00\x00\x18\x07\xc8ADMIN$\\C$\\svc_exec.exe"
    p_smb = Ether()/IP(src=INTERNAL_PIVOT, dst=SERVER_IP)/TCP(sport=s_port, dport=445, flags="PA", seq=1501, ack=1601)/Raw(load=smb_payload)
    p_smb.time = current_t + 0.02
    packets.extend([p_syn, p_sa, p_ack, p_smb])
    current_t += 0.05
    add_flow_record(fid, INTERNAL_PIVOT, s_port, SERVER_IP, 445, "TCP", t_start, current_t - t_start, "Infiltration-LateralSweep", 1000013)
    current_t += 1.0

    # 16. ZeroDay-Unknown-Exploit (Explicitly Uncovered Zero-Day Baseline)
    flow_counter += 1
    fid = f"FLOW_{flow_counter:04d}"
    t_start = current_t
    s_port = 60014
    p_syn = Ether()/IP(src="198.51.100.99", dst=SERVER_IP)/TCP(sport=s_port, dport=80, flags="S", seq=1700)
    p_syn.time = current_t
    p_sa = Ether()/IP(src=SERVER_IP, dst="198.51.100.99")/TCP(sport=80, dport=s_port, flags="SA", seq=1800, ack=1701)
    p_sa.time = current_t + 0.005
    p_ack = Ether()/IP(src="198.51.100.99", dst=SERVER_IP)/TCP(sport=s_port, dport=80, flags="A", seq=1701, ack=1801)
    p_ack.time = current_t + 0.008
    novel_payload = "POST /api/v2/opaque_poly_eval HTTP/1.1\r\nHost: 192.168.1.10\r\n\r\n\xde\xad\xbe\xef\xca\xfe\xba\xbe"
    p_novel = Ether()/IP(src="198.51.100.99", dst=SERVER_IP)/TCP(sport=s_port, dport=80, flags="PA", seq=1701, ack=1801)/Raw(load=novel_payload)
    p_novel.time = current_t + 0.02
    packets.extend([p_syn, p_sa, p_ack, p_novel])
    current_t += 0.05
    add_flow_record(fid, "198.51.100.99", s_port, SERVER_IP, 80, "TCP", t_start, current_t - t_start, "ZeroDay-Unknown-Exploit", 0)

    # Sort all packets by timestamp
    packets.sort(key=lambda p: float(p.time))

    # Write PCAP file
    wrpcap(output_pcap, packets)

    # Write Ground Truth CSV
    fieldnames = ["flow_id", "src_ip", "src_port", "dest_ip", "dest_port", "proto", "timestamp", "duration", "ground_truth_label", "expected_sid", "split"]
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(ground_truth_records)

    print(f"[+] PCAP generated [{dataset_split} split]: {output_pcap} ({len(packets)} packets)")
    print(f"[+] Ground-truth generated [{dataset_split} split]: {output_csv} ({len(ground_truth_records)} flows)")
    return output_pcap, output_csv


def generate_calibration_and_test_splits():
    """Generates independent calibration and held-out test splits."""
    generate_synthetic_dataset(
        output_pcap="data/calibration/calibration.pcap",
        output_csv="data/calibration/ground_truth.csv",
        dataset_split="calibration"
    )
    generate_synthetic_dataset(
        output_pcap="data/raw_pcap/traffic_sample.pcap",
        output_csv="data/ground_truth.csv",
        dataset_split="test"
    )


if __name__ == "__main__":
    generate_calibration_and_test_splits()

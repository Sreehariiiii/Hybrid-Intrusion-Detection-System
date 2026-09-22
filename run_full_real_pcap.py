import os
import sys
import time
import json
import sqlite3
import threading
import psutil
import subprocess
from datetime import datetime

PCAP_PATH = r'C:\Users\venug\Downloads\Thursday-WorkingHours.pcap'
DB_PATH = 'database/alerts.db'
CONFIG_PATH = 'config/suricata.yaml'
RULES_PATH = 'config/custom_rules.rules'
LOG_DIR = 'logs'
EVE_PATH = os.path.join(LOG_DIR, 'eve.json')

stop_monitoring = False

from src.eve_ingestor import generate_dynamic_reason, init_database
from src.alert_notifier import AlertNotificationDispatcher

def resource_monitor_thread(log_file='logs/resource_usage.log'):
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    with open(log_file, 'w', encoding='utf-8') as f:
        f.write('Timestamp,CPU_Percent,RAM_Used_MB,RAM_Percent,Docker_RAM_MB\n')
        while not stop_monitoring:
            cpu = psutil.cpu_percent(interval=1.0)
            ram = psutil.virtual_memory()
            ram_used_mb = ram.used / (1024 * 1024)
            ram_percent = ram.percent
            
            docker_ram = 0.0
            for proc in psutil.process_iter(['name', 'memory_info']):
                try:
                    pname = (proc.info.get('name') or '').lower()
                    if 'docker' in pname or 'vmmem' in pname:
                        docker_ram += proc.info['memory_info'].rss / (1024 * 1024)
                except Exception:
                    pass
            
            ts = datetime.utcnow().isoformat()
            f.write(f'{ts},{cpu},{ram_used_mb:.2f},{ram_percent:.1f},{docker_ram:.2f}\n')
            f.flush()
            time.sleep(2.0)

def live_eve_tailer(eve_path, db_path):
    init_database(db_path)
    notifier = AlertNotificationDispatcher()
    
    while not os.path.exists(eve_path) and not stop_monitoring:
        time.sleep(0.5)
        
    print('[*] Live EVE tailer active: streaming alerts to SQLite & dashboard in real time...')
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM alerts')
    conn.commit()
    
    batch = []
    total_streamed = 0
    
    with open(eve_path, 'r', encoding='utf-8', errors='ignore') as f:
        while not stop_monitoring:
            line = f.readline()
            if not line:
                if batch:
                    cursor.executemany('INSERT INTO alerts (timestamp, src_ip, src_port, dest_ip, dest_port, proto, signature_id, signature, category, severity, bytes_toserver, pkts_toserver, bytes_toclient, pkts_toclient, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', batch)
                    conn.commit()
                    total_streamed += len(batch)
                    batch.clear()
                time.sleep(0.3)
                continue
                
            line = line.strip()
            if not line:
                continue
                
            try:
                event = json.loads(line)
            except Exception:
                continue
                
            if event.get('event_type') != 'alert':
                continue
                
            ts = event.get('timestamp', datetime.utcnow().isoformat())
            src_ip = event.get('src_ip', '0.0.0.0')
            src_port = int(event.get('src_port', 0))
            dest_ip = event.get('dest_ip', '0.0.0.0')
            dest_port = int(event.get('dest_port', 0))
            proto = event.get('proto', 'TCP').upper()

            alert_obj = event.get('alert', {})
            sig_id = int(alert_obj.get('signature_id', 0))
            sig_name = alert_obj.get('signature', 'Unknown Signature')
            category = alert_obj.get('category', 'General Security Event')
            severity = int(alert_obj.get('severity', 3))

            flow_obj = event.get('flow', {})
            bytes_toserver = int(flow_obj.get('bytes_toserver', 0))
            pkts_toserver = int(flow_obj.get('pkts_toserver', 1))
            bytes_toclient = int(flow_obj.get('bytes_toclient', 0))
            pkts_toclient = int(flow_obj.get('pkts_toclient', 0))

            reason = generate_dynamic_reason(
                sig_name=sig_name,
                sid=sig_id,
                src_ip=src_ip,
                src_port=src_port,
                dest_ip=dest_ip,
                dest_port=dest_port,
                proto=proto,
                category=category,
                pkts=pkts_toserver,
                bytes_count=bytes_toserver
            )

            batch.append((
                ts, src_ip, src_port, dest_ip, dest_port, proto,
                sig_id, sig_name, category, severity,
                bytes_toserver, pkts_toserver, bytes_toclient, pkts_toclient,
                reason
            ))

            if len(batch) >= 100:
                cursor.executemany('INSERT INTO alerts (timestamp, src_ip, src_port, dest_ip, dest_port, proto, signature_id, signature, category, severity, bytes_toserver, pkts_toserver, bytes_toclient, pkts_toclient, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', batch)
                conn.commit()
                total_streamed += len(batch)
                batch.clear()

            if severity == 1 and total_streamed < 500:
                notifier.dispatch({
                    'severity': severity,
                    'signature_id': sig_id,
                    'signature': sig_name,
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dest_ip': dest_ip,
                    'dest_port': dest_port,
                    'proto': proto,
                    'timestamp': ts,
                    'reason': reason
                })

        if batch:
            cursor.executemany('INSERT INTO alerts (timestamp, src_ip, src_port, dest_ip, dest_port, proto, signature_id, signature, category, severity, bytes_toserver, pkts_toserver, bytes_toclient, pkts_toclient, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', batch)
            conn.commit()
            total_streamed += len(batch)
            batch.clear()

    conn.close()
    print(f'[+] Live tailer finished: {total_streamed} alerts committed to SQLite.')

def main():
    global stop_monitoring
    print('=' * 70)
    print(f'[*] STARTING LIVE REAL-TIME STREAMING INGESTION: {PCAP_PATH}')
    print(f'[*] File Size: {os.path.getsize(PCAP_PATH) / (1024**3):.2f} GB')
    print('=' * 70)

    os.makedirs(LOG_DIR, exist_ok=True)
    if os.path.exists(EVE_PATH):
        try:
            os.remove(EVE_PATH)
        except Exception:
            pass

    mon_t = threading.Thread(target=resource_monitor_thread, daemon=True)
    mon_t.start()

    tail_t = threading.Thread(target=live_eve_tailer, args=(EVE_PATH, DB_PATH), daemon=True)
    tail_t.start()

    start_time = time.time()
    
    from src.eve_ingestor import run_suricata_offline
    try:
        run_suricata_offline(
            pcap_path=PCAP_PATH,
            config_path=CONFIG_PATH,
            rules_path=RULES_PATH,
            log_dir=LOG_DIR
        )
        time.sleep(2.0)
    except Exception as e:
        print(f'[!] Suricata encountered an error: {e}')
    finally:
        stop_monitoring = True
        tail_t.join(timeout=10)
        mon_t.join(timeout=3)
        
    elapsed = time.time() - start_time
    print('\n' + '=' * 70)
    print(f'[+] FULL REAL DATASET EXECUTION COMPLETE in {elapsed:.2f}s ({elapsed/60:.2f} mins)')
    print('=' * 70)

    conn = sqlite3.connect(DB_PATH)
    import pandas as pd
    df = pd.read_sql_query('SELECT signature_id, signature, severity, count(*) as alert_count FROM alerts GROUP BY signature_id, signature, severity ORDER BY alert_count DESC', conn)
    print('\n--- FINAL DETECTED ATTACK SIGNATURE DISTRIBUTION ---')
    print(df.to_string(index=False))
    conn.close()

if __name__ == '__main__':
    main()

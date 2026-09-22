-- SQLite DDL Schema for Signature-Based IDS Engine

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dest_ip TEXT NOT NULL,
    dest_port INTEGER NOT NULL,
    proto TEXT NOT NULL,
    signature_id INTEGER NOT NULL,
    signature TEXT NOT NULL,
    category TEXT,
    severity INTEGER NOT NULL,
    bytes_toserver INTEGER DEFAULT 0,
    pkts_toserver INTEGER DEFAULT 0,
    bytes_toclient INTEGER DEFAULT 0,
    pkts_toclient INTEGER DEFAULT 0,
    reason TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alerts_5tuple ON alerts(src_ip, src_port, dest_ip, dest_port, proto);
CREATE INDEX IF NOT EXISTS idx_alerts_sid ON alerts(signature_id);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);

CREATE TABLE IF NOT EXISTS evaluation_flows (
    flow_id TEXT PRIMARY KEY,
    src_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dest_ip TEXT NOT NULL,
    dest_port INTEGER NOT NULL,
    proto TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    duration REAL DEFAULT 0.0,
    ground_truth_label TEXT NOT NULL,
    expected_sid INTEGER,
    detected_sid INTEGER,
    detected_signature TEXT,
    match_status TEXT NOT NULL, -- 'TP', 'FP', 'TN', 'FN'
    overlapping_sids TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_eval_status ON evaluation_flows(match_status);
CREATE INDEX IF NOT EXISTS idx_eval_label ON evaluation_flows(ground_truth_label);
CREATE INDEX IF NOT EXISTS idx_eval_detected_sid ON evaluation_flows(detected_sid);

CREATE TABLE IF NOT EXISTS benchmark_metrics (
    run_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    total_runtime_sec REAL NOT NULL,
    pcap_size_bytes INTEGER NOT NULL,
    total_flows INTEGER NOT NULL,
    total_packets INTEGER NOT NULL,
    throughput_mb_s REAL NOT NULL,
    throughput_flows_s REAL NOT NULL,
    peak_memory_rss_mb REAL NOT NULL,
    total_alerts INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

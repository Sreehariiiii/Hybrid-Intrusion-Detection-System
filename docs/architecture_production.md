# Architecture & Production Scaling Considerations

## Prototype Scope (Current Implementation)
The current implementation utilizes **SQLite** (`database/alerts.db`) for alert persistence, flow alignment records, and benchmark metrics. SQLite was selected for this stage because it is self-contained, serverless, zero-configuration, and offers high read/write performance for single-node evaluation benchmarks.

## Production-Scale Transition Roadmap
When deploying this signature-based IDS in high-throughput enterprise networks (10Gbps+ wire speed), the following architectural components replace the prototype layer:

1. **Storage & Analytics Layer**:
   - **PostgreSQL / TimescaleDB**: Replaces SQLite for structured telemetry, supporting partitioned time-series tables, connection pooling (PgBouncer), and multi-terabyte query indexing.
   - **Elasticsearch / OpenSearch (ELK Stack)**: Ingests raw `eve.json` log streams via Filebeat/Logstash for distributed full-text search, SIEM dashboards (Kibana), and sub-second log queries.
2. **Log Retention & Rotation Policy**:
   - **Hot-Warm-Cold Tiering**: Retain raw packet telemetry on NVMe storage for 7 days (Hot), compress and move alerts to block storage for 90 days (Warm), and archive aggregated flow metadata to S3/Glacier for 365 days (Cold).
   - **Logrotate**: Truncate and compress `logs/eve.json` hourly with maximum size limits (`maxsize 500M`) to prevent disk exhaustion.
3. **Capture & Acceleration Layer**:
   - Enable **AF_PACKET** with fanout or **DPDK (Data Plane Development Kit)** for kernel-bypass packet capture at multi-gigabit line rates.
   - Deploy Suricata across dedicated worker threads pinning CPU cores to prevent packet drops.

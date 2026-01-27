# Technical Improvement Roadmap & Solutions

> **Engineering Strategy**: This document outlines the specific technical path to resolve Sentinel NetLab's architectural limitations, moving from a Prototype to a Production-Grade System.

---

## 🗺️ Roadmap Overview

| Critical Issue | Short-Term Optimization (Immediate) | Mid/Long-Term Re-Architecture (v2.0+) | Target Technologies |
| :--- | :--- | :--- | :--- |
| **1. I/O Bottlenecks & Latency** | • **Optimize Data Flow**: Switch to `jsonlines` for stream processing.<br>• **Buffer**: Increase pipe buffer size.<br>• **Memory Safety**: Use fixed-size `multiprocessing.Queue` to prevent OOM. | **Core Rewrite**: Rewrite the capture/analysis engine in a high-performance, memory-safe language to eliminate Python GIL overhead. | **Rust** (`libpnet`)<br>**Go** (`gopacket`) |
| **2. Storage Scalability** | • **Partitioning**: Rotate DB files daily.<br>• **Caching**: Keep recent raw data in RAM, flush only aggregates to disk. | **Decoupled Storage**: <br>• **Time-Series**: Store metrics in specialized TSDB.<br>• **Events**: Store alerts in Search Engine. | **TimescaleDB** (Metrics)<br>**Elasticsearch** (Logs)<br>**InfluxDB** |
| **3. Single Point of Failure (SPOF)** | • **Resilience**: Systemd service with auto-restart policy.<br>• **Monitoring**: Add `/health` endpoint for liveness probes. | **Decentralized Architecture**: Introduce a Message Queue (Broker) between Sensor and Controller. Sensor buffers data if Controller is down. | **NATS JetStream**<br>**Redis Streams**<br>**Apache Kafka** |
| **4. Passive Detection Limits** | • **Heuristics**: Add rules for high-frequency client probing and abnormal beacon rates. | **UEBA & ML Integration**:<br>• **Phase 1**: Statistical Baselinine.<br>• **Phase 2**: Unsupervised Learning for Zero-Day anomaly detection. | **Isolation Forest**<br>**Autoencoders**<br>**Scikit-learn / PyTorch** |

---

## 🛠️ Implementation Details

### 1. High-Performance Core (The "Rust" Migration)
*Current Problem*: Python's Global Interpreter Lock (GIL) limits concurrency during heavy packet capture.
*Solution*: Move the `CaptureEngine` to a binary service.
- **Rust Service**: Captures packets -> Normalizes to Struct -> Pushes to Redis.
- **Python Service**: Reads Redis -> Business Logic -> API.

### 2. Time-Series Data Model
*Current Problem*: SQLite locks interface during write, blocking reads.
*Solution*:
```sql
-- TimescaleDB Hypertable
CREATE TABLE sensor_readings (
    time        TIMESTAMPTZ       NOT NULL,
    sensor_id   TEXT              NOT NULL,
    signal      DOUBLE PRECISION  NULL,
    risk_score  DOUBLE PRECISION  NULL
);
SELECT create_hypertable('sensor_readings', 'time');
```

### 3. ML-Driven Anomaly Detection (UEBA)
*Current Problem*: Static rules miss "Low and Slow" attacks.
*Solution Workflow*:
1.  **Training**: Collect efficient traffic baselines (Packet Size, Inter-arrival time) for 7 days.
2.  **Inference**: Use **Isolation Forest** (`sklearn.ensemble.IsolationForest`) to score new sessions.
3.  **Alerting**: Trigger if Anomaly Score > 0.85 (configurable).

---
*Roadmap generated for Thesis Defense - Future Work Section*

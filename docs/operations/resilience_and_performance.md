# Operational Resilience & Performance Guide

This document outlines the design principles for self-healing, resource optimization, and monitoring for the Sentinel NetLab system.

## 1. Self-Healing Mechanisms
The goal is to achieve recovery capabilities without causing "restart storms" or masking underlying architectural issues.

### 1.1 Process Recovery (Service Level)
**Objective**: Restart processes that crash or hang, but prevent infinite loops.

**Recommended Configurations**:
*   **Systemd** (for Sensor Host):
    *   Reference Implementation: [`ops/systemd/sentinel-sensor.service`](../../ops/systemd/sentinel-sensor.service)
    *   `Restart=on-failure`
    *   `RestartSec=5s` (exponential backoff recommended)
    *   `StartLimitIntervalSec=300` + `StartLimitBurst=3` (prevents restart loops)
    *   `WatchdogSec=...` (if application supports heartbeat)
*   **Docker Compose** (Controller/Dashboard):
    *   **Reference**: [`ops/docker-compose.prod.yml`](../../ops/docker-compose.prod.yml)
    *   `restart: unless-stopped`
    *   **Healthchecks**: Essential to distinguish "running but stuck" vs. "crashed".
    *   **Security**: `read_only: true`, `no-new-privileges:true`.
*   **Kubernetes** (if applicable):
    *   Liveness Probes (restart if dead)
    *   Readiness Probes (remove from load balancer if busy)
    *   Resource Limits (prevent node starvation)

**Anti-Pattern**: Infinite restarts without backoff (causes high CPU, log spam, and difficulty debugging).

### 1.2 Capture Plane Integrity (Sensor Level)
Sensors often experience functional failures without process crashes (e.g., interface drops monitor mode, driver stuck).

**Functional Failures**:
*   Interface exits monitor mode.
*   Driver reset/hang.
*   Stuck on channel hopping or RX freeze.
*   NetworkManager interference.

**Correct Approach**:
*   **Application-Level Self-Check**: The sensor app should run a lightweight loop:
    *   **Implemented**: `sensor/sensor_cli.py` checks `last_packet_ts`.
    *   **Condition**: If uptime > 60s AND no packets > 30s -> `sys.exit(2)` (Triggers `Restart=on-failure`).
    *   Check: "Is interface in monitor mode?"
    *   Check: "Have we received frames recently?"
*   **Recovery Strategy**:
    *   If fail: Attempt re-init once with backoff.
    *   If fail > N times: **Fail-fast** (exit process) and let the supervisor (Systemd/Docker) handle the restart.
*   **Principle**: Separation of concerns—lightweight self-heal in app, restart policy in supervisor.

## 2. Resource Optimization
### 2.1 Sensor Optimization (The Edge)
Hardware resources (CPU/IO) are limited. The most expensive operations are **Capture + Parse + IO**, not detection.

**Resource Hogs**:
*   Capturing raw frames (especially saving PCAP or payloads).
*   Parsing/Feature Extraction (Scapy/Python overhead).
*   Serialization (JSON) and Batching.
*   **Logging**: Excessive logging is a specific "silent killer".

**Optimization Strategies**:
*   **No Default PCAP**: Use ring buffers in memory or disk only when needed; do not save all traffic.
*   **Metadata Only**: Discard raw payloads after feature extraction.
*   **Batching**: Send telemetry in batches (e.g., every 0.5-2s or N records) with compression (gzip).
*   **Log Control**: Rate limit logs. Never log per-packet in production.

### 2.2 Controller Optimization (The Core)
Bottlenecks typically occur at **Ingest + Validation + Storage**.

**Bottlenecks**:
*   Schema validation (Pydantic/JSON parsing).
*   Database writes (synchronous).
*   Alert pipeline & high-cardinality dashboard queries.

**Optimization Strategies**:
*   **Batch Validation**: Validate lists/batches rather than single items.
*   **Async Storage**: Use write-behind patterns or queues to avoid blocking ingest.
*   **Cardinality Control**: Avoid high-cardinality values (e.g., unique sensor IDs per event) in metrics/logs.

## 3. Monitoring & Observability
Monitoring should not degrade performance.

### 3.1 Metrics (Prometheus)
*   **Cost**: Generally low if cardinality is managed.
*   **Cardinality Rule**: Do NOT use labels with high uniqueness (e.g., Client MAC, BSSID, SSID) for metrics.
*   **Good Labels**: `sensor_id` (if low count), `result` (ok/fail), `reason` (auth/schema).

### 3.2 Logging (The Dangerous Part)
*   **Risk**: Logging per-record/frame destroys I/O and CPU.
*   **Best Practices**:
    *   Log **Events** (batch success, error, state change), NOT **Data** (frames).
    *   **Sampling**: If debugging, sample 1/1000 records.
    *   **Levels**: `INFO` for ops, `DEBUG` only for lab/dev (time-boxed).

### 3.3 Tracing (OpenTelemetry)
*   Enable only on Controller.
*   Use strict sampling (0.1% - 1%).
*   Do not trace every telemetry record.

## 4. Detection Methodologies
Balance algorithm choice with available resources (Hybrid Evidence).

### 4.1 Rule-Based (Baseline)
*   **Method**: Thresholds, heuristics (burst detection), EWMA (moving averages).
*   **Cost**: O(1) per record. Very cheap.
*   **Role**: Primary detection layer for sensors.

### 4.2 ML Anomaly Detection (Autoencoder)
*   **Method**: Learn "normal" patterns; score = reconstruction error.
*   **Cost**: Heavier than rules.
*   **Optimization**:
    *   Small feature vectors.
    *   Batch inference.
    *   Run on **aggregated** telemetry (not raw frames).
*   **Placement**: Prefer running on Controller; Sensor only does feature extraction.

### 4.3 Risk Scoring & Explainability
*   **Method**: Weighted sum / Logistic function: `Score = w1*Rule + w2*ML + w3*Context`.
*   **Cost**: O(1). Very cheap.
*   **Output**: Include "top contributing factors" for explainability.

## 5. Operational Checklist
### P0: Stability (Prevent Self-Destruction)
*   [ ] Configure Restart Policy with Backoff & Rate Limits (StartLimit).
*   [ ] Sensor: Implement "Monitor Mode Check" & "No Frames" fail-fast logic.
*   [ ] Disable DEBUG logs by default; enforce log sampling.
*   [ ] Metrics: Enforce low-cardinality labels.

### P1: Performance & Efficiency
*   [ ] Batching + Gzip for telemetry.
*   [ ] Discard raw payload; use PCAP ring buffer only for specific needs.
*   [ ] Controller: Async storage/write-behind.
*   [ ] ML: Shift heavy inference to Controller.

### P2: Rigor & Reproducibility
*   [ ] Measure Overhead: CPU/RAM/Disk p95, Ingest Latency.
*   [ ] Publish reproducible methodologies and configs.

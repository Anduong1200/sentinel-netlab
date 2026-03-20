# Data Flow Architecture

## End-to-End Pipeline

The Sentinel NetLab data pipeline processes raw 802.11 frames into actionable security insights.

```mermaid
dataflow
    subgraph External_Entities
        WiFi_APs[WiFi APs]
    end

    subgraph Sensor
        Capture[Capture Engine]
        Parser[Parser]
        Detector[Detector Plugins]
        Buffer[Buffer Manager]
        Formatter[Telemetry Formatter]
    end

    subgraph Controller
        Auth[Auth/RBAC Middleware]
        Ingest[Ingestion Handler]
        Storage[(Storage DB)]
        Alert[Alert Processor]
        Dashboard[Dashboard API]
    end

    %% Flows
    WiFi_APs -->|802.11 frames| Capture
    Capture --> Parser
    Parser --> Detector
    Detector -->|Alerts| Buffer
    Parser --> Formatter
    Formatter -->|Telemetry| Buffer
    Buffer -->|Batch + HMAC / HTTPS| Auth
    
    Auth --> Ingest
    Ingest --> Storage
    Ingest --> Alert
    Alert --> Dashboard
```

## 1. Collection Phase (Sensor)
- **Capture**: `CaptureDriver` puts interface in monitor mode, hopping channels every 200ms.
- **Normalization**: Frames are parsed (Dot11 types) and key metadata (SSID, BSSID, RSSI) extracted.
- **Pattern Matching**: `Detector` engine checks for known signatures (Evil Twin, Deauth) in real-time.

## 2. Transmission Phase (Transport)
- **Buffering**: Data is batched (e.g., 50 items or 5 seconds).
- **Security**: Batches are signed with HMAC-SHA256 (`X-Signature`).
- **Reliability**: Failed uploads are journaled to disk (SQLite) and retried with exponential backoff.

## 3. Ingestion Phase (Controller)
- **Validation**: API validates HMAC signature, Timestamp freshness, and JSON Schema.
- **Persistence**: Valid data is committed to PostgreSQL/SQLite.
- **Correlation**: (Future) Cross-sensor correlation for locating transmitters.

## 4. Visualization Phase (Dashboard)
- **API**: Frontend polls `/api/v1/telemetry` and `/api/v1/alerts`.
- **Metrics**: Prometheus metrics exposed at `/metrics` for operational monitoring.

## 5. Proposed Enterprise Evolution

### Decision Context
- The current design already separates the edge `Sensor` role from the central `Controller` role.
- Sensor transport includes local journaling plus exponential backoff, which is a strong baseline for unreliable branch or campus networks.
- The main scaling pressure now shifts from transport reliability to central ingestion throughput.

### Problem Statement
- In the current flow, event ingestion is still coupled to the Controller API path.
- At enterprise scale, the API can become a bottleneck for connection handling, burst absorption, and retry amplification when many sensors reconnect at once.

### Proposed Decision
- Keep the Controller API focused on control-plane concerns such as sensor registration, policy distribution, heartbeat, and operator workflows.
- Move the telemetry data plane to an asynchronous ingestion path backed by a durable message broker.

### Recommended Flow

```text
Sensor -> local durable spool -> message broker -> ingest workers -> analytics/storage
```

### Rationale
- A broker absorbs burst traffic better than a synchronous API boundary.
- Ingest workers can scale horizontally without forcing the control plane to scale at the same rate.
- Backpressure becomes explicit and measurable through queue depth and consumer lag.
- Replay is easier when parsers, rules, or enrichment logic change.

### Candidate Platforms
- **Kafka / Redpanda**: Better fit for high-throughput, replay-heavy pipelines.
- **RabbitMQ**: Better fit for simpler routing patterns and moderate throughput requirements.

### Reliability Note
- Claims such as "zero data loss" should be reserved for deployments that combine durable local spooling, clear acknowledgment semantics, and idempotent downstream consumers.
- Otherwise, the more accurate guarantee is minimized data loss under network disruption.

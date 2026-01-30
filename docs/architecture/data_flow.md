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

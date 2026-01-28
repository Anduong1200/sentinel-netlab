# System Architecture

Technical architecture and design documentation for Sentinel NetLab.

---

## High-Level Overview

Sentinel NetLab is a distributed wireless intrusion detection system with three primary layers:

```mermaid
graph TB
    subgraph "Sensor Layer"
        S1[Sensor #1<br/>Raspberry Pi]
        S2[Sensor #2<br/>Linux VM]
        S3[Sensor #N<br/>...]
    end
    
    subgraph "Controller Layer"
        API[REST API<br/>Flask]
        DB[(Storage<br/>SQLite/PostgreSQL)]
        QUEUE[Task Queue<br/>Redis]
    end
    
    subgraph "Presentation Layer"
        DASH[Dashboard<br/>Web UI]
        PROM[Prometheus<br/>Metrics]
    end
    
    S1 & S2 & S3 --> |HTTPS/JSON| API
    API <--> DB
    API <--> QUEUE
    API --> DASH
    API --> PROM
```

---

## Sensor Architecture

Each sensor node runs independently and handles capture, processing, and upload.

### Component Diagram

```mermaid
flowchart LR
    subgraph Capture
        USB[WiFi Adapter] --> CAP[CaptureDriver]
        CAP --> |Raw Frames| PARSE[FrameParser]
    end
    
    subgraph Processing
        PARSE --> |ParsedFrame| NORM[Normalizer]
        NORM --> |Telemetry| DETECT[Detection]
        NORM --> |Telemetry| RISK[RiskEngine]
    end
    
    subgraph Transport
        DETECT & RISK --> BUF[BufferManager]
        BUF --> |Batch| CLIENT[TransportClient]
        BUF -.-> |Journal| DISK[(Disk)]
    end
    
    CLIENT --> |HTTPS| CTRL[Controller]
```

### Component Responsibilities

| Component | File | Responsibility |
|-----------|------|----------------|
| **CaptureDriver** | `capture_driver.py` | Monitor mode, channel hopping, raw frame capture |
| **FrameParser** | `frame_parser.py` | Radiotap parsing, IE extraction, deduplication |
| **Normalizer** | `normalizer.py` | OUI lookup, timestamp normalization, anonymization |
| **RiskEngine** | `risk.py` | Weighted scoring, threat classification |
| **Detection** | `detection.py` | Evil twin, deauth flood, pattern matching |
| **BufferManager** | `buffer_manager.py` | Ring buffer, disk journal, batch selection |
| **TransportClient** | `transport_client.py` | Upload, retry, circuit breaker |
| **GeoMapper** | `geo_mapping.py` | Signal trilateration, Kalman filtering, heatmap generation |
| **Wardrive** | `wardrive.py` | GPS correlation, mobile capture, session management |
| **ActiveDefense** | `attacks.py` | Deauth, FakeAP (controlled lab use only) |
| **Audit** | `audit.py` | Security posture analysis, report generation |

---

## Data Flow

### Capture to Storage

```mermaid
sequenceDiagram
    participant A as WiFi Adapter
    participant C as CaptureDriver
    participant P as FrameParser
    participant N as Normalizer
    participant R as RiskEngine
    participant B as BufferManager
    participant T as TransportClient
    participant S as Controller

    A->>C: Raw 802.11 Frame
    C->>C: Channel Hop (1→6→11)
    C->>P: Enqueue Frame
    P->>P: Parse Radiotap + IEs
    P->>N: ParsedFrame
    N->>N: Normalize (OUI, timestamp)
    N->>R: TelemetryRecord
    R->>R: Calculate Score
    R->>B: Scored Record
    B->>B: Add to Ring Buffer
    
    Note over B,T: Upload Timer
    B->>T: Batch (200 records)
    T->>S: POST /api/v1/telemetry
    S-->>T: 200 OK + ack_id
    T->>B: Clear Batch
```

### Network Outage Recovery

```mermaid
sequenceDiagram
    participant B as BufferManager
    participant D as Disk Journal
    participant T as TransportClient
    participant C as Controller

    Note over B,C: Controller Unreachable
    B->>T: Upload Batch
    T->>C: POST (timeout)
    T-->>B: Failure
    B->>D: Persist to Journal
    
    Note over B,C: Controller Recovers
    B->>D: Load Pending Journals
    D-->>B: Batch Data
    B->>T: Retry Upload
    T->>C: POST
    C-->>T: 200 OK
    T->>D: Delete Journal
```

---

## Risk Scoring Pipeline

```mermaid
flowchart LR
    subgraph Input
        NET[Network Data]
    end
    
    subgraph "Feature Extraction"
        NET --> ENC[Encryption Score]
        NET --> RSSI[RSSI Normalized]
        NET --> VEND[Vendor Trust]
        NET --> SSID[SSID Suspicious]
        NET --> WPS[WPS Flag]
        NET --> BCN[Beacon Anomaly]
    end
    
    subgraph "Weighted Scoring"
        ENC & RSSI & VEND & SSID & WPS & BCN --> SUM["Σ(w × x)"]
        YAML[(risk_weights.yaml)] -.-> SUM
        SUM --> SCORE[Score 0-100]
    end
    
    subgraph Output
        SCORE --> |"< 40"| LOW[LOW]
        SCORE --> |"40-69"| MED[MEDIUM]
        SCORE --> |"≥ 70"| HIGH[HIGH]
        SCORE --> EXP[Explanation]
    end
```

### Scoring Formula

```
Score = Σ (weight_i × feature_i) × 100

Where:
- feature_i ∈ [0, 1] (normalized)
- weight_i ∈ [0, 1] (from config)
- Σ weights = 1.0
```

---

## Detection Algorithms

### Evil Twin Detection

```python
# Simplified logic
def detect_evil_twin(current_ap, known_aps):
    for known in known_aps:
        if ssid_similarity(current_ap.ssid, known.ssid) > 0.8:
            if current_ap.bssid != known.bssid:
                if current_ap.rssi - known.rssi > 20:
                    return Alert("Evil Twin", severity="HIGH")
```

### Deauth Flood Detection

```python
# Sliding window rate detection
def detect_deauth_flood(frames, window_sec=2):
    deauth_count = count_frames(
        type="deauth", 
        window=window_sec
    )
    if deauth_count > threshold:
        return Alert("Deauth Flood", rate=deauth_count)
```

    if deauth_count > threshold:
        return Alert("Deauth Flood", rate=deauth_count)
```

### Geo-Location Engine (Trilateration)

```mermaid
flowchart LR
    S1[Sensor 1] & S2[Sensor 2] & S3[Sensor 3] --> |"RSSI (dBm)"| PL{Path Loss Model}
    PL --> |"Distance (m)"| TRI[Trilateration Solver]
    TRI --> |"Raw (x,y)"| KAL[Kalman Filter]
    KAL --> |"Smoothed (x,y)"| MAP[Heatmap Generator]
```

### Active Defense Safety

The `ActiveDefense` module requires explicit safety overrides to operate (`ALLOW_ACTIVE_ATTACKS` env var). It provides:
- **Deauth**: Targeted disconnection of unauthorized clients.
- **FakeAP**: Honey-pot AP creation for detecting connection attempts.
- **Lab Safety**: Checks for isolated environment before execution.

---

## Deployment Options

### Option A: Raspberry Pi (Recommended)

```mermaid
graph TD
    subgraph "Raspberry Pi 4"
        Agent[Sensor Agent]
    end
    
    subgraph "Hardware"
        USB[USB WiFi<br/>(RTL8812AU)]
    end
    
    subgraph "Server"
        Ctrl[Controller]
    end

    Agent --- USB
    Agent -->|HTTP/S| Ctrl
```

### Option B: Virtual Machine

```mermaid
graph TD
    subgraph "Host (Windows/macOS)"
        subgraph "VirtualBox / VMware"
            subgraph "Ubuntu Guest"
                Agent[Sensor Agent]
            end
        end
        USB[USB Passthrough]
    end

    Agent --- USB
```

---

## JSON Schemas

All telemetry data conforms to JSON Schema (Draft-07):

- [telemetry.json](../../sensor/schema/telemetry.json) - Single record
- [telemetry_batch.json](../../sensor/schema/telemetry_batch.json) - Batch wrapper

---

## Technology Stack

| Layer | Technology |
|-------|------------|
| **Capture** | Scapy, libpcap, iw |
| **Processing** | Python 3.9+ |
| **API** | Flask, Gunicorn |
| **Storage** | SQLite, PostgreSQL (planned) |
| **Queue** | Redis (planned) |
| **Metrics** | Prometheus |
| **Containerization** | Docker (optional) |

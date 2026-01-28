# Architecture Overview

> System design, components, and data flow for Sentinel NetLab

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              WIRELESS ENVIRONMENT                           │
│    [APs] [Clients] [Attackers]                                              │
│         ↓ 802.11 frames                                                     │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                    ══════════════════╪══════════════════
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                               SENSOR LAYER                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         Sensor (Pi / Linux)                          │   │
│  │  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐         │   │
│  │  │ Capture  │──▶│  Parser  │──▶│ Detector │──▶│ Transport│──HTTPS──│   │
│  │  │ Engine   │   │          │   │ Plugins  │   │  Client  │         │   │
│  │  └──────────┘   └──────────┘   └──────────┘   └──────────┘         │   │
│  │        │                             │              │               │   │
│  │        ▼                             ▼              ▼               │   │
│  │   [WiFi Adapter]              [Alerts]      [Telemetry Batch]       │   │
│  │   (Monitor Mode)                                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  [Sensor 1] ───┐                                                           │
│  [Sensor 2] ───┼─────────────────HTTPS/mTLS────────────────────────────────│
│  [Sensor N] ───┘                                                           │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                    ══════════════════╪══════════════════
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                             CONTROLLER LAYER                                │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                          Controller API                              │   │
│  │  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐         │   │
│  │  │Auth/RBAC │──▶│Ingestion │──▶│ Storage  │──▶│ Alert    │         │   │
│  │  │Middleware│   │ Handler  │   │  (DB)    │   │ Manager  │         │   │
│  │  └──────────┘   └──────────┘   └──────────┘   └──────────┘         │   │
│  │        │              │              │              │               │   │
│  │  [Rate Limit]   [HMAC Verify]   [Postgres]    [Webhooks]           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                      │                                      │
│  ┌────────────┐   ┌────────────┐   ┌────────────┐                         │
│  │   Redis    │   │ Prometheus │   │  Grafana   │                         │
│  │ (Rate Lim) │   │ (Metrics)  │   │(Dashboard) │                         │
│  └────────────┘   └────────────┘   └────────────┘                         │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                    ══════════════════╪══════════════════
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              OPERATOR LAYER                                 │
│                                                                             │
│  [SOC Analyst] ──API/Dashboard──▶ Alerts, Forensics, Reports               │
│  [Admin]       ──API───────────▶ Sensor Management, Config                 │
│  [SIEM]        ──Webhook/CEF───▶ Alert Integration                         │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Component Details

### Sensor Components

| Component | File | Description |
|-----------|------|-------------|
| **Capture Engine** | `capture.py` | pcap-based frame capture |
| **Frame Parser** | `parser.py` | 802.11 frame decoding |
| **WiFi Parser** | `wifi_parser.py` | Beacon/Probe extraction |
| **Risk Scorer** | `risk.py` | Network risk assessment |
| **WIDS Detectors** | `wids_detectors.py` | Detection plugins |
| **Transport Client** | `message_signing.py` | Secure HTTPS client |

### Controller Components

| Component | File | Description |
|-----------|------|-------------|
| **API Server** | `api_server.py` | Flask REST API |
| **Models** | `models.py` | SQLAlchemy ORM |
| **Auth Middleware** | `api_server.py` | Token/RBAC auth |
| **Rate Limiter** | `api_server.py` | flask-limiter |

### Data Stores

| Store | Purpose | Technology |
|-------|---------|------------|
| **PostgreSQL** | Telemetry, alerts, sensors | Primary storage |
| **Redis** | Rate limiting, caching | In-memory cache |
| **File Spool** | Offline buffer | Local disk |

---

## Data Flow

### 1. Telemetry Ingestion

```
Sensor                    Controller              Database
  │                           │                      │
  │  POST /api/v1/telemetry   │                      │
  │  + Bearer Token           │                      │
  │  + X-Signature (HMAC)     │                      │
  │  + X-Timestamp            │                      │
  │  + X-Sequence             │                      │
  │ ─────────────────────────▶│                      │
  │                           │ Verify Auth          │
  │                           │ Verify HMAC          │
  │                           │ Validate Schema      │
  │                           │ ──────────────────▶  │
  │                           │                      │ Store
  │          200 OK           │ ◀──────────────────  │
  │ ◀─────────────────────────│                      │
```

### 2. Alert Flow

```
Detector Plugin            Controller              Dashboard
  │                           │                      │
  │ Alert Generated           │                      │
  │ POST /api/v1/alerts       │                      │
  │ ─────────────────────────▶│                      │
  │                           │ Store Alert          │
  │                           │ Trigger Webhook      │
  │                           │ Update Metrics       │
  │          201 Created      │                      │
  │ ◀─────────────────────────│                      │
  │                           │                      │
  │                           │ GET /api/v1/alerts   │
  │                           │ ◀────────────────────│
  │                           │ Alert List           │
  │                           │ ────────────────────▶│
```

---

## Security Architecture

### Authentication Flow

```
                    ┌─────────────────────┐
                    │   API Token Store   │
                    │  (Hashed Tokens)    │
                    └─────────────────────┘
                              ▲
                              │ Verify
    ┌─────────┐               │
    │ Sensor  │──Bearer Token─┼──▶ Controller
    └─────────┘               │    │
                              │    ├─ Check Token Hash
                              │    ├─ Check Expiry
                              │    ├─ Check Role
                              │    └─ Check HMAC Signature
```

### Trust Zones

1. **Untrusted**: External WiFi environment
2. **DMZ**: Sensor (limited privileges)
3. **Trusted**: Controller + Database
4. **Management**: Admin/SOC access

---

## Deployment Topologies

### Single-Node (Development)

```
┌────────────────────────────────┐
│          Single Host           │
│  ┌──────────┐  ┌───────────┐  │
│  │  Sensor  │  │ Controller│  │
│  │ (mock)   │──│ (SQLite)  │  │
│  └──────────┘  └───────────┘  │
└────────────────────────────────┘
```

### Production (2-Tier)

```
┌──────────────┐     ┌───────────────────────────┐
│   Sensor 1   │────▶│                           │
├──────────────┤     │      Controller VM        │
│   Sensor 2   │────▶│   (Postgres, Redis,       │
├──────────────┤     │    Prometheus, Grafana)   │
│   Sensor N   │────▶│                           │
└──────────────┘     └───────────────────────────┘
```

### Enterprise (3-Tier)

```
                     ┌──────────────────┐
                     │   Load Balancer  │
                     └────────┬─────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐     ┌───────────────┐     ┌───────────────┐
│ Controller 1  │     │ Controller 2  │     │ Controller N  │
└───────────────┘     └───────────────┘     └───────────────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              ▼
                     ┌──────────────────┐
                     │ Postgres Cluster │
                     │ + Redis Cluster  │
                     └──────────────────┘
```

---

## Technology Stack

| Layer | Technology |
|-------|------------|
| **Sensor Runtime** | Python 3.11, scapy, asyncio |
| **Controller API** | Flask, Pydantic, SQLAlchemy |
| **Database** | PostgreSQL (prod), SQLite (dev) |
| **Cache** | Redis |
| **Metrics** | Prometheus + Grafana |
| **Container** | Docker, docker-compose |
| **CI/CD** | GitHub Actions |

---

## Protocol Specifications

### Telemetry Batch (JSON)

```json
{
  "sensor_id": "sensor-01",
  "batch_id": "batch-abc123",
  "timestamp_utc": "2026-01-28T10:30:00Z",
  "sequence_number": 42,
  "items": [
    {
      "bssid": "AA:BB:CC:11:22:33",
      "ssid": "MyNetwork",
      "channel": 6,
      "rssi_dbm": -55,
      "security": "wpa2_ccmp"
    }
  ]
}
```

### Alert (JSON)

```json
{
  "alert_type": "evil_twin",
  "severity": "High",
  "title": "Evil Twin Detected",
  "description": "Same SSID with different BSSID",
  "bssid": "DE:AD:BE:EF:00:01",
  "ssid": "CorpNet",
  "evidence": {"frame_count": 15},
  "mitre_attack": "T1557"
}
```

---

*Last Updated: January 28, 2026*

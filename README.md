<h1 align="center">Sentinel NetLab</h1>

<p align="center">
  <strong>Lightweight Hybrid Wireless Intrusion Detection System</strong>
</p>

<p align="center">
<p align="center">
  <a href="https://github.com/anduong1200/sentinel-netlab/actions"><img src="https://img.shields.io/github/actions/workflow/status/anduong1200/sentinel-netlab/ci.yml?branch=main&style=flat-square" alt="Build Status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square" alt="License"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11%2B-blue.svg?style=flat-square" alt="Python"></a>
  <a href="https://github.com/astral-sh/ruff"><img src="https://img.shields.io/badge/code%20style-ruff-261230.svg?style=flat-square" alt="Code Style"></a>
</p>
</p>

<p align="center">
  A research-focused WiFi security monitoring platform combining signature-based detection with ML-enhanced anomaly analysis for educational and authorized security testing environments.
</p>

> [!TIP]
> **📚 Documentation**: Start here → **[docs/README.md](docs/README.md)**  
> (Supports **Lab Mode** and **Production Deployment**)

---

## 🎯 Overview

Sentinel NetLab is a distributed wireless intrusion detection system designed for:

- **Security Research** — Study WiFi attack patterns and defensive techniques
- **Security Assessment** — Wardriving and network mapping (Assessment Mode)
- **Lab Environments** — Train security professionals in controlled settings
- **Continuous Monitoring** — Distributed WIDS (Monitor Mode)

### Key Capabilities

| Feature | Description |
|---------|-------------|
| **Real-time Capture** | 802.11 management frame sniffing with channel hopping |
| **Evil Twin Detection** | Identify rogue APs impersonating legitimate networks |
| **Deauth Flood Detection** | Alert on denial-of-service attacks |
| **Risk Scoring** | Weighted threat assessment with explainability |
| **Distributed Architecture** | Multiple sensors → centralized controller |
| **Geo-Location** | Trilateration & Heatmaps for physical source tracking |
| **Wardriving** | GPS-correlated mobile network mapping |
| **Hybrid ML Analysis** | Rule-based engine boosted by Autoencoder Anomaly Detection |
| **Real-time Dashboard** | Live heatmaps and alert visualization (Dash/Plotly) |
| **Scenario Replay** | Replay captured traffic (PCAP) for regression testing and algorithm tuning |

> [!IMPORTANT]
> **Scope**:
> This is strictly a **Passive WIDS**. It focuses exclusively on passively detecting, logging, and alerting on threats (Rogue AP, Deauth, Evil Twin) without transmitting disruptive countermeasures. Active countermeasures (WIPS) are deliberately out of scope for this repository.

---

## 📁 Project Structure

```
sentinel-netlab/
├── sensor/                     # 🔊 Capture Agent
│   ├── sensor_cli.py          # Unified entry point & CLI
│   ├── sensor_controller.py   # Main orchestrator
│   ├── capture_driver.py      # Monitor mode driver
│   ├── capture_tshark.py      # High-performance tshark engine
│   ├── capture_queue.py       # Producer-consumer capture
│   ├── frame_parser.py        # 802.11 frame decoder
│   ├── normalizer.py          # Telemetry normalization
│   ├── transport.py           # Upload with retry & circuit breaker
│   ├── rule_engine.py         # Pattern matching engine
│   ├── forensics.py           # Offline PCAP analysis
│   ├── geo_mapping.py         # Trilateration & heatmaps
│   ├── wardrive.py            # GPS-correlated wardriving CLI
│   ├── audit.py               # Security audit CLI
│   └── schema/                # JSON schemas
│
├── algos/                      # 🧠 Detection Algorithms
│   ├── evil_twin.py           # Evil Twin V2
│   ├── dos.py                 # DoS / Deauth Flood Detector
│   ├── disassoc_detector.py   # Disassociation Flood Detector
│   ├── beacon_flood_detector.py # Beacon Flood / Fake AP Detector
│   ├── krack_detector.py      # KRACK (Key Reinstallation) Detector
│   ├── pmkid_detector.py      # PMKID Harvesting Detector
│   ├── karma_detector.py      # Karma/Pineapple Detector
│   ├── jamming_detector.py    # RF Jamming Detector
│   ├── wardrive_detector.py   # Wardriving Detector
│   ├── wep_iv_detector.py     # WEP IV Attack Detector
│   ├── exploit_chain_analyzer.py # Multi-stage Attack Correlator
│   ├── risk.py                # Risk Scoring Engine
│   ├── baseline.py            # Behavioral Baseline
│   └── detection.py           # Utilities (Levenshtein, BloomFilter)
│
├── controller/                 # 🖥️ Central Server
│   ├── api_server.py          # Flask REST API
│   ├── api/                   # Route handlers (alerts, auth, telemetry)
│   ├── db/                    # SQLAlchemy models & migrations
│   ├── alerts/                # Alert emission pipeline
│   ├── dedup/                 # Event deduplication
│   ├── scoring/               # Risk scoring
│   ├── ingest/                # Telemetry ingestion queue & worker
│   ├── integrations/          # SIEM connectors (Elasticsearch, Splunk)
│   └── export_engine.py       # Report generation (HTML/JSON/CSV)
│
├── common/                     # 🔗 Shared Code
│   ├── contracts.py           # Pydantic data models
│   ├── frame_constants.py     # 802.11 constants
│   ├── privacy.py             # MAC anonymization
│   ├── observability/         # Logging, metrics, tracing
│   ├── detection/             # Evidence & findings models
│   └── schemas/               # Shared Pydantic schemas
│
├── dashboard/                  # 📊 Web UI (Dash Multi-Page App)
│   ├── app.py                 # Entry point
│   ├── pages/                 # overview, map, threats, signals
│   └── components/            # sidebar, cards
│
├── ml/                         # 🧠 Machine Learning
│   └── anomaly_model.py       # PyTorch Autoencoder
│
├── benchmarks/                 # 📈 Performance & Accuracy tests
│   ├── benchmark_suite.py     # Comprehensive metrics
│   └── compare_recall.py      # Ground truth comparison
│
├── data/                       # 💾 Datasets & PCAPs
│   ├── datasets/              # CSV/JSON exports
│   └── pcap_annotated/        # Training data
│
├── docs/                       # 📚 Documentation
│   ├── lab/                   # Lab quickstart & safety
│   ├── prod/                  # Production deployment & ops
│   ├── reference/             # API, config, schema, observability
│   ├── architecture/          # System design & threat model
│   └── adr/                   # Architecture decision records
│
├── ops/                        # ⚙️ Operations & Docker
│   ├── docker-compose.prod.yml # Hardened production stack
│   ├── docker-compose.yml     # Development stack
│   ├── Dockerfile.controller  # Controller image
│   ├── Dockerfile.sensor      # Sensor image
│   └── systemd/               # Sentinel Systemd units
│
├── examples/                   # 📝 Sample Data
│   ├── sample_telemetry.json  # Telemetry example
│   └── sample_alert.json      # Alert example
│
├── pyproject.toml              # Modern Python build config
└── Makefile                    # Build/test commands
```

---

## 🎓 Lab Quick Start (Recommended for Learners)

> **New to Sentinel NetLab?** Start here for the fastest path to a working demo.

```bash
git clone https://github.com/anduong1200/sentinel-netlab.git
cd sentinel-netlab
make lab-up
```

Then open [http://127.0.0.1:8050](http://127.0.0.1:8050) in your browser.

📖 **Full Guide**: [docs/lab/quickstart.md](docs/lab/quickstart.md)
🔧 **Troubleshooting**: [docs/lab/troubleshooting.md](docs/lab/troubleshooting.md)

---

## 🚀 Quick Start (Development/Production)

### Prerequisites
- Python 3.11+
- **[Detailed System Requirements](docs/reference/hardware_requirements.md)** (CPU, RAM, OS Kernel, Storage, and WiFi Adapters for VMs, Lab, and Production).

### 1. Installation

**Prerequisites**: Python 3.11+, Linux (for Sensor w/ Monitor Mode) or Windows (Controller/Dashboard).

```bash
# Clone
git clone https://github.com/anduong1200/sentinel-netlab.git
cd sentinel-netlab

# Venv
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install Dependencies (Pick your role)
pip install ".[controller]"  # For Controller only
pip install ".[sensor]"      # For Sensor only
pip install ".[dashboard]"   # For Dashboard only
pip install ".[dev]"         # For Development (Tests, Linting)
```

### 2. Deployment (Docker)

```bash
# Configure secrets (Required! No default keys provided)
cp .env.example .env
nano .env

# Start stack
docker compose -f ops/docker-compose.yml up -d
```

> [!CAUTION]
> **NEVER COMMIT `.env` FILES**
> This repository is configured to fail CI/CD if `.env` or `.venv` files are detected. 
> Always use the provided `.env.example` as a template and keep your actual configuration local.

### Usage

Sentinel NetLab operates in two primary modes:

#### A. Standalone Tools (CLI)
Isolated tools for specific security assessments (Manual/Ad-hoc).

**1. Wardriving (WiFi Mapping)**
Capture networks with GPS correlation and optionally upload to Controller.
```bash
# Capture and save locally
python sensor/wardrive.py --iface wlan0mon --gps /dev/ttyUSB0 --output session.json

# Capture and upload (Connected Mode)
python sensor/wardrive.py --iface wlan0mon --upload --api-url http://controller:5000/api/v1
```

**2. Audit (Security Checklist)**
Run compliance checks against discovered networks.
```bash
# Security check against Home profile
python sensor/audit.py --profile home --output report.json
```

#### B. WIDS Platform (Continuous Monitoring)
The core Distributed Wireless Intrusion Detection System.

**1. Run Sensor Agent**
Starts the continuous monitoring daemon.
```bash
# Fail-fast check for config and connectivity
python sensor/sensor_cli.py --sensor-id sensor-01 --iface wlan0mon --config config.yaml
```

**2. Deploy Controller (Production)**
Start the central management backend with hardened configs (Ports 80/443 only).
```bash
cp ops/.env.prod.example .env  # Configure secrets first!
docker compose -f ops/docker-compose.prod.yml up -d
```

**3. Dashboard**
View real-time alerts and heatmaps at http://localhost:8050

**Run Tests:**
```bash
pytest tests/
```

---

## 📊 Architecture

```mermaid
graph TB
    subgraph "Sensor Layer (Edge)"
        S1[Sensor #1<br/>RPi] 
        S2[Sensor #2<br/>VM]
        S3[Sensor #3]
    end

    subgraph "Controller Layer (Core)"
        API[API Server]
        Auth[Auth Service]
    end

    subgraph "Data & Processing"
        DB[(PostgreSQL)]
        Redis[(Redis Queue)]
        Prom[Prometheus]
    end

    S1 & S2 & S3 -->|HTTPS/JSON| API
    API --> Auth
    API --> DB
    API --> Redis
    API --> Prom
```

### Data Flow

```mermaid
sequenceDiagram
    participant W as WiFi Adapter
    participant D as Driver
    participant P as Parser
    participant N as Normalizer
    participant C as Controller

    W->>D: 802.11 Mgmt Frames
    D->>P: Raw Packets
    P->>N: Extracted Metadata
    N->>C: Telemetry Batch (JSON)
```

---

## 📚 Documentation

### Core Guides
*   **[Lab Quick Start](docs/lab/quickstart.md)**: Set up a local test environment.
*   **[Production Deployment](docs/prod/deployment.md)**: Deploy via Docker Compose with security hardening.
*   **[Operations Runbook](docs/prod/ops-runbook.md)**: Monitoring, Troubleshooting, and Recovery.
*   **[Troubleshooting](docs/lab/troubleshooting.md)**: Common Lab/Dev issues.

### Reference
*   **[Configuration](docs/reference/configuration.md)**: Environment Variables & Secrets.
*   **[Observability](docs/reference/observability.md)**: Metrics, Logs, and Dashboards.
*   **[Trust Model](docs/reference/proxy-trust.md)**: Security architecture.
*   **[Architecture](docs/architecture/system-design.md)**: System design.
*   **[Database Schema](docs/reference/schema.md)**: Data models.
*   **[API Spec](docs/reference/api.md)**: REST Endpoints.

### Research
*   [Threat Model](docs/architecture/threat_model.md)
---

## 🧪 Development

### Run Tests

```bash
pytest tests/unit/ -v --cov=. --cov-report=html
```

### Code Quality

```bash
# Linting
ruff check .

# Type checking
mypy algos/ controller/ sensor/ common/ --ignore-missing-imports
```

---

## 🔒 Security & Ethics

> [!CAUTION]
> **AUTHORIZED USE ONLY**
>
> This software captures wireless network traffic. **Use only on networks you own or have explicit written authorization to monitor.**
>
> Unauthorized interception of wireless communications may violate laws including:
> - Computer Fraud and Abuse Act (US)
> - Computer Misuse Act (UK)
> - Similar legislation in other jurisdictions

See [Legal & Ethics Statement](docs/reference/legal_ethics.md) for detailed guidelines.

---

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](.github/CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📬 Contact

- **Issues**: [GitHub Issues](https://github.com/anduong1200/sentinel-netlab/issues)
- **Security**: See [SECURITY.md](.github/SECURITY.md) for reporting vulnerabilities

---

<p align="center">
  <sub>Built with ❤️ for security research and education</sub>
</p>

### Known Limitations
* **WPA3 and PMF (Protected Management Frames):** The system currently lacks the ability to inspect data frames encrypted with WPA3/PMF. Additionally, containment (deterrence) actions will fail on the 6GHz band because management frames are protected.

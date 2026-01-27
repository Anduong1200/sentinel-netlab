<p align="center">
  <img src="docs/images/logo.png" alt="Sentinel NetLab" width="200" height="200">
</p>

<h1 align="center">Sentinel NetLab</h1>

<p align="center">
  <strong>Lightweight Hybrid Wireless Intrusion Detection System</strong>
</p>

<p align="center">
  <a href="https://github.com/Anduong1200/sentinel-netlab/actions"><img src="https://img.shields.io/github/actions/workflow/status/Anduong1200/sentinel-netlab/ci.yml?branch=main&style=flat-square" alt="Build Status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square" alt="License"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.9%2B-blue.svg?style=flat-square" alt="Python"></a>
  <a href="ETHICS.md"><img src="https://img.shields.io/badge/use-authorized%20only-red.svg?style=flat-square" alt="Ethics"></a>
</p>

<p align="center">
  A research-focused WiFi security monitoring platform combining signature-based detection with ML-enhanced anomaly analysis for educational and authorized security testing environments.
</p>

---

## 🎯 Overview

Sentinel NetLab is a distributed wireless intrusion detection system designed for:

- **Security Research** — Study WiFi attack patterns and defensive techniques
- **Lab Environments** — Train security professionals in controlled settings
- **Network Auditing** — Assess wireless security posture (with authorization)
- **Academic Projects** — Support thesis research on WiFi security

### Key Capabilities

| Feature | Description |
|---------|-------------|
| **Real-time Capture** | 802.11 management frame sniffing with channel hopping |
| **Evil Twin Detection** | Identify rogue APs impersonating legitimate networks |
| **Deauth Flood Detection** | Alert on denial-of-service attacks |
| **Risk Scoring** | Weighted threat assessment with explainability |
| **Distributed Architecture** | Multiple sensors → centralized controller |
| **ML Integration** | Export labeled data for machine learning workflows |

---

## 📁 Project Structure

```
sentinel-netlab/
├── sensor/                     # 🔊 Capture Agent
│   ├── cli.py                 # Entry point & CLI
│   ├── sensor_controller.py   # Main orchestrator
│   ├── capture_driver.py      # Monitor mode driver
│   ├── frame_parser.py        # 802.11 frame decoder
│   ├── normalizer.py          # Telemetry normalization
│   ├── buffer_manager.py      # Ring buffer + journal
│   ├── transport_client.py    # Upload with retry
│   ├── detection.py           # Threat detection logic
│   ├── risk.py                # Risk scoring engine
│   ├── utils/                 # OUI lookup, time sync
│   ├── schema/                # JSON schemas
│   └── tests/                 # Unit & integration tests
│
├── controller/                 # 🖥️ Central Server
│   └── (Flask API - planned)
│
├── docs/                       # 📚 Documentation
│   ├── getting-started/       # Installation & quickstart
│   ├── architecture/          # System design & diagrams
│   ├── operations/            # Deployment & monitoring
│   └── research/              # Academic materials
│
├── ops/                        # ⚙️ Operations
│   └── systemd/               # Service files
│
├── scripts/                    # 🔧 Utilities
│   ├── setup.sh               # Installation script
│   └── upgrade.sh             # Update script
│
└── research/                   # 🔬 Test Data
    └── pcaps/                 # Sample captures
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.9+
- Linux (Debian/Ubuntu recommended)
- WiFi adapter with monitor mode support ([see compatibility](docs/operations/hardware.md))

### Installation

```bash
# Clone repository
git clone https://github.com/Anduong1200/sentinel-netlab.git
cd sentinel-netlab

# Run setup script (Debian/Ubuntu)
sudo ./scripts/setup.sh

# Or manual installation
python3 -m venv venv
source venv/bin/activate
pip install -r sensor/requirements.txt
```

### Configure WiFi Adapter

```bash
# Enable monitor mode
sudo ip link set wlan0 down
sudo iw wlan0 set type monitor
sudo ip link set wlan0 up
```

### Start Sensor

```bash
cd sensor

# Production mode (requires root)
sudo python cli.py --sensor-id lab-sensor-01 --iface wlan0

# Development mode (mock capture)
python cli.py --sensor-id dev-01 --iface mock0 --mock-mode
```

---

## 📊 Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        SENSOR LAYER                              │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐            │
│  │  Sensor #1  │   │  Sensor #2  │   │  Sensor #3  │            │
│  │  (Pi/VM)    │   │  (Pi/VM)    │   │  (Pi/VM)    │            │
│  └──────┬──────┘   └──────┬──────┘   └──────┬──────┘            │
│         │ HTTPS           │ HTTPS           │ HTTPS              │
└─────────┼─────────────────┼─────────────────┼────────────────────┘
          │                 │                 │
          └────────────────┬┘─────────────────┘
                           │
┌──────────────────────────┼───────────────────────────────────────┐
│                          ▼         CONTROLLER LAYER              │
│                   ┌─────────────┐                                │
│                   │  Controller │                                │
│                   │  (Flask)    │                                │
│                   └──────┬──────┘                                │
│                          │                                       │
│           ┌──────────────┼──────────────┐                       │
│           ▼              ▼              ▼                       │
│    ┌───────────┐  ┌───────────┐  ┌───────────┐                 │
│    │  SQLite   │  │   Redis   │  │ Prometheus│                 │
│    │  Storage  │  │   Queue   │  │  Metrics  │                 │
│    └───────────┘  └───────────┘  └───────────┘                 │
└──────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
[WiFi Adapter] → [CaptureDriver] → [FrameParser] → [Normalizer]
                                                         ↓
[Controller] ← [TransportClient] ← [BufferManager] ← [RiskEngine]
```

---

## 📚 Documentation

### Getting Started
- [Installation Guide](docs/getting-started/installation.md)
- [Quick Start Tutorial](docs/getting-started/quickstart.md)
- [Configuration Reference](docs/getting-started/configuration.md)

### Architecture
- [System Design](docs/architecture/system-design.md)
- [Risk Scoring Model](docs/architecture/risk-scoring.md)
- [Detection Algorithms](docs/architecture/detection.md)

### Operations
- [Deployment Guide](docs/operations/deployment.md)
- [Hardware Compatibility](docs/operations/hardware.md)
- [Monitoring & Metrics](docs/operations/monitoring.md)
- [Troubleshooting](docs/operations/troubleshooting.md)

### Research
- [WiFi Security Analysis](docs/research/wifi-security.md)
- [IEEE Report Template](docs/research/ieee-report.md)
- [Test Vectors](sensor/tests/unit/test_vectors/)

### Reference
- [API Documentation](docs/api-reference.md)
- [CLI Reference](docs/cli-reference.md)
- [JSON Schemas](sensor/schema/)

---

## 🧪 Development

### Run Tests

```bash
cd sensor
pytest tests/unit/ -v --cov=. --cov-report=html
```

### Code Quality

```bash
# Linting
ruff check sensor/
flake8 sensor/ --max-line-length=120

# Type checking
mypy sensor/ --ignore-missing-imports
```

### Build Package

```bash
cd sensor
python -m build
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

See [ETHICS.md](ETHICS.md) for detailed guidelines and authorization templates.

---

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📬 Contact

- **Issues**: [GitHub Issues](https://github.com/Anduong1200/sentinel-netlab/issues)
- **Security**: See [SECURITY.md](SECURITY.md) for reporting vulnerabilities

---

<p align="center">
  <sub>Built with ❤️ for security research and education</sub>
</p>

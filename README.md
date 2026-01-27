# Sentinel NetLab 🛡️
> **Wireless Intrusion Detection System (WIDS)**

[![CI](https://github.com/Anduong1200/sentinel-netlab/actions/workflows/main.yml/badge.svg)](https://github.com/Anduong1200/sentinel-netlab/actions)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)

**Sentinel NetLab** is a **Lightweight Hybrid Wireless Monitoring System** designed for **resource-constrained environments**. It combines a high-performance C-based capture engine (Tshark) with a flexible Python analysis core.

> **Note:** This project targets **Education, Research, and Tactical Monitoring**.

---

## 🎯 Target Audience

| Audience | Fit | Verdict |
|----------|-----|---------|
| 🎓 **Student / Lab** | ⭐⭐⭐⭐⭐ | **Perfect**. Ideal for learning 802.11 security. |
| 🔬 **Researcher** | ⭐⭐⭐⭐ | **Strong**. Modular framework for testing algorithms. |
| 🏢 **Enterprise** | ⭐ | **Weak**. Use commercial WIPS for production. |

---

## 🚀 Quick Start

### Prerequisites
- Linux Environment (Debian 12 / Ubuntu 22.04 / Kali)
- USB WiFi Adapter with Monitor Mode (Atheros AR9271)
- Python 3.9+

### Installation

```bash
# Clone repository
git clone https://github.com/Anduong1200/sentinel-netlab.git
cd sentinel-netlab

# Run unified setup script
sudo ./scripts/setup_vm.sh

# Activate virtual environment
source /opt/sentinel-netlab/venv/bin/activate
```

### Start Sensor

```bash
cd sensor
python api_server.py
```

### Launch GUI (Windows)

```powershell
cd controller
python scanner_gui.py
```

---

## 🏗️ Project Structure

```
sentinel-netlab/
├── sensor/           # API server and capture engine
│   ├── api_server.py
│   ├── capture.py
│   ├── parser.py
│   └── risk.py
├── controller/       # Windows GUI
│   └── scanner_gui.py
├── scripts/          # Setup and utility scripts
│   └── setup_vm.sh
├── tests/            # Unit tests
├── docs/             # Documentation
└── .github/          # CI/CD workflows
```

---

## 📚 Documentation

### Core Docs
| Document | Description |
|----------|-------------|
| [System Design](docs/SYSTEM_DESIGN.md) | Architecture & flowcharts |
| [IEEE Report](docs/IEEE_Sentinel_NetLab_Report.md) | Academic paper |
| [Install Guide](docs/install_guide.md) | Step-by-step setup |
| [Demo Runbook](docs/demo_runbook.md) | Live demo guide |

### Technical Deep-Dive
| Document | Description |
|----------|-------------|
| [API Reference](docs/api_reference.md) | REST API endpoints |
| [Technical Critique](docs/technical_critique.md) | Architectural analysis |
| [Improvement Roadmap](docs/technical_improvement_roadmap.md) | Future plans |

### Defense & Presentation
| Document | Description |
|----------|-------------|
| [Defense Script](docs/defense_script.md) | Q&A preparation |
| [Slides](docs/presentation_slides.md) | Presentation content |

---

## 🛡️ Security & Legal

This software is for **authorized security auditing only**. Users must comply with all applicable laws.

See [Legal Disclaimer](docs/legal_ethics.md) for details.

---

## 🤝 Contributing

Contributions welcome! Please follow:
- PEP 8 coding standards
- Create tests for new features
- Update documentation

---

**Security Research Club** © 2024-2026

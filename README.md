# 🛡️ Hybrid Wireless Security Assessment System

> A Proof-of-Concept (PoC) hybrid system combining a Linux VM sensor with a Windows GUI controller for comprehensive Wi-Fi security assessment.

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Educational-green.svg)]()
[![Status](https://img.shields.io/badge/Status-Phase_2_Complete-brightgreen.svg)]()

## 📋 Overview

This project addresses the challenge of performing Wi-Fi security analysis on Windows systems, where native monitor mode support is limited. By leveraging a Linux VM with USB passthrough, we enable comprehensive 802.11 frame capture while providing a user-friendly Windows interface.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Windows Host                              │
│  ┌──────────────────────┐      ┌─────────────────────────┐  │
│  │   Controller (GUI)   │◄────►│   Linux VM (Sensor)     │  │
│  │   - Tkinter UI       │ HTTP │   - Flask API           │  │
│  │   - Risk Display     │ REST │   - CaptureEngine       │  │
│  │   - Export CSV/JSON  │      │   - WiFiParser          │  │
│  └──────────────────────┘      │   - RiskScorer          │  │
│                                └───────────┬─────────────┘  │
│                                            │ USB Passthrough │
│                                    ┌───────┴───────┐         │
│                                    │  Wi-Fi Adapter│         │
│                                    │  (AR9271)     │         │
│                                    └───────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

## ✨ Features

- **Monitor Mode Support**: Full 802.11 frame capture via Linux VM
- **Channel Hopping**: Automatic scanning across 2.4GHz channels (1-13)
- **Advanced Risk Scoring**: Weighted algorithm (encryption 45%, signal 20%, SSID 15%, vendor 10%, channel 10%)
- **REST API**: Clean JSON API with rate limiting and authentication
- **Mock Mode**: Demo without hardware using simulated data
- **Data Persistence**: SQLite database with automatic PCAP rotation
- **Export Options**: CSV, JSON export for forensic analysis
- **OUI Lookup**: Vendor identification from MAC address

## 🚀 Quick Start

### Prerequisites

- Windows 10/11 host
- VirtualBox 7.x (with Extension Pack) or VMware Workstation
- Kali Linux VM (or Ubuntu with aircrack-ng)
- USB Wi-Fi adapter (Atheros AR9271 recommended)
  - TP-Link TL-WN722N v1
  - Alfa AWUS036NHA

### Sensor Setup (Linux VM)

```bash
# Clone repository
git clone https://github.com/your-repo/hod_lab.git
cd hod_lab

# Run setup script
chmod +x scripts/setup_vm.sh
./scripts/setup_vm.sh

# Start sensor API
cd sensor
sudo python3 api_server.py
```

### Controller Setup (Windows)

```powershell
# Navigate to controller
cd hod_lab\controller

# Install dependencies
pip install -r requirements.txt

# Run GUI
python scanner_gui.py
```

## 📁 Project Structure

```
hod_lab/
├── sensor/                 # Linux VM Backend (Modular)
│   ├── api_server.py       # Flask REST API (integrated)
│   ├── capture.py          # CaptureEngine class
│   ├── parser.py           # WiFiParser + OUI database
│   ├── storage.py          # WiFiStorage + MemoryStorage
│   ├── risk.py             # RiskScorer class
│   ├── config.py           # Configuration management
│   ├── requirements.txt    # Python dependencies
│   └── wifi-scanner.service # Systemd service file
│
├── controller/             # Windows Frontend
│   ├── scanner_gui.py      # Tkinter GUI
│   └── requirements.txt
│
├── scripts/                # Utility Scripts
│   ├── check_driver.py     # Driver diagnostics
│   ├── setup_vm.sh         # VM auto-setup
│   ├── install_service.sh  # Service installer
│   └── setup_host.ps1      # Windows host helper
│
├── docs/                   # Documentation
│   ├── technical_report.md # Full technical report
│   ├── install_guide.md    # Installation guide
│   ├── api_reference.md    # API documentation
│   ├── risk_management.md  # Risk register
│   ├── demo_runbook.md     # Demo script
│   └── roadmap_8weeks.md   # Development roadmap
│
├── tests/                  # Test Scripts
│   └── test_modules.py     # Unit tests
│
├── artifacts/              # Test artifacts (gitignored)
└── README.md
```

## 🔌 API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | ❌ | Health check |
| `/status` | GET | ❌ | Sensor status + interface info |
| `/scan` | GET | ✅ | Trigger WiFi scan |
| `/history` | GET | ✅ | Get scan history |
| `/export/csv` | GET | ✅ | Export as CSV |
| `/export/json` | GET | ✅ | Export as JSON |

**Authentication**: Include `X-API-Key` header.

```bash
# Example
curl -H "X-API-Key: student-project-2024" http://VM_IP:5000/scan
```

## 📊 Risk Scoring

Networks are scored 0-100 based on weighted factors:

| Factor | Weight | High Risk | Low Risk |
|--------|--------|-----------|----------|
| Encryption | 45% | Open, WEP | WPA3 |
| Signal | 20% | > -50 dBm | < -70 dBm |
| SSID | 15% | "Free", "Hotspot" | Normal |
| Vendor | 10% | Unknown | Known brand |
| Channel | 10% | Unusual | Standard (1,6,11) |

**Risk Levels**:
- 🔴 **Critical** (90-100): Avoid connecting
- 🟠 **High** (70-89): Use VPN if necessary
- 🟡 **Medium** (40-69): Exercise caution
- 🟢 **Low** (0-39): Relatively safe

## 🧪 Testing

```bash
# Run unit tests
cd hod_lab
python -m pytest tests/ -v

# Check driver status (on VM)
python scripts/check_driver.py
```

## ⚠️ Legal Notice

> **This tool is for educational and authorized security testing only.**

- Only scan networks you own or have explicit permission to test
- Follow local laws and regulations
- Attack features are disabled by default
- The authors are not responsible for misuse

## 📚 Documentation

- [Technical Report](docs/technical_report.md)
- [Installation Guide](docs/install_guide.md)
- [API Reference](docs/api_reference.md)
- [Risk Management](docs/risk_management.md)
- [Demo Runbook](docs/demo_runbook.md)

## 📄 License

This project is for educational purposes as part of academic coursework.

---

**⭐ Star this repo if you find it useful!**

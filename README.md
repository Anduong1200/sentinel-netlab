# 🛡️ Hybrid Wireless Security Assessment System

> A Proof-of-Concept (PoC) hybrid system combining a Linux VM sensor with a Windows GUI controller for comprehensive Wi-Fi security assessment.

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Educational-green.svg)]()
[![Status](https://img.shields.io/badge/Status-In_Development-yellow.svg)]()

## 📋 Overview

This project addresses the challenge of performing Wi-Fi security analysis on Windows systems, where native monitor mode support is limited. By leveraging a Linux VM with USB passthrough, we enable comprehensive 802.11 frame capture while providing a user-friendly Windows interface.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Windows Host                              │
│  ┌──────────────────────┐      ┌─────────────────────────┐  │
│  │   Controller (GUI)   │◄────►│   Linux VM (Sensor)     │  │
│  │   - Tkinter UI       │ HTTP │   - Flask API           │  │
│  │   - Risk Display     │ REST │   - Monitor Mode        │  │
│  │   - Export CSV/JSON  │      │   - Packet Capture      │  │
│  └──────────────────────┘      └───────────┬─────────────┘  │
│                                            │ USB Passthrough │
│                                    ┌───────┴───────┐         │
│                                    │  Wi-Fi Adapter│         │
│                                    │  (AR9271)     │         │
│                                    └───────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

## ✨ Features

- **Monitor Mode Support**: Full 802.11 frame capture via Linux VM
- **Channel Hopping**: Automatic scanning across 2.4GHz channels
- **Risk Scoring**: Weighted algorithm assessing encryption, signal, SSID patterns
- **REST API**: Clean JSON API for sensor-controller communication
- **Mock Mode**: Demo without hardware using simulated data
- **Data Persistence**: SQLite database with PCAP rotation
- **Export Options**: CSV, JSON export for forensic analysis

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
cd hod_lab/sensor

# Install dependencies
pip install -r requirements.txt

# Run sensor API
sudo python3 api_server.py
```

### Controller Setup (Windows)

```bash
# Navigate to controller
cd hod_lab/controller

# Install dependencies
pip install -r requirements.txt

# Run GUI
python scanner_gui.py
```

## 📁 Project Structure

```
hod_lab/
├── sensor/                 # Linux VM Backend
│   ├── api_server.py       # Flask REST API
│   ├── capture.py          # Monitor mode & channel hopping
│   ├── parser.py           # 802.11 frame parsing
│   ├── storage.py          # SQLite & PCAP management
│   ├── risk.py             # Risk scoring algorithm
│   └── config.py           # Configuration management
│
├── controller/             # Windows Frontend
│   ├── scanner_gui.py      # Tkinter GUI
│   └── requirements.txt
│
├── docs/                   # Documentation
│   ├── technical_report.md # Full technical report
│   ├── install_guide.md    # Installation guide
│   └── api_reference.md    # API documentation
│
├── tests/                  # Test scripts
├── scripts/                # Utility scripts
└── artifacts/              # Test artifacts storage
```

## 🔌 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/scan` | GET | Trigger WiFi scan |
| `/history` | GET | Get scan history |
| `/export/csv` | GET | Export as CSV |

**Authentication**: Include `X-API-Key` header with your API key.

```bash
# Example
curl -H "X-API-Key: student-project-2024" http://VM_IP:5000/scan
```

## 📊 Risk Scoring

Networks are scored 0-100 based on weighted factors:

| Factor | Weight | Description |
|--------|--------|-------------|
| Encryption | 45% | Open/WEP = High, WPA3 = Low |
| Signal | 20% | Strong signal = More accessible |
| SSID | 15% | Suspicious patterns (Free, Hotspot) |
| Vendor | 10% | Unknown vendors = Higher risk |
| Channel | 10% | Unusual channels = Flag |

**Risk Levels**:
- 🔴 **Critical** (90-100): Avoid connecting
- 🟠 **High** (70-89): Use VPN if necessary
- 🟡 **Medium** (40-69): Exercise caution
- 🟢 **Low** (0-39): Relatively safe

## ⚠️ Legal Notice

> **This tool is for educational and authorized security testing only.**

- Only scan networks you own or have explicit permission to test
- Follow local laws and regulations
- Attack features are disabled by default
- The authors are not responsible for misuse

## 🛠️ Development

### Running Tests

```bash
# Compare recall with airodump-ng
python tests/compare_recall.py artifacts/gt_output.csv artifacts/poc.json

# Test API latency
python tests/test_latency.py
```

### Configuration

Environment variables:
```bash
export WIFI_SCANNER_INTERFACE=wlan0
export WIFI_SCANNER_PORT=5000
export WIFI_SCANNER_API_KEY=your-key
export WIFI_SCANNER_MOCK_MODE=true
```

## 📚 Documentation

- [Technical Report](docs/technical_report.md) - Full project documentation
- [Installation Guide](docs/install_guide.md) - Setup instructions
- [API Reference](docs/api_reference.md) - API documentation

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open Pull Request

## 📄 License

This project is for educational purposes as part of academic coursework.

## 👥 Authors

- Student Project - Wireless Security Assessment
- Supervised by [Instructor Name]

---

**⭐ Star this repo if you find it useful!**

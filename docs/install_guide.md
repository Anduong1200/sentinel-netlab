# Installation Guide - Sentinel NetLab

## 📋 Overview

The system consists of 2 components:
- **Sensor** (Linux VM): Flask API + Scapy/Tshark
- **Controller** (Windows): Tkinter GUI

## 🔧 System Requirements

### Hardware
| Component | Requirement |
|-----------|-------------|
| CPU | 2+ cores |
| RAM | 4GB minimum |
| Disk | 20GB free |
| USB WiFi | Atheros AR9271 (TP-Link WN722N v1) |

### Software
- Windows 10/11 (host)
- VirtualBox 7.x or VMware Workstation
- Python 3.9+

---

## 🖥️ Part 1: Sensor Setup (Linux VM)

### 1.1 Quick Setup (Recommended)

```bash
# Clone repository
git clone https://github.com/Anduong1200/sentinel-netlab.git
cd sentinel-netlab

# Run unified setup script
sudo ./scripts/setup_vm.sh
```

The script will:
- Install system dependencies (tshark, aircrack-ng)
- Create Python virtual environment at `/opt/sentinel-netlab/venv`
- Install all Python packages

### 1.2 Start Sensor

```bash
# Activate environment
source /opt/sentinel-netlab/venv/bin/activate

# Run API server
cd sensor
sudo python3 api_server.py
```

### 1.3 Verify

```bash
curl http://localhost:5000/health
# {"status": "ok"}
```

---

## 🪟 Part 2: Controller Setup (Windows)

### 2.1 Install Python Dependencies

```powershell
cd D:\hod_lab\controller
pip install -r requirements.txt
```

### 2.2 Launch GUI

```powershell
python scanner_gui.py
```

### 2.3 Connect to Sensor

1. Enter VM IP address (e.g., `192.168.1.100`)
2. Click "Connect"
3. Status should turn green

---

## 🔌 Part 3: USB WiFi Adapter Setup

### VirtualBox
1. Install Extension Pack
2. VM Settings → USB → Enable USB 3.0
3. Add Device Filter for your adapter
4. Start VM → Devices → USB → Select adapter

### VMware
1. VM Settings → USB Controller → USB 3.0
2. Start VM → VM → Removable Devices → Select adapter

### Verify in Linux
```bash
lsusb | grep -i atheros
iw dev
# Should show wlan0 interface
```

---

## 🔧 Troubleshooting

### "Interface not found"
```bash
# Check if driver loaded
lsmod | grep ath9k

# Reload driver
sudo modprobe -r ath9k_htc
sudo modprobe ath9k_htc
```

### "Permission denied"
```bash
# Add user to wireshark group
sudo usermod -aG wireshark $USER
# Then log out and back in
```

---

## 📁 Project Structure

```
sentinel-netlab/
├── sensor/           # API server and capture engine
│   ├── api_server.py
│   ├── capture.py
│   └── risk.py
├── controller/       # Windows GUI
│   └── scanner_gui.py
├── scripts/          # Setup and utility scripts
│   └── setup_vm.sh
├── tests/            # Unit and integration tests
└── docs/             # Documentation
```

---

*For detailed architecture, see [SYSTEM_DESIGN.md](SYSTEM_DESIGN.md)*

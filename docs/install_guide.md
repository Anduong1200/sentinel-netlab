# Installation Guide

> Complete setup instructions for Sentinel NetLab deployment

---

## Prerequisites

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4 cores |
| RAM | 4 GB | 8 GB |
| Storage | 20 GB | 50 GB |
| USB WiFi | AR9271 chipset | TP-Link WN722N v1 |

### Software Requirements

| Platform | Component | Version |
|----------|-----------|---------|
| **Host** | Windows | 10/11 |
| **Host** | VirtualBox or VMware | 7.x / 17.x |
| **VM** | Debian/Ubuntu/Kali | 12 / 22.04 / 2024 |
| **Both** | Python | 3.9+ |

---

## Part 1: Sensor Deployment (Linux)

### Option A: Automated Setup (Recommended)

```bash
# Clone repository
git clone https://github.com/Anduong1200/sentinel-netlab.git
cd sentinel-netlab

# Run automated setup
sudo ./scripts/setup_vm.sh
```

**The script will:**
1. Install system dependencies (tshark, aircrack-ng, libpcap)
2. Create Python virtual environment at `/opt/sentinel-netlab/venv`
3. Install all Python packages from requirements.txt
4. Configure systemd service (optional)

### Option B: Manual Setup

```bash
# Install dependencies
sudo apt update
sudo apt install -y python3-pip python3-venv tshark aircrack-ng

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python packages
pip install -r sensor/requirements.txt
```

### Start the Sensor

```bash
# Activate environment
source /opt/sentinel-netlab/venv/bin/activate

# Start API server
cd sensor
sudo python3 api_server.py

# Or use systemd
sudo systemctl start wifi-scanner
```

### Verify Installation

```bash
curl http://localhost:5000/health
# Expected: {"status": "ok", "timestamp": "..."}
```

---

## Part 2: Controller Setup (Windows)

### Install Dependencies

```powershell
cd D:\path\to\sentinel-netlab\controller
pip install -r requirements.txt
```

### Launch GUI

```powershell
python scanner_gui.py
```

### Connect to Sensor

1. Enter sensor IP address (e.g., `192.168.56.101`)
2. Enter API key (default: `sentinel-dev-2024`)
3. Click **Connect**
4. Status indicator turns green when connected

---

## Part 3: USB WiFi Adapter Configuration

### VirtualBox Setup

1. Install **VirtualBox Extension Pack**
2. VM Settings → USB → Enable **USB 3.0 (xHCI) Controller**
3. Add USB Device Filter:
   - Vendor ID: `0cf3` (Atheros)
   - Product ID: `9271`
4. Start VM → Devices → USB → Select your adapter

### VMware Setup

1. VM Settings → USB Controller → **USB 3.1**
2. Start VM → VM → Removable Devices → Connect USB WiFi

### Verify in Linux

```bash
# Check USB device
lsusb | grep -i atheros

# Check wireless interface
iw dev
# Expected: wlan0 or wlan1

# Check monitor mode support
iw phy phy0 info | grep monitor
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WIFI_SCANNER_API_KEY` | `sentinel-dev-2024` | API authentication key |
| `WIFI_SCANNER_INTERFACE` | `wlan0` | Wireless interface name |
| `WIFI_SCANNER_MOCK_MODE` | `false` | Enable simulation mode |
| `ALLOW_ACTIVE_ATTACKS` | `false` | Enable deauth/injection |

**Example:**
```bash
export WIFI_SCANNER_API_KEY="my-secure-key-2024"
export WIFI_SCANNER_INTERFACE="wlan1"
python3 api_server.py
```

---

## Troubleshooting

### Interface Not Found

```bash
# Check if driver is loaded
lsmod | grep ath9k_htc

# Reload driver
sudo modprobe -r ath9k_htc
sudo modprobe ath9k_htc

# Check dmesg for errors
dmesg | tail -20
```

### Permission Denied

```bash
# Add user to wireshark group
sudo usermod -aG wireshark $USER

# Or grant capabilities
sudo setcap cap_net_raw,cap_net_admin+ep $(which python3)

# Log out and back in
```

### Connection Refused (Windows → Linux)

```bash
# Check firewall
sudo ufw allow 5000/tcp

# Check if API is running
ps aux | grep api_server

# Check network connectivity
ping <vm-ip>
```

---

## Next Steps

- [System Architecture](SYSTEM_DESIGN.md)
- [API Reference](api_reference.md)
- [Demo Runbook](demo_runbook.md)

---

*Last Updated: January 2026*

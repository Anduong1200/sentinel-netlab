# Installation Guide

Complete installation instructions for Sentinel NetLab on Linux systems.

## System Requirements

### Minimum Hardware
- CPU: ARM Cortex-A53 (Pi 3B+) or x86_64
- RAM: 1 GB
- Storage: 4 GB SD/SSD
- USB: 1 port for WiFi adapter

### Recommended Hardware
- CPU: ARM Cortex-A72 (Pi 4) or Intel i3+
- RAM: 2+ GB
- Storage: 16+ GB
- USB 3.0 for faster adapters

### Supported Operating Systems
- Debian 11/12
- Ubuntu 20.04/22.04/24.04
- Raspberry Pi OS (Bookworm)

---

## Installation Methods

### Method 1: Automated Setup (Recommended)

```bash
# Clone repository
git clone https://github.com/Anduong1200/sentinel-netlab.git
cd sentinel-netlab

# Run setup script
sudo ./scripts/setup.sh
```

The setup script will:
1. Install system dependencies
2. Create `sentinel` user and directories
3. Set up Python virtual environment
4. Install Python packages
5. Create default configuration
6. Install systemd service

### Method 2: Manual Installation

#### Step 1: Install System Packages

```bash
sudo apt update && sudo apt upgrade -y

sudo apt install -y \
    python3 python3-venv python3-pip \
    build-essential libpcap-dev libffi-dev libssl-dev \
    git wget curl jq \
    iproute2 iw rfkill wireless-tools
```

#### Step 2: Create User and Directories

```bash
# Create system user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin sentinel

# Create directories
sudo mkdir -p /opt/sentinel
sudo mkdir -p /etc/sentinel
sudo mkdir -p /var/lib/sentinel/journal

# Set permissions
sudo chown -R sentinel:sentinel /opt/sentinel /var/lib/sentinel
sudo chown -R root:sentinel /etc/sentinel
sudo chmod 750 /etc/sentinel
```

#### Step 3: Deploy Code

```bash
# Clone repository
sudo -u sentinel git clone https://github.com/Anduong1200/sentinel-netlab.git /opt/sentinel

# Create virtual environment
sudo -u sentinel python3 -m venv /opt/sentinel/venv

# Install dependencies
sudo -u sentinel /opt/sentinel/venv/bin/pip install --upgrade pip
sudo -u sentinel /opt/sentinel/venv/bin/pip install -r /opt/sentinel/sensor/requirements.txt
```

#### Step 4: Configure

```bash
# Copy example config
sudo cp /opt/sentinel/sensor/config.yaml /etc/sentinel/config.yaml
sudo chmod 640 /etc/sentinel/config.yaml
sudo chown root:sentinel /etc/sentinel/config.yaml

# Create environment file for secrets
cat << 'EOF' | sudo tee /etc/sentinel/env
BEARER_TOKEN=your-secure-token-here
EOF
sudo chmod 640 /etc/sentinel/env
sudo chown root:sentinel /etc/sentinel/env
```

#### Step 5: Install Service

```bash
# Install monitor mode helper
sudo cp /opt/sentinel/ops/systemd/sentinel-ensure-monitor-mode /usr/local/bin/
sudo chmod 755 /usr/local/bin/sentinel-ensure-monitor-mode

# Install systemd service
sudo cp /opt/sentinel/ops/systemd/sentinel-sensor@.service /etc/systemd/system/
sudo systemctl daemon-reload
```

---

## WiFi Adapter Setup

### Verify Adapter

```bash
# List USB devices
lsusb

# Check wireless interfaces
iw dev

# Verify monitor mode support
iw list | grep -A5 "Supported interface modes"
# Look for: * monitor
```

### Enable Monitor Mode

```bash
# Bring interface down
sudo ip link set wlan0 down

# Set monitor mode
sudo iw wlan0 set type monitor

# Bring interface up
sudo ip link set wlan0 up

# Verify
iw dev wlan0 info | grep type
# Should show: type monitor
```

### Driver Installation (if needed)

For RTL8812AU adapters:
```bash
sudo apt install dkms git
git clone https://github.com/aircrack-ng/rtl8812au.git
cd rtl8812au
sudo make dkms_install
```

---

## Starting the Service

### Enable and Start

```bash
# Enable service for interface wlan0
sudo systemctl enable --now sentinel-sensor@wlan0.service

# Check status
sudo systemctl status sentinel-sensor@wlan0.service

# View logs
sudo journalctl -u sentinel-sensor@wlan0.service -f
```

### Manual Start (Development)

```bash
cd /opt/sentinel/sensor

# With real adapter
sudo /opt/sentinel/venv/bin/python cli.py \
    --config /etc/sentinel/config.yaml \
    --iface wlan0

# Mock mode
/opt/sentinel/venv/bin/python cli.py \
    --sensor-id dev-01 \
    --iface mock0 \
    --mock-mode
```

---

## Verification

Run through the [Deployment Checklist](../operations/deployment.md) to verify installation:

- [ ] `sentinel` user exists
- [ ] Virtual environment created
- [ ] Configuration files present
- [ ] Service starts without errors
- [ ] Monitor mode active
- [ ] Logs show frame capture

---

## Next Steps

- [Configuration Reference](configuration.md)
- [Quick Start Tutorial](quickstart.md)
- [Hardware Compatibility](../operations/hardware.md)

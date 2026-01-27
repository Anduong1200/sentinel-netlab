#!/bin/bash
# ============================================================
# Sentinel NetLab - Debian Minimal Sensor Setup
# For Debian 12 "Netinst" (no GUI)
# Target: ~180MB RAM, ~2GB disk
# ============================================================

set -e

echo "=============================================="
echo "  Sentinel NetLab - Debian Minimal Setup"
echo "=============================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo)"
    exit 1
fi

# ============================================================
# 1. System Update
# ============================================================
echo "[1/8] Updating system..."
apt update && apt upgrade -y

# ============================================================
# 2. Install Core Dependencies
# ============================================================
echo "[2/8] Installing core dependencies..."
apt install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    git \
    curl \
    wget \
    ca-certificates

# ============================================================
# 3. Install Wireless Tools
# ============================================================
echo "[3/8] Installing wireless tools..."
apt install -y --no-install-recommends \
    wireless-tools \
    iw \
    aircrack-ng \
    tshark \
    tcpdump \
    net-tools \
    pciutils \
    usbutils

# ============================================================
# 4. Install Firmware (for USB adapters)
# ============================================================
echo "[4/8] Installing wireless firmware..."
apt install -y --no-install-recommends \
    firmware-atheros \
    firmware-realtek \
    firmware-misc-nonfree 2>/dev/null || true

# ============================================================
# 5. Create Sensor User
# ============================================================
echo "[5/8] Creating sensor user..."
if ! id "sensor" &>/dev/null; then
    useradd -m -s /bin/bash sensor
    usermod -aG sudo sensor
    echo "sensor ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/sensor
fi

# ============================================================
# 6. Setup Python Environment
# ============================================================
echo "[6/8] Setting up Python environment..."
mkdir -p /opt/sentinel-netlab
cd /opt/sentinel-netlab

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python packages
pip install --upgrade pip
pip install \
    flask \
    flask-cors \
    flask-limiter \
    scapy \
    requests \
    gunicorn

# ============================================================
# 7. Clone/Copy Sensor Code
# ============================================================
echo "[7/8] Setting up sensor code..."
cat > /opt/sentinel-netlab/requirements.txt << 'EOF'
flask>=2.0.0
flask-cors>=3.0.0
flask-limiter>=2.0.0
scapy>=2.5.0
requests>=2.25.0
gunicorn>=20.0.0
EOF

# Create systemd service
cat > /etc/systemd/system/sentinel-sensor.service << 'EOF'
[Unit]
Description=Sentinel NetLab WiFi Sensor
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/sentinel-netlab/sensor
Environment="WIFI_SCANNER_INTERFACE=wlan0"
Environment="WIFI_SCANNER_API_KEY=sentinel-2024"
ExecStart=/opt/sentinel-netlab/venv/bin/python sensor_cli.py \
    --engine tshark \
    --buffered-storage \
    --watchdog \
    --api \
    --interface wlan0
Restart=always
RestartSec=5

# Performance tuning
Nice=-10
IOSchedulingClass=realtime
IOSchedulingPriority=0

[Install]
WantedBy=multi-user.target
EOF

# ============================================================
# 8. System Optimization
# ============================================================
echo "[8/8] Applying system optimizations..."

# Disable unnecessary services
systemctl disable --now bluetooth 2>/dev/null || true
systemctl disable --now cups 2>/dev/null || true
systemctl disable --now avahi-daemon 2>/dev/null || true
systemctl disable --now ModemManager 2>/dev/null || true

# Optimize kernel parameters
cat > /etc/sysctl.d/99-sentinel.conf << 'EOF'
# Network buffers
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.netdev_max_backlog = 5000

# Reduce disk sync frequency
vm.dirty_ratio = 60
vm.dirty_background_ratio = 30

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF
sysctl -p /etc/sysctl.d/99-sentinel.conf

# Create helper scripts
mkdir -p /usr/local/bin

# Start sensor script
cat > /usr/local/bin/sensor-start << 'EOF'
#!/bin/bash
cd /opt/sentinel-netlab/sensor
source ../venv/bin/activate
sudo python sensor_cli.py --engine tshark --buffered-storage --watchdog --api "$@"
EOF
chmod +x /usr/local/bin/sensor-start

# Status script
cat > /usr/local/bin/sensor-status << 'EOF'
#!/bin/bash
curl -s http://localhost:5000/status | python3 -m json.tool
EOF
chmod +x /usr/local/bin/sensor-status

# Monitor mode script
cat > /usr/local/bin/monitor-mode << 'EOF'
#!/bin/bash
IFACE=${1:-wlan0}
echo "Enabling monitor mode on $IFACE..."
sudo ip link set $IFACE down
sudo iw dev $IFACE set type monitor
sudo ip link set $IFACE up
echo "Done. Verify with: iw dev $IFACE info"
EOF
chmod +x /usr/local/bin/monitor-mode

echo ""
echo "=============================================="
echo "  Setup Complete!"
echo "=============================================="
echo ""
echo "Next steps:"
echo "  1. Copy sensor code to /opt/sentinel-netlab/sensor/"
echo "  2. Enable service: sudo systemctl enable sentinel-sensor"
echo "  3. Start service: sudo systemctl start sentinel-sensor"
echo ""
echo "Quick commands:"
echo "  sensor-start    - Start sensor manually"
echo "  sensor-status   - Check sensor status"
echo "  monitor-mode    - Enable monitor mode"
echo ""
echo "Memory usage: $(free -h | grep Mem | awk '{print $3}') / $(free -h | grep Mem | awk '{print $2}')"

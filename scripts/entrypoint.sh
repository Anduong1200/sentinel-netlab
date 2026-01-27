#!/bin/sh
# ============================================================
# Sentinel NetLab - Docker Entrypoint
# ============================================================

set -e

echo "=============================================="
echo "  Sentinel NetLab Sensor (Alpine)"
echo "=============================================="

# Check for wireless interface
if [ ! -d "/sys/class/net/${WIFI_SCANNER_INTERFACE}" ]; then
    echo "WARNING: Interface ${WIFI_SCANNER_INTERFACE} not found"
    echo "Available interfaces:"
    ls /sys/class/net/
    echo ""
    echo "Make sure to run with: --privileged --net=host"
fi

# Enable monitor mode if interface exists
if [ -d "/sys/class/net/${WIFI_SCANNER_INTERFACE}" ]; then
    echo "Enabling monitor mode on ${WIFI_SCANNER_INTERFACE}..."
    ip link set ${WIFI_SCANNER_INTERFACE} down 2>/dev/null || true
    iw dev ${WIFI_SCANNER_INTERFACE} set type monitor 2>/dev/null || true
    ip link set ${WIFI_SCANNER_INTERFACE} up 2>/dev/null || true
fi

echo ""
echo "Configuration:"
echo "  Interface: ${WIFI_SCANNER_INTERFACE}"
echo "  Engine: ${CAPTURE_ENGINE}"
echo "  API Key: ${WIFI_SCANNER_API_KEY:0:10}..."
echo "  Active Attacks: ${ALLOW_ACTIVE_ATTACKS}"
echo ""

# Start sensor
cd /opt/sensor/sensor
exec python sensor_cli.py \
    --interface ${WIFI_SCANNER_INTERFACE} \
    "$@"

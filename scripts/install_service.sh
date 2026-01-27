#!/bin/bash
# ============================================================
# Sentinel NetLab - Install Systemd Service
# ============================================================

set -e

SERVICE_NAME="wifi-scanner.service"
SRC_PATH="$(dirname "$0")/../ops/systemd/$SERVICE_NAME"
DEST_PATH="/etc/systemd/system/$SERVICE_NAME"

echo "================================"
echo "  Installing WiFi Scanner Service"
echo "================================"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root (sudo)"
    exit 1
fi

# Check source file
if [ ! -f "$SRC_PATH" ]; then
    echo "❌ Service file not found at: $SRC_PATH"
    echo "   Make sure you're running from the scripts/ directory"
    exit 1
fi

echo "📁 Source: $SRC_PATH"
echo "📁 Destination: $DEST_PATH"

# Install
echo ""
echo "➜ Copying service file..."
cp "$SRC_PATH" "$DEST_PATH"
chmod 644 "$DEST_PATH"
echo "✔ Service file installed"

echo ""
echo "➜ Reloading systemd daemon..."
systemctl daemon-reload
echo "✔ Daemon reloaded"

echo ""
echo "➜ Enabling service..."
systemctl enable $SERVICE_NAME
echo "✔ Service enabled (will start on boot)"

echo ""
echo "➜ Starting service..."
systemctl start $SERVICE_NAME
echo "✔ Service started"

echo ""
echo "================================"
echo "  Status:"
echo "================================"
systemctl status $SERVICE_NAME --no-pager || true

echo ""
echo "✅ Installation complete!"
echo ""
echo "Useful commands:"
echo "  sudo systemctl status $SERVICE_NAME"
echo "  sudo systemctl restart $SERVICE_NAME"
echo "  sudo journalctl -u $SERVICE_NAME -f"

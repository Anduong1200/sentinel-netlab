#!/bin/bash
# Script to install and enable the WiFi Scanner systemd service

SERVICE_NAME="wifi-scanner.service"
SRC_PATH="../sensor/wifi-scanner.service"
DEST_PATH="/etc/systemd/system/$SERVICE_NAME"

# Check root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

if [ ! -f "$SRC_PATH" ]; then
    echo "Service file not found at $SRC_PATH"
    exit 1
fi

echo "Installing $SERVICE_NAME..."
cp "$SRC_PATH" "$DEST_PATH"
chmod 644 "$DEST_PATH"

echo "Reloading systemd daemon..."
systemctl daemon-reload

echo "Enabling service..."
systemctl enable $SERVICE_NAME

echo "Starting service..."
systemctl start $SERVICE_NAME

echo "Status:"
systemctl status $SERVICE_NAME --no-pager

echo "Done."

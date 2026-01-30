#!/bin/bash
# ============================================================
# Sentinel NetLab - Upgrade Script
# Updates sensor code and dependencies
# ============================================================

set -e

INSTALL_DIR="/opt/sentinel"
BACKUP_DIR="/opt/sentinel-backup-$(date +%Y%m%d_%H%M%S)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check root
if [ "$EUID" -ne 0 ]; then
    log_error "Please run as root (sudo ./upgrade.sh)"
    exit 1
fi

echo "============================================"
echo "  Sentinel NetLab - Upgrade"
echo "============================================"
echo ""

# Stop service
log_info "Stopping sensor service..."
systemctl stop sentinel-sensor.service 2>/dev/null || true
systemctl stop 'sentinel-sensor@*.service' 2>/dev/null || true

# Backup current installation
log_info "Creating backup at $BACKUP_DIR..."
cp -r "$INSTALL_DIR" "$BACKUP_DIR"

# Pull updates
log_info "Pulling latest code..."
sudo -u sentinel git -C "$INSTALL_DIR" fetch origin
sudo -u sentinel git -C "$INSTALL_DIR" pull origin main

# Update dependencies
log_info "Updating Python dependencies..."
sudo -u sentinel "$INSTALL_DIR/venv/bin/pip" install --upgrade pip
sudo -u sentinel "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" --upgrade

# Update helper script
log_info "Updating helper scripts..."
cp "$INSTALL_DIR/ops/systemd/sentinel-ensure-monitor-mode" /usr/local/bin/
chmod 755 /usr/local/bin/sentinel-ensure-monitor-mode

# Reload systemd
log_info "Reloading systemd..."
cp "$INSTALL_DIR/ops/systemd/sentinel-sensor@.service" /etc/systemd/system/
cp "$INSTALL_DIR/ops/systemd/sentinel-sensor.service" /etc/systemd/system/
systemctl daemon-reload

# Restart service
log_info "Starting sensor service..."
systemctl start sentinel-sensor.service 2>/dev/null || \
    systemctl start sentinel-sensor@wlan0.service 2>/dev/null || \
    log_warn "No service to restart"

echo ""
echo -e "${GREEN}Upgrade complete!${NC}"
echo "Backup saved to: $BACKUP_DIR"
echo ""
echo "Check status: sudo systemctl status sentinel-sensor.service"

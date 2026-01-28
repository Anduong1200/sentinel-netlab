#!/bin/bash
###############################################################################
#  Sentinel NetLab - Unified VM Setup Script
#  Runs entirely in a SINGLE terminal window with progress tracking
###############################################################################

set -e  # Exit on error

# ─────────────────────────── Colors & Symbols ────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

OK="${GREEN}✔${NC}"
FAIL="${RED}✘${NC}"
ARROW="${CYAN}➜${NC}"
WARN="${YELLOW}⚠${NC}"

# ─────────────────────────── Helper Functions ────────────────────────────────
log_step() {
    echo -e "\n${ARROW} ${BOLD}$1${NC}"
}

log_ok() {
    echo -e "  ${OK} $1"
}

log_warn() {
    echo -e "  ${WARN} $1"
}

log_fail() {
    echo -e "  ${FAIL} $1"
}

spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    while ps -p $pid > /dev/null 2>&1; do
        for i in $(seq 0 9); do
            printf "\r  ${CYAN}${spinstr:$i:1}${NC} Installing..."
            sleep $delay
        done
    done
    printf "\r                    \r"
}

run_silent() {
    "$@" > /dev/null 2>&1
}

# ─────────────────────────── Pre-flight Checks ───────────────────────────────
clear
echo -e "${BOLD}${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         🛡️  SENTINEL NETLAB - VM SETUP WIZARD                 ║"
echo "║             Single-Window Unified Installer                   ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Root check
if [ "$EUID" -ne 0 ]; then
    log_fail "This script requires root privileges."
    echo -e "    Run: ${CYAN}sudo $0${NC}"
    exit 1
fi
log_ok "Running as root"

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_NAME="$NAME"
    log_ok "Detected OS: ${OS_NAME}"
else
    log_warn "Could not detect OS, assuming Debian-based"
    OS_NAME="Unknown"
fi

# ─────────────────────────── Step 1: System Packages ─────────────────────────
log_step "Step 1/5: Updating package lists..."
apt-get update -qq &
spinner $!
log_ok "Package lists updated"

log_step "Step 2/5: Installing system dependencies..."
PACKAGES=(
    python3
    python3-pip
    python3-venv
    aircrack-ng
    wireless-tools
    iw
    pciutils
    usbutils
    net-tools
    tshark
    curl
    git
)

for pkg in "${PACKAGES[@]}"; do
    if dpkg -s "$pkg" > /dev/null 2>&1; then
        log_ok "$pkg (already installed)"
    else
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg" > /dev/null 2>&1 && \
            log_ok "$pkg" || log_fail "$pkg (failed)"
    fi
done

# ─────────────────────────── Step 3: Python Environment ──────────────────────
log_step "Step 3/5: Setting up Python environment..."

VENV_PATH="/opt/sentinel-netlab/venv"
mkdir -p /opt/sentinel-netlab

if [ ! -d "$VENV_PATH" ]; then
    python3 -m venv "$VENV_PATH" && log_ok "Virtual environment created at $VENV_PATH"
else
    log_ok "Virtual environment exists"
fi

# Create data directories
mkdir -p /var/lib/wifi-scanner/pcaps
mkdir -p /etc/wifi-scanner
chmod 755 /var/lib/wifi-scanner
chmod 777 /var/lib/wifi-scanner/pcaps  # Allow writing
log_ok "Created data directories: /var/lib/wifi-scanner"

# Activate and install
source "$VENV_PATH/bin/activate"

log_step "Step 4/5: Installing Python packages..."
pip install --upgrade pip -q
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt -q && log_ok "requirements.txt installed"
else
    # Fallback if running from a detached script
    pip install . -q && log_ok "Package installed"
fi

# ─────────────────────────── Step 5: Configuration ───────────────────────────
log_step "Step 5/5: Final configuration..."

# Wireshark permissions for tshark
if getent group wireshark > /dev/null 2>&1; then
    usermod -aG wireshark "$SUDO_USER" 2>/dev/null && log_ok "Added $SUDO_USER to wireshark group"
fi

# Firmware check
if [ -d "/lib/firmware/ath9k_htc" ]; then
    log_ok "Atheros firmware present"
else
    log_warn "Atheros firmware not found (install firmware-atheros if using AR9271)"
fi

# ─────────────────────────── Summary ─────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    ✅ SETUP COMPLETE!                         ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${BOLD}Quick Start:${NC}"
echo -e "  ${ARROW} Activate environment: ${CYAN}source /opt/sentinel-netlab/venv/bin/activate${NC}"
echo -e "  ${ARROW} Start API server:     ${CYAN}python sensor/api_server.py${NC}"
echo -e "  ${ARROW} Run diagnostics:      ${CYAN}python scripts/check_driver.py${NC}"
echo ""
echo -e "${YELLOW}Note: Log out and back in for group changes to take effect.${NC}"

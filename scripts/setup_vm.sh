#!/bin/bash
# automated setup script for WiFi Sensor VM (Kali/Ubuntu)

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}   WiFi Sensor VM Setup Script                ${NC}"
echo -e "${GREEN}==============================================${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root (sudo ./setup_vm.sh)${NC}"
  exit 1
fi

echo -e "${YELLOW}[*] Updating package lists...${NC}"
apt-get update

echo -e "${YELLOW}[*] Installing system dependencies...${NC}"
# aircrack-ng: for airmon-ng if needed
# wireless-tools: for iwconfig
# iw: for iw dev
# pciutils: for lspci
# usbutils: for lsusb
# net-tools: for ifconfig
# python3-pip: for python libs
apt-get install -y \
    python3 \
    python3-pip \
    aircrack-ng \
    wireless-tools \
    iw \
    pciutils \
    usbutils \
    net-tools \
    ufw \
    curl

echo -e "${YELLOW}[*] Installing Python libraries...${NC}"
# Install requirements directly
pip3 install flask flask-cors flask-limiter scapy requests pandas --break-system-packages

echo -e "${YELLOW}[*] Configuring Firewall (UFW)...${NC}"
# Allow API port
ufw allow 5000/tcp
echo -e "${GREEN}[+] Port 5000 allowed.${NC}"

# Optional: Enable ufw if not enabled (be careful not to lock out SSH)
# ufw enable

echo -e "${YELLOW}[*] Checking for Atheros Firmware...${NC}"
if [ ! -d "/lib/firmware/ath9k_htc" ]; then
    echo -e "${YELLOW}[!] Firmware directory /lib/firmware/ath9k_htc not found.${NC}"
    echo -e "${YELLOW}[*] Attempting to install firmware-atheros...${NC}"
    apt-get install -y firmware-atheros
else
    echo -e "${GREEN}[+] Firmware directory exists.${NC}"
fi

echo -e "${YELLOW}[*] Setting permissions...${NC}"
# Make diagnostic script executable if it exists
if [ -f "check_driver.py" ]; then
    chmod +x check_driver.py
    echo -e "${GREEN}[+] Made check_driver.py executable.${NC}"
fi

echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}   Setup Complete!                            ${NC}"
echo -e "${GREEN}==============================================${NC}"
echo -e "You can now run the sensor API:"
echo -e "  sudo python3 ../sensor/api_server.py"
echo -e ""
echo -e "Or run diagnostics:"
echo -e "  sudo python3 check_driver.py"

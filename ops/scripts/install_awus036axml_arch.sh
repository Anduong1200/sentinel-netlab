#!/usr/bin/env bash
# ==============================================================================
# ALFA AWUS036AXML (MT7921AUN) Arch Linux Installer
# Automatically installs required packages, enables services, and checks status.
# ==============================================================================

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo -e "${GREEN}[+] ALFA AWUS036AXML (MT7921AUN) Arch Linux Setup${NC}"
echo "============================================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Please run as root (use sudo)${NC}"
  exit 1
fi

echo -e "\n${YELLOW}[*] Step 1: Updating System & Installing Prerequisites${NC}"
pacman -Syu --noconfirm
pacman -S --needed --noconfirm \
  linux linux-headers linux-firmware \
  networkmanager iw wpa_supplicant usbutils ethtool \
  bluez bluez-utils

echo -e "\n${YELLOW}[*] Step 2: Enabling Services${NC}"
systemctl enable --now docker || true
systemctl enable --now NetworkManager || true
systemctl enable --now bluetooth || true

echo -e "\n${YELLOW}[*] Step 3: Probing Driver (mt7921u)${NC}"
modprobe mt7921u || echo -e "${RED}[!] Failed to probe mt7921u module. May need a reboot.${NC}"

echo -e "\n${YELLOW}[*] Step 4: System Diagnosis${NC}"
echo -e "${GREEN}--> Checking USB Devices (lsusb):${NC}"
lsusb | grep -i "MediaTek" || echo "No MediaTek device found via USB just yet."

echo -e "\n${GREEN}--> Checking Loaded Modules (lsmod | grep mt7921u):${NC}"
lsmod | grep mt7921u || echo "Module not currently loaded."

echo -e "\n${GREEN}--> Checking Network Interfaces (iw dev):${NC}"
iw dev

echo -e "\n============================================================"
echo -e "${GREEN}[+] Installation Completed!${NC}"
echo -e "If the Wi-Fi interface is not showing up, or the system was heavily updated, please reboot:"
echo -e "${YELLOW}sudo reboot${NC}"
echo ""
echo -e "If it still doesn't appear after a reboot, try running:"
echo -e "${YELLOW}sudo mkinitcpio -P && sudo reboot${NC}"
echo -e "============================================================"

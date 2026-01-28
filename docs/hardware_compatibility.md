# Hardware Compatibility Matrix

> Tested WiFi adapters for Sentinel NetLab monitor mode operation

---

## Recommended Adapters

### ⭐ Top Picks (Production Ready)

| Model | Chipset | Band | Monitor | Inject | Notes |
|-------|---------|------|---------|--------|-------|
| **Alfa AWUS036ACH** | RTL8812AU | 2.4/5 GHz | ✅ | ✅ | Best all-around, high power |
| **Alfa AWUS036NHA** | AR9271 | 2.4 GHz | ✅ | ✅ | Most reliable, atheros driver |
| **Panda PAU09** | MT7612U | 2.4/5 GHz | ✅ | ✅ | Good range, dual antenna |
| **TP-Link TL-WN722N v1** | AR9271 | 2.4 GHz | ✅ | ✅ | Budget friendly (v1 only!) |

### ✅ Tested Working

| Model | Chipset | Band | Monitor | Inject | Driver |
|-------|---------|------|---------|--------|--------|
| Alfa AWUS036AXML | MT7921AU | 2.4/5/6 GHz | ✅ | ✅ | mt76 |
| Alfa AWUS036ACM | MT7612U | 2.4/5 GHz | ✅ | ✅ | mt76 |
| Alfa AWUS036AC | RTL8812AU | 2.4/5 GHz | ✅ | ✅ | rtl8812au |
| Netgear A6210 | MT7612U | 2.4/5 GHz | ✅ | ⚠️ | mt76 |
| TP-Link Archer T2U Plus | RTL8821AU | 2.4/5 GHz | ✅ | ⚠️ | rtl8821au |

### ⚠️ Known Issues

| Model | Chipset | Issue |
|-------|---------|-------|
| TP-Link TL-WN722N **v2/v3** | RTL8188EUS | No monitor mode |
| Intel AX200/210 | Intel | Limited monitor, no inject |
| Realtek RTL8188 | Various | Unreliable monitor mode |
| Broadcom BCM43xx | Various | macOS only, limited Linux |

---

## Chipset Guide

### Atheros (Best Linux Support)
```
AR9271    - ath9k_htc driver (excellent)
AR9287    - ath9k driver
QCA9377   - ath10k (limited)
```

### MediaTek (Good Support)
```
MT7612U   - mt76 driver (good)
MT7921AU  - mt76 driver (WiFi 6)
```

### Realtek (Requires Extra Drivers)
```
RTL8812AU - rtl8812au (aircrack repo)
RTL8821AU - rtl8821au
RTL8814AU - rtl8814au
```

---

## Driver Installation

### Ubuntu/Debian

```bash
# Atheros (usually built-in)
sudo apt install linux-firmware

# MediaTek
sudo apt install linux-firmware

# Realtek RTL8812AU
sudo apt install dkms git
git clone https://github.com/aircrack-ng/rtl8812au.git
cd rtl8812au
sudo make dkms_install
```

### Raspberry Pi OS

```bash
# RTL8812AU
sudo apt install raspberrypi-kernel-headers dkms
git clone https://github.com/aircrack-ng/rtl8812au.git
cd rtl8812au
sed -i 's/CONFIG_PLATFORM_I386_PC = y/CONFIG_PLATFORM_I386_PC = n/' Makefile
sed -i 's/CONFIG_PLATFORM_ARM_RPI = n/CONFIG_PLATFORM_ARM_RPI = y/' Makefile
sudo make dkms_install
```

---

## Verification Commands

```bash
# List wireless interfaces
iw dev

# Check monitor mode support
iw list | grep -A 10 "Supported interface modes"

# Enable monitor mode
sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up

# Alternative (aircrack-ng)
sudo airmon-ng start wlan1

# Verify
iw dev wlan1 info | grep type  # Should show: type monitor

# Test capture
sudo tcpdump -i wlan1mon -c 10
```

---

## Platform Compatibility

| Platform | Status | Notes |
|----------|--------|-------|
| Ubuntu 22.04 | ✅ | Recommended |
| Raspberry Pi OS (64-bit) | ✅ | Use Pi 4 |
| Kali Linux | ✅ | Pre-installed drivers |
| Debian 12 | ✅ | Similar to Ubuntu |
| Fedora 38+ | ⚠️ | May need manual drivers |
| macOS | ⚠️ | Limited to system WiFi |
| Windows | ❌ | No native monitor mode |

---

## Purchasing Links

- [Alfa Network Store](https://www.alfa.com.tw/)
- [Amazon (search chipset)](https://amazon.com)
- [Hak5 Shop](https://shop.hak5.org/)

---

## FAQ

**Q: Why won't my adapter enter monitor mode?**
A: Check driver compatibility. Use `lsusb` to find chipset, verify against matrix.

**Q: Adapter works but no frames captured?**
A: Verify channel. Some adapters need firmware: `sudo apt install linux-firmware`

**Q: RTL8812AU not detected after reboot?**
A: DKMS may need rebuild: `sudo dkms autoinstall`

---

*Last Updated: January 28, 2026*

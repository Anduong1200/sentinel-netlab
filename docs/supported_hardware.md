# Sentinel NetLab - Supported Hardware

## WiFi Adapters for Monitor Mode

### ✅ Fully Tested & Recommended

| Adapter | Chipset | Driver | Notes |
|---------|---------|--------|-------|
| Alfa AWUS036ACH | RTL8812AU | rtl8812au | Dual-band, high power, excellent range |
| Alfa AWUS036ACS | RTL8811AU | rtl8811au | 2x2 MIMO, compact form factor |
| Panda PAU09 | RT5572 | rt2800usb | Native Linux support, no extra drivers |
| TP-Link TL-WN722N v1 | AR9271 | ath9k_htc | Only v1! Later versions use different chipset |

### ⚠️ Tested with Caveats

| Adapter | Chipset | Issue |
|---------|---------|-------|
| TP-Link TL-WN722N v2/v3 | RTL8188EUS | Requires patched driver |
| Realtek RTL8188FU | RTL8188FU | Poor range in monitor mode |

### ❌ Not Recommended

| Adapter | Reason |
|---------|--------|
| Intel AX200/AX210 | Monitor mode unreliable on Linux |
| Broadcom BCM43xx | Complex driver situation |

---

## Single-Board Computers

### ✅ Recommended

| Device | Notes |
|--------|-------|
| Raspberry Pi 4B (2GB+) | Primary development platform |
| Raspberry Pi 3B+ | Adequate for basic capture |
| Orange Pi 5 | Higher performance alternative |

### Performance Guidelines

| Device | Max recommended capture load |
|--------|------------------------------|
| Pi 4 (4GB) | 500 frames/sec |
| Pi 3B+ | 200 frames/sec |
| Pi Zero W | Not recommended |

---

## Driver Installation

### RTL8812AU (Alfa AWUS036ACH)

```bash
# Ubuntu/Debian
sudo apt install dkms git
git clone https://github.com/aircrack-ng/rtl8812au.git
cd rtl8812au
sudo make dkms_install

# Enable monitor mode
sudo ip link set wlan0 down
sudo iw wlan0 set type monitor
sudo ip link set wlan0 up
```

### Atheros AR9271 (TP-Link TL-WN722N v1)

```bash
# Built-in driver, no installation needed
sudo ip link set wlan0 down
sudo iw wlan0 set type monitor
sudo ip link set wlan0 up
```

---

## Testing Your Adapter

```bash
# Check if monitor mode is supported
sudo iw list | grep -A5 "Supported interface modes"

# Should show:
#   * monitor

# Test channel switching
sudo iw wlan0 set channel 6
sudo iw wlan0 set channel 11

# Test packet capture
sudo tcpdump -i wlan0 -c 10
```

---

## Known Issues

### Issue: RTL8812AU doesn't see 5GHz networks
**Solution**: Some regions require regulatory domain setting:
```bash
sudo iw reg set US
```

### Issue: Channel hopping causes packet loss
**Solution**: Increase dwell time in config:
```yaml
capture:
  dwell_ms: 300  # Increase from default 200
```

### Issue: High CPU usage during capture
**Solution**: Use tshark engine instead of scapy:
```yaml
capture:
  method: tshark
```

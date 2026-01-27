# Hardware Compatibility

Tested hardware and driver requirements for Sentinel NetLab sensor nodes.

---

## WiFi Adapters

### ✅ Recommended

| Adapter | Chipset | Driver | Band | Notes |
|---------|---------|--------|------|-------|
| **Alfa AWUS036ACH** | RTL8812AU | rtl8812au | 2.4/5 GHz | Best overall, high TX power |
| **Alfa AWUS036ACS** | RTL8811AU | rtl8811au | 2.4/5 GHz | Compact, 2x2 MIMO |
| **Panda PAU09** | RT5572 | rt2800usb | 2.4/5 GHz | Native Linux support |
| **TP-Link TL-WN722N v1** | AR9271 | ath9k_htc | 2.4 GHz | Budget option (v1 only!) |

### ⚠️ Limited Support

| Adapter | Chipset | Issue |
|---------|---------|-------|
| TP-Link TL-WN722N v2/v3 | RTL8188EUS | Requires patched driver |
| Generic RTL8188FU | RTL8188FU | Poor range in monitor mode |

### ❌ Not Recommended

| Adapter | Reason |
|---------|--------|
| Intel AX200/AX210 | Unreliable monitor mode on Linux |
| Broadcom BCM43xx | Complex driver situation |
| Built-in laptop WiFi | Usually cannot do monitor mode |

---

## Single-Board Computers

### ✅ Recommended

| Device | RAM | Notes |
|--------|-----|-------|
| **Raspberry Pi 4B** | 4GB | Primary development platform |
| **Raspberry Pi 4B** | 2GB | Adequate for single sensor |
| **Raspberry Pi 3B+** | 1GB | Basic capture only |
| **Orange Pi 5** | 8GB | High-performance option |

### Performance Estimates

| Device | Max Frame Rate | Memory Usage |
|--------|----------------|--------------|
| Pi 4 (4GB) | ~500 fps | ~200 MB |
| Pi 4 (2GB) | ~500 fps | ~150 MB |
| Pi 3B+ | ~200 fps | ~100 MB |
| Pi Zero W | Not recommended | - |

---

## Driver Installation

### RTL8812AU (Alfa AWUS036ACH)

```bash
# Install build tools
sudo apt install -y dkms git build-essential

# Clone and install driver
git clone https://github.com/aircrack-ng/rtl8812au.git
cd rtl8812au
sudo make dkms_install

# Verify
modinfo 88XXau
```

### RTL8188EUS (TL-WN722N v2/v3)

```bash
git clone https://github.com/aircrack-ng/rtl8188eus.git
cd rtl8188eus
sudo make dkms_install
```

### Atheros AR9271 (TL-WN722N v1)

No installation needed - uses built-in `ath9k_htc` driver.

---

## Power Requirements

### USB Power Considerations

High-power adapters (like AWUS036ACH) may require:
- Powered USB hub
- USB Y-cable for supplemental power
- Pi 4 with 3A power supply

### Symptoms of Insufficient Power

- Adapter disconnects during TX
- `dmesg` shows USB reset errors
- Inconsistent frame capture

---

## Verification Commands

```bash
# List USB devices
lsusb

# Check wireless interfaces
iw dev

# Verify monitor mode support
iw list | grep -A10 "Supported interface modes"

# Test channel switching
sudo iw wlan0 set channel 6
sudo iw wlan0 set channel 11

# Test capture (should see output)
sudo tcpdump -i wlan0 -c 10 type mgt
```

---

## Known Issues

### RTL8812AU: No 5GHz networks visible
**Solution**: Set regulatory domain
```bash
sudo iw reg set US
```

### Channel hopping causes packet loss
**Solution**: Increase dwell time
```yaml
capture:
  dwell_ms: 300  # Default is 200
```

### High CPU during capture
**Solution**: Use tshark instead of scapy
```yaml
capture:
  method: tshark
```

### USB disconnects under load
**Solution**: Use powered USB hub or reduce TX power

---

## Testing Procedure

1. **Physical Check**: Verify adapter LED activity
2. **USB Check**: `lsusb` shows device
3. **Driver Check**: `iw dev` shows interface
4. **Mode Check**: Can set monitor mode
5. **Capture Check**: `tcpdump` shows frames
6. **Hop Check**: Channel switching works

Document results in deployment checklist.

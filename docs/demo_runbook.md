# Demo Runbook

> Step-by-step guide for demonstrating Sentinel NetLab

---

## 🎯 Demo Objectives

1. Show sensor capturing WiFi networks
2. Demonstrate controller GUI functionality
3. Display risk scoring in action
4. Export and verify data
5. (Optional) Show active attack capabilities

---

## ⏱️ Estimated Time: 10-15 minutes

---

## 📋 Pre-Demo Checklist

### Hardware
- [ ] Laptop with VM ready
- [ ] USB WiFi adapter (AR9271 recommended)
- [ ] Power adapter connected

### Software
- [ ] VM booted and sensor installed
- [ ] Controller GUI ready on Windows
- [ ] Terminal windows open
- [ ] Wireshark installed

### Environment
- [ ] WiFi networks visible in area (at least 3-5)
- [ ] No security restrictions blocking monitor mode
- [ ] Network owner consent (if in office/lab)

---

## 🚀 Demo Steps

### Step 1: Verify Environment (2 min)

```bash
# On Linux VM

# 1. Check USB adapter connection
lsusb | grep -i wireless
# Expected: Shows adapter (e.g., "Atheros Communications")

# 2. Check interface
iw dev
# Expected: Shows wlan0 or similar

# 3. Run driver check
python scripts/check_driver.py
# Expected: All checks PASS
```

**Script output to show**:
```
✅ Interface wlan0 found
✅ Monitor mode supported
✅ Injection supported
```

---

### Step 2: Start Sensor (2 min)

```bash
# Option A: Using CLI
cd /opt/sentinel-netlab/sensor
sudo python sensor_cli.py \
    --engine tshark \
    --buffered-storage \
    --api \
    --verbose

# Option B: Using systemd
sudo systemctl start sentinel-sensor
sudo systemctl status sentinel-sensor
```

**Expected output**:
```
==========================================================
  Sentinel NetLab - Sensor CLI
==========================================================
Interface: wlan0
Engine: tshark
API server started on http://0.0.0.0:5000
----------------------------------------------------------
📶 NetworkA              | AA:BB:CC:DD:EE:FF | Risk: 45
📶 CoffeeShop_WiFi       | 11:22:33:44:55:66 | Risk: 72
...
```

---

### Step 3: Verify API (1 min)

```bash
# Health check
curl http://localhost:5000/health
# {"status": "ok"}

# Get networks
curl http://localhost:5000/networks | python -m json.tool
# Shows JSON with detected networks

# Get status
curl http://localhost:5000/status | python -m json.tool
# Shows sensor status
```

---

### Step 4: Launch Controller GUI (2 min)

```powershell
# On Windows host
cd D:\hod_lab\controller
python scanner_gui.py
```

**GUI Demo Points**:
1. Show connection to sensor (green status)
2. Click "Start Scan" - networks populate
3. Sort by Risk Score column
4. Select high-risk network - show details
5. Click "Risk Report" - show popup

---

### Step 5: Export Data (1 min)

1. In GUI, click "Export CSV"
2. Save file
3. Open in Excel/Notepad - show columns:
   - SSID, BSSID, Channel, RSSI, Encryption, Risk Score

```powershell
# Verify CSV
type networks_export.csv
```

---

### Step 6: Show PCAP in Wireshark (2 min)

```bash
# On Linux VM
ls -la /tmp/captures/
# Show PCAP files with rotation

# Open in Wireshark (if GUI available)
wireshark /tmp/captures/latest.pcap &
```

**Wireshark Demo Points**:
1. Show Beacon frames
2. Show Probe Requests
3. Filter: `wlan.fc.type_subtype == 8` (Beacons)
4. Point out SSID, BSSID, Channel fields

---

### Step 7: Run Evaluation Tests (3 min)

```bash
# Recall test (pre-recorded)
python tests/compare_recall.py \
    artifacts/gt_output.csv \
    artifacts/poc.json

# Show results
cat artifacts/recall_report.txt
# Expected: Recall >= 80%

# Latency test (quick)
python tests/test_latency.py -n 10

# Show results
# Expected: avg < 1000ms
```

---

### Step 8: (Optional) Active Attack Demo (3 min)

⚠️ **Only in authorized lab environment**

```bash
# Enable active attacks
export ALLOW_ACTIVE_ATTACKS=true

# Deauth test (single packet)
curl -X POST http://localhost:5000/attack/deauth \
    -H "X-API-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"bssid": "AA:BB:CC:DD:EE:FF", "count": 1}'

# Show forensics events
curl http://localhost:5000/forensics/events
```

---

## 🎥 Video Recording Tips

If recording demo video:

1. **Resolution**: 1920x1080 minimum
2. **Duration**: Max 5 minutes
3. **Audio**: Narrate each step
4. **Terminal**: Increase font size
5. **Highlight**: Use mouse pointer to highlight

### Recording Script (Linux)

```bash
# Install recordmydesktop or OBS
# Start recording before demo
recordmydesktop --no-sound -o demo.ogv

# After demo, convert to MP4
ffmpeg -i demo.ogv -c:v libx264 demo_video.mp4
```

---

## ❓ Common Demo Issues & Solutions

### "No networks found"

```bash
# Check monitor mode
iw dev wlan0 info | grep type
# Should show: type monitor

# Re-enable monitor mode
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

### "Connection refused" on API

```bash
# Check if sensor is running
ps aux | grep sensor

# Check port
netstat -tlnp | grep 5000
```

### "USB adapter disconnected"

```bash
# Check USB
lsusb

# Reload driver
sudo modprobe -r ath9k_htc
sudo modprobe ath9k_htc
```

---

## 📊 Demo Metrics to Highlight

| Metric | Target | Your Value |
|--------|--------|------------|
| Networks detected | ≥5 | ____ |
| Recall | ≥80% | ____% |
| API latency | <1s | ____ms |
| Memory usage | <500MB | ____MB |
| Capture engine | tshark | ✓ |

---

## 🏁 Post-Demo

1. Stop sensor: `Ctrl+C` or `sudo systemctl stop sentinel-sensor`
2. Save any generated files
3. Take screenshots for report
4. Answer Q&A

---

*Good luck with your demo!*

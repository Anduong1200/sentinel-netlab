# Demo Runbook

> Step-by-step guide for demonstrating Sentinel NetLab

---

## 🎯 Demo Objectives

1. Show sensor capturing WiFi networks
2. Demonstrate controller GUI functionality
3. Display risk scoring in action
4. Export and verify data

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
- [ ] Terminal window open

### Environment
- [ ] WiFi networks visible in area (at least 3-5)
- [ ] Network owner consent (if in office/lab)

---

## 🚀 Demo Steps

### Step 1: Verify Environment (2 min)

```bash
# On Linux VM

# 1. Check USB adapter connection
lsusb | grep -i wireless

# 2. Check interface
iw dev

# 3. Run driver check
python3 scripts/check_driver.py
```

---

### Step 2: Start Sensor (2 min)

```bash
# Activate virtual environment
source /opt/sentinel-netlab/venv/bin/activate

# Start sensor API
cd sensor
sudo python3 api_server.py
```

**Expected output**:
```
 * Running on http://0.0.0.0:5000
```

---

### Step 3: Verify API (1 min)

```bash
# Health check
curl http://localhost:5000/health

# Get networks
curl http://localhost:5000/networks | python3 -m json.tool

# Get status
curl http://localhost:5000/status
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

---

### Step 5: Export Data (1 min)

1. In GUI, click "Export CSV"
2. Save file
3. Open in Excel/Notepad

---

### Step 6: Run Tests (Optional, 2 min)

```bash
# Recall test
python3 tests/compare_recall.py artifacts/gt_output.csv artifacts/poc.json

# Latency test
python3 tests/test_latency.py -n 10
```

---

## ❓ Common Demo Issues

### "No networks found"
```bash
# Re-enable monitor mode
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

### "Connection refused"
```bash
# Check if sensor is running
ps aux | grep api_server
```

---

## 📊 Metrics to Highlight

| Metric | Target |
|--------|--------|
| Networks detected | ≥5 |
| API latency | <1s |
| Memory usage | <500MB |

---

## 🏁 Post-Demo

1. Stop sensor: `Ctrl+C`
2. Answer Q&A

---

*Good luck with your demo!*

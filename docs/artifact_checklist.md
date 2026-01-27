# Artifact Submission Checklist

> Complete list of artifacts required for thesis defense

---

## ✅ Checklist

### Core Artifacts

- [ ] **poc.json** - Sample `/scan` API output
  - Location: `artifacts/poc.json`
  - Content: JSON array of detected networks
  - How to generate: `curl http://localhost:5000/networks > artifacts/poc.json`

- [ ] **gt_output.csv** - Ground truth from airodump-ng
  - Location: `artifacts/gt_output.csv`
  - Content: CSV from airodump-ng scan
  - How to generate: `airodump-ng wlan0 -w gt_output --output-format csv`

- [ ] **recall_report.txt** - Recall comparison results
  - Location: `artifacts/recall_report.txt`
  - Content: Precision/Recall metrics
  - How to generate: `python tests/compare_recall.py artifacts/gt_output.csv artifacts/poc.json -o artifacts/recall_report.txt`

- [ ] **sample.pcap** - Sample packet capture
  - Location: `artifacts/sample.pcap`
  - Content: PCAP file openable in Wireshark
  - How to generate: `tshark -i wlan0 -w artifacts/sample.pcap -a duration:60`

### Driver & System Verification

- [ ] **check_driver_output.txt** - Driver verification
  - Location: `artifacts/check_driver_output.txt`
  - How to generate: `python scripts/check_driver.py > artifacts/check_driver_output.txt`

- [ ] **iw_dev.txt** - Wireless interface info
  - Location: `artifacts/iw_dev.txt`
  - How to generate: `iw dev > artifacts/iw_dev.txt`

### Service Configuration

- [ ] **wifi-scanner.service** - Systemd service file
  - Location: `artifacts/wifi-scanner.service`
  - Verification: Should show non-root user or capability-based

- [ ] **config.example.json** - Example configuration
  - Location: `artifacts/config.example.json`
  - Verification: No actual secrets

- [ ] **.gitignore** - Ensures no secrets committed
  - Location: `.gitignore`
  - Verification: Contains `*.key`, `*.pem`, `config.json`

### Test Reports

- [ ] **latency_report.txt** - API latency test results
  - Location: `artifacts/latency_report.txt`
  - How to generate: `python tests/test_latency.py -o artifacts/latency_report.txt`

- [ ] **stability_report.txt** - Stability test results
  - Location: `artifacts/stability_report.txt`
  - How to generate: `python tests/test_stability.py -d 30 -o artifacts/stability_report.txt`

### Setup & Documentation

- [ ] **setup_vm.sh / setup_debian_minimal.sh** - VM setup script
  - Location: `scripts/setup_debian_minimal.sh`
  
- [ ] **demo_runbook.md** - Step-by-step demo guide
  - Location: `docs/demo_runbook.md`

- [ ] **check_driver.py** - Driver verification script
  - Location: `scripts/check_driver.py`

### Legal & Ethics

- [ ] **legal_ethics.md** - Consent form + legal notes
  - Location: `docs/legal_ethics.md`
  - Must contain: Consent form template, legal warnings

### Presentation Materials

- [ ] **report.pdf** - Technical report
  - Location: `docs/technical_report.pdf`

- [ ] **slides.pptx** - Presentation slides
  - Location: `artifacts/slides.pptx`

- [ ] **demo_video.mp4** - Demo video (≤5 min)
  - Location: `artifacts/demo_video.mp4`
  - Content: End-to-end workflow demonstration

---

## 📁 Recommended Directory Structure

```
sentinel-netlab/
├── artifacts/                    # Submission artifacts
│   ├── poc.json
│   ├── gt_output.csv
│   ├── recall_report.txt
│   ├── latency_report.txt
│   ├── stability_report.txt
│   ├── sample.pcap
│   ├── check_driver_output.txt
│   ├── iw_dev.txt
│   ├── wifi-scanner.service
│   ├── config.example.json
│   ├── slides.pptx
│   └── demo_video.mp4
├── docs/
│   ├── technical_report.md
│   ├── legal_ethics.md
│   ├── evaluation_rubric.md
│   ├── demo_runbook.md
│   └── ...
├── scripts/
│   ├── setup_debian_minimal.sh
│   ├── check_driver.py
│   └── ...
├── sensor/
│   └── ...
├── controller/
│   └── ...
├── tests/
│   ├── compare_recall.py
│   ├── test_latency.py
│   ├── test_stability.py
│   └── ...
├── .gitignore
└── README.md
```

---

## 🛠️ Quick Generate All Artifacts

```bash
#!/bin/bash
# generate_artifacts.sh - Run this on the Linux VM

# Create artifacts directory
mkdir -p artifacts

# 1. Driver check
python scripts/check_driver.py > artifacts/check_driver_output.txt

# 2. Interface info
iw dev > artifacts/iw_dev.txt

# 3. Sample capture (60 seconds)
echo "Capturing packets for 60 seconds..."
sudo tshark -i wlan0 -w artifacts/sample.pcap -a duration:60

# 4. Start sensor and capture API output
sudo python sensor/sensor_cli.py --engine tshark --api &
SENSOR_PID=$!
sleep 10  # Wait for startup

# 5. Get PoC output
curl -s http://localhost:5000/networks > artifacts/poc.json

# 6. Run ground truth (airodump-ng)
echo "Running airodump-ng for 60 seconds..."
sudo timeout 60 airodump-ng wlan0 -w artifacts/gt --output-format csv
mv artifacts/gt-01.csv artifacts/gt_output.csv

# 7. Compare recall
python tests/compare_recall.py artifacts/gt_output.csv artifacts/poc.json \
    -o artifacts/recall_report.txt

# 8. Latency test
python tests/test_latency.py -n 50 -o artifacts/latency_report.txt

# 9. Stability test (short version for CI)
python tests/test_stability.py -d 5 -i 1 -o artifacts/stability_report.txt

# Cleanup
kill $SENSOR_PID 2>/dev/null

echo "Done! Artifacts generated in ./artifacts/"
ls -la artifacts/
```

---

## ✔️ Pre-Submission Verification

Before defense, verify:

1. [ ] All artifacts exist and are non-empty
2. [ ] sample.pcap opens in Wireshark
3. [ ] poc.json is valid JSON
4. [ ] recall_report.txt shows ≥80% recall
5. [ ] latency_report.txt shows avg < 1s
6. [ ] stability_report.txt shows 0 crashes
7. [ ] demo_video.mp4 plays correctly
8. [ ] No secrets in any file (grep for passwords/keys)

---

*Last updated: January 2024*

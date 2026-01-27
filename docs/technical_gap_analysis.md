# Technical Gap Analysis & Improvement Roadmap

> Based on expert evaluation of Sentinel NetLab

---

## 📊 Current State Assessment

| Area | Current | Gap | Priority |
|------|---------|-----|----------|
| **Risk Scoring** | Heuristic, fixed weights | No data-driven calibration | High |
| **Parsing** | Scapy-based | Performance under load | Medium |
| **Architecture** | Flask dev server | No TLS, single sensor | High |
| **Validation** | Manual only | No automated metrics | High |
| **Hardening** | Root execution | Privilege escalation risk | Medium |

---

## 1. Risk Scoring Algorithm Improvements

### 1.1 Current Limitations
- Fixed weights without empirical validation
- RSSI ≠ Security Risk (strong signal doesn't mean malicious)
- Missing 802.11 features (beacon interval, capability bits)

### 1.2 Implemented Improvements (`risk_v2.py`)

| Feature | v1 | v2 |
|---------|----|----|
| Weight calibration | ❌ | ✅ From labeled data |
| Beacon interval analysis | ❌ | ✅ |
| Privacy/capability flags | ❌ | ✅ |
| Temporal anomaly | ❌ | ✅ (new networks) |
| Validation metrics | ❌ | ✅ (precision/recall/F1) |
| ML export | ❌ | ✅ |

### 1.3 Usage Example
```python
from risk_v2 import EnhancedRiskScorer

scorer = EnhancedRiskScorer()

# Score with ground truth for validation
result = scorer.calculate_risk(network, ground_truth_label="malicious")

# Get validation metrics
metrics = scorer.get_validation_metrics()
print(f"Precision: {metrics['precision']}, Recall: {metrics['recall']}")

# Calibrate weights from labeled data
new_weights = scorer.calibrate_weights_from_data(labeled_dataset)
```

### 1.4 Future: ML Integration
```python
# Export for sklearn training
features = scorer.export_for_ml_training()

# Train logistic regression
from sklearn.linear_model import LogisticRegression
model = LogisticRegression()
model.fit(X, y)
```

---

## 2. Parsing & Capture Improvements

### 2.1 Current Status
- ✅ `capture_tshark.py`: High-performance tshark backend (already implemented)
- ✅ `capture_queue.py`: Producer-consumer pattern for loss prevention
- ⚠️ `parser.py`: Needs robustness checks

### 2.2 Robustness Checklist
- [ ] Check RadioTap header presence before RSSI extraction
- [ ] Handle malformed frames gracefully
- [ ] Validate BSSID format before storage
- [ ] Add frame type filtering at capture level (BPF)

### 2.3 RSSI Accuracy
| Adapter | RSSI Accuracy | Notes |
|---------|---------------|-------|
| Atheros AR9271 | ✅ Accurate | Recommended |
| Realtek RTL8812AU | ⚠️ Varies | Driver dependent |
| Intel AX200 | ❌ Poor in monitor | Not recommended |

---

## 3. Architecture Hardening

### 3.1 Production Stack (Implemented)

```
                    ┌─────────────────┐
                    │   nginx (TLS)   │
                    │    :443         │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │   Gunicorn      │
                    │   (workers)     │
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
┌────────▼────────┐ ┌────────▼────────┐ ┌────────▼────────┐
│  api_server.py  │ │  monitoring.py  │ │   storage.py    │
│  (Flask app)    │ │  (Prometheus)   │ │   (SQLite)      │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

### 3.2 Files Created
- `ops/systemd/wifi-scanner.service`: Systemd unit
- `sensor/gunicorn_conf.py`: Production config
- `sensor/monitoring.py`: Prometheus metrics

### 3.3 Security Hardening Checklist
- [x] Gunicorn instead of Flask dev server
- [x] Rate limiting (flask-limiter)
- [x] API key authentication
- [ ] TLS/HTTPS (nginx config provided)
- [ ] Non-root execution (requires sudoers setup)
- [ ] Secret rotation policy

---

## 4. Validation Framework

### 4.1 Metrics Now Tracked

| Metric | Tool | Target |
|--------|------|--------|
| Detection Recall | `compare_recall.py` | ≥80% |
| Detection Precision | `compare_recall.py` | ≥90% |
| False Positive Rate | `risk_v2.py` | <10% |
| API Latency | `test_latency.py` | <1s avg |
| Scan Duration | `/metrics` | <5s |

### 4.2 Validation Workflow
```bash
# 1. Generate ground truth
sudo airodump-ng wlan0 -w gt --output-format csv &
sleep 60 && kill %1

# 2. Run sensor scan
curl http://localhost:5000/scan > poc.json

# 3. Compare recall/precision
python tests/compare_recall.py gt-01.csv poc.json

# 4. Check risk scoring metrics
python -c "
from sensor.risk_v2 import EnhancedRiskScorer
scorer = EnhancedRiskScorer()
# ... score networks with labels ...
print(scorer.get_validation_metrics())
"
```

---

## 5. Multi-Sensor Architecture (Future)

### 5.1 Current: Single Sensor
```
[Sensor] ──HTTP──► [Controller GUI]
```

### 5.2 Target: Distributed
```
[Sensor 1] ──┐
[Sensor 2] ──┼──MQTT/HTTP──► [Aggregator API] ──► [SIEM/Elastic]
[Sensor 3] ──┘                    │
                                  ▼
                             [PostgreSQL]
```

### 5.3 Implementation Path
1. Add sensor_id to all API responses
2. Create aggregator service (FastAPI recommended)
3. Use message queue (RabbitMQ/MQTT) for reliability
4. Migrate from SQLite to PostgreSQL

---

## 6. Improvement Priority Matrix

| Task | Effort | Impact | Priority |
|------|--------|--------|----------|
| Use `risk_v2.py` | Low | High | P0 |
| Add TLS (nginx) | Low | High | P0 |
| Run validation tests | Low | High | P0 |
| Weight calibration with data | Medium | High | P1 |
| Parser robustness | Medium | Medium | P1 |
| Multi-sensor aggregator | High | High | P2 |
| ML model training | High | Medium | P2 |

---

## 7. Recommendations Summary

### Immediate (This Week)
1. ✅ Switch to `risk_v2.py` for enhanced scoring
2. ✅ Enable Prometheus metrics (`/metrics`)
3. Run `compare_recall.py` to baseline accuracy

### Short-term (1-2 Weeks)
4. Collect labeled dataset (50-100 networks)
5. Calibrate weights using `calibrate_weights_from_data()`
6. Deploy nginx TLS proxy

### Medium-term (1 Month)
7. Implement multi-sensor aggregation
8. Train simple ML classifier (LogisticRegression)
9. Integrate with SIEM (Elastic/Splunk)

---

*Document generated from expert technical review*

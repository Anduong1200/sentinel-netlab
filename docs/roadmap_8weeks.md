# Lộ Trình 8 Tuần - WiFi Security Assessment System

## Tổng quan

| Phase | Tuần | Nội dung | Status |
|-------|------|----------|--------|
| 1 | 1-2 | Môi trường & POC | ✅ Done |
| 2 | 3-4 | Core Sensor | ✅ Done |
| 3 | 5-6 | Controller & GUI | 🔄 In Progress |
| 4 | 7-8 | Testing & Documentation | ⏳ Pending |

---

## Chi tiết

### Tuần 1-2: Môi trường & POC ✅

- [x] Setup VirtualBox/VMware
- [x] Import Kali Linux VM
- [x] Configure USB Passthrough
- [x] Test monitor mode với adapter
- [x] Tạo Flask API skeleton
- [x] Implement mock data endpoint

### Tuần 3-4: Core Sensor ✅

- [x] `capture.py` - Monitor mode control, channel hopping
- [x] `parser.py` - 802.11 frame parsing, OUI lookup
- [x] `storage.py` - SQLite database, PCAP rotation
- [x] `risk.py` - Risk scoring algorithm
- [x] `config.py` - Configuration management
- [x] Real WiFi scanning integration

### Tuần 5-6: Controller & GUI 🔄

- [x] `scanner_gui.py` - Tkinter GUI
- [ ] `api_client.py` - HTTP client wrapper
- [ ] Color-coded risk display
- [ ] Settings persistence
- [ ] Export functionality polish
- [ ] Error handling & recovery UI

### Tuần 7-8: Testing & Documentation ⏳

- [ ] Unit tests cho parser, risk
- [ ] `compare_recall.py` - Accuracy test vs airodump-ng
- [ ] `test_latency.py` - API performance test
- [ ] Complete technical report
- [ ] Prepare demo video (3-5 mins)
- [ ] Prepare presentation slides
- [ ] Final bug fixes

---

## Milestones

| Milestone | Target | Status |
|-----------|--------|--------|
| M1: Hardware Working | Tuần 2 | ✅ |
| M2: API Functional | Tuần 4 | ✅ |
| M3: GUI Complete | Tuần 6 | 🔄 |
| M4: Ready for Demo | Tuần 8 | ⏳ |

---

## Deliverables

- Source code (sensor + controller)
- Technical report (30-40 pages)
- Presentation slides (15-20 slides)
- Demo video (3-5 minutes)
- Test artifacts (recall report, latency stats)

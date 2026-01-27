# Lộ Trình 8 Tuần - WiFi Security Assessment System

## Tổng quan Tiến độ

| Phase | Tuần | Nội dung | Status |
|-------|------|----------|--------|
| 1 | 1-2 | Môi trường & POC | ✅ Done |
| 2 | 3-4 | Core Sensor (Modules) | ✅ Done |
| 3 | 5-6 | Controller & Integration | ✅ Done |
| 4 | 7 | **Advanced Pentest & Forensics** | 🚀 Planned |
| 5 | 8 | Demo & Documentation | 🔄 In Progress |

---

## Chi tiết từng Phase

### Phase 1: Môi trường & POC (Tuần 1-2) ✅
- Setup đầy đủ Environment & Driver.

### Phase 2: Core Sensor Development (Tuần 3-4) ✅
- Modules: Capture, Parser, Storage, Risk, API.

### Phase 3: Controller & Integration (Tuần 5-6) ✅
- GUI (Windows), API Integration, Security Hardening.

### Phase 4: Advanced Pentest & Forensics (Tuần 7) - New Focus 🚀

> **Mục tiêu:** Nâng cấp từ Passive Monitoring sang Active Assessment để hợp đề tài.

- **Tuần 7.1: High Performance Capture**
  - Chuyển Capture Engine từ Scapy sang `tshark` (giảm packet loss).
- **Tuần 7.2: Active Attack Module**
  - Targeted De-authentication (với consent interlock).
  - WPA Handshake Capture & Export.
- **Tuần 7.3: Forensics Analysis**
  - Attack Signature Detection (Flood, Rogue AP).
  - Timeline Analysis.

### Phase 5: Thử nghiệm & Demo (Tuần 8)
- Live demo active attacks.
- Final report.

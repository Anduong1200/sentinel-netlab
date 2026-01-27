# 🔥 BẢN ĐỀ ÁN TỐI ƯU - 8 TUẦN HOÀN THÀNH

## 🎯 KẾ HOẠCH 8 TUẦN: "MINIMUM VIABLE PRODUCT" KHÔNG THẤT BẠI

```mermaid
timeline
    title Lộ Trình 8 Tuần - MVP Chắc Thắng
    section Tuần 1-2 : MÔI TRƯỜNG & POC
      Cài đặt VM Kali<br>USB Passthrough
      : Kiểm tra driver Atheros
      : POC sniffing cơ bản
      : Mock data backup
    section Tuần 3-4 : CORE SENSOR
      Channel hopping
      : JSON API server
      : Basic persistence
      : Risk scoring đơn giản
    section Tuần 5-6 : CONTROLLER & GUI
      Tkinter GUI Windows
      : Socket client + TLS
      : Real-time display
      : CSV/JSON export
    section Tuần 7-8 : POLISH & BÁO CÁO
      Testing & bug fix
      : Documentation
      : Demo video
      : Bảo vệ
```

## 📋 ĐỀ CƯƠNG CHI TIẾT

### TUẦN 1: THIẾT LẬP MÔI TRƯỜNG NHANH
- VirtualBox 7.0+ với Extension Pack.
- Kali Linux VM (2 CPU, 4GB RAM).
- USB Passthrough cho Atheros AR9271.

### TUẦN 2: SENSOR POC & MOCK DATA
- Test monitor mode thủ công.
- Tạo `hybrid_sensor.py` với cơ chế Mock Data fallback.

### TUẦN 3: CHANNEL HOPPING & JSON API
- Implement Channel Hopping.
- Xây dựng Flask API (`/scan`).
- Setup Systemd service.

### TUẦN 4: BASIC PERSISTENCE & RISK SCORING
- SQLite Database: Tables `networks`.
- Risk Scoring Logic (Open/WEP/Strong Signal).

### TUẦN 5: WINDOWS CONTROLLER GUI
- Tkinter GUI.
- API Client polling data từ VM.

### TUẦN 6: SECURITY & NETWORKING
- Config Network Bridge.
- API Key Authentication.

### TUẦN 7: TESTING & POLISHING
- Unit/Integration Tests.
- Bug fixing.

### TUẦN 8: DOCUMENTATION & FINAL PREP
- Video demo.
- Báo cáo kỹ thuật.
- Slide thuyết trình.

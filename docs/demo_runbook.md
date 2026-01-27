# Demo Runbook - Kịch Bản Trình Diễn

> **Mục tiêu:** Đảm bảo buổi demo diễn ra suôn sẻ, giảm thiểu rủi ro lỗi kỹ thuật Live.
> **Thời lượng:** 3-5 phút thực hiện + 5 phút Q&A.

## 1. Chuẩn Bị Trước Giờ G (Pre-Demo Checklist)

### Phần cứng
- [ ] Laptop Windows (Host) đã sạc đầy.
- [ ] USB WiFi Adapter (TL-WN722N / Alfa) + 1 cái dự phòng.
- [ ] Dây mạng LAN (nếu WiFi hội trường chập chờn).
- [ ] Kiểm tra kết nối USB Passthrough vào VM lần cuối.

### Phần mềm & Dữ liệu
- [ ] **VM Snapshot:** Revert về snapshot "Ready-for-Demo" (sạch sẽ, đã cài đủ deps).
- [ ] **Service:** Đảm bảo `wifi-scanner` service đang chạy (`systemctl status wifi-scanner`).
- [ ] **Connectivity:** Ping thông nhau giữa Host (Windows) và VM (Linux).
- [ ] **Clean State:** Xóa bớt lịch sử scan cũ trong DB (để demo thấy data mới nhảy vào).
- [ ] **Backup:** Video demo (`demo.mp4`) đã copy ra Desktop để sẵn sàng bật nếu live fail.
- [ ] **Artifacts:** File `poc.json` (Mock data) sẵn sàng để fallback.

---

## 2. Kịch Bản Demo (Live Script)

### Bước 1: Giới thiệu & Setup (1 phút)
1.  Show cấu hình VM (VirtualBox/VMware) đang chạy.
2.  Cắm USB Adapter vào máy.
3.  Trên VM: Chạy `sudo python3 check_driver.py`.
    *   *Nói:* "Hệ thống tự động kiểm tra driver và firmware. Kết quả OK, Monitor mode sẵn sàng."

### Bước 2: Thực hiện Scan (2 phút)
1.  Mở **Windows Controller GUI**.
2.  Bấm **Connect**.
    *   *Nói:* "Controller kết nối tới Sensor qua REST API bảo mật với API Key."
3.  Bấm **Start Scan**.
    *   *Quan sát:* List mạng WiFi hiện ra, nhảy số lượng realtime.
    *   *Chỉ vào:* Cột **Risk Score** (Màu Đỏ/Vàng/Xanh).
    *   *Giải thích:* "Hệ thống đang channel hopping và phân tích rủi ro dựa trên Encryption, Vendor, Signal..."

### Bước 3: Export & Forensics (1 phút)
1.  Chọn 1 mạng có rủi ro cao (VD: Open/WEP).
2.  Bấm **Stop Scan**.
3.  Bấm **Export CSV**. Show file CSV vừa tạo.
4.  Bấm **Export Report**. Show report ngắn gọn.
    *   *Nói:* "Dữ liệu được lưu trữ xuống SQLite và file PCAP để phục vụ điều tra số (forensics) sau này."

---

## 3. Plan B: Xử Lý Sự Cố (Troubleshooting Live)

### Tình huống 1: USB không nhận / Driver lỗi
*   **Hành động:** Chuyển ngay sang **Mock Mode**.
*   **Thao tác:** Restart API với flag `--mock` (hoặc cấu hình trong GUI chọn "Demo Mode").
*   **Lời thoại:** "Do điều kiện sóng vô tuyến tại hội trường nhiễu cao/hạn chế phần cứng, em xin phép chuyển sang chế độ Demo với dữ liệu mẫu đã thu thập trước đó."

### Tình huống 2: GUI không kết nối được VM
*   **Hành động:** Kiểm tra IP VM. Nếu mất thời gian (> 30s) -> Bật **Video Demo**.
*   **Lời thoại:** "Có vẻ kết nối mạng nội bộ VM đang gặp trục trặc. Để tiết kiệm thời gian, em xin phép chiếu video demo quy trình đã ghi hình trước đó."

### Tình huống 3: Không quét thấy mạng nào
*   **Hành động:** Kiểm tra ăng-ten. Nếu vẫn không thấy -> Show **History** (Dữ liệu cũ trong DB).
*   **Lời thoại:** "Hiện tại không bắt được gói tin beacon nào (có thể do lồng Faraday/nhiễu). Đây là dữ liệu lịch sử hệ thống đã quét được tại Lab."

---

## 4. Q&A Cheat Sheet (Câu hỏi thường gặp)

**Q: Tại sao phải dùng VM mà không dùng WSL2?**
A: WSL2 hiện tại chưa hỗ trợ tốt monitor mode và USB passthrough cho các dòng chip Atheros/Realtek cũ. Dùng VM đảm bảo độ ổn định cao nhất cho driver Linux gốc.

**Q: Hệ thống tính điểm rủi ro (Risk Score) như thế nào?**
A: Dựa trên trọng số: Encryption (45%), Signal (20%), SSID Pattern (15%), Vendor (10%)... Ví dụ mạng Open sẽ bị 100 điểm (Critical).

**Q: Làm sao để mở rộng hệ thống này?**
A: Kiến trúc REST API cho phép deploy nhiều sensor (Raspberry Pi) và gom log về 1 server trung tâm (SIEM/Elasticsearch) để vẽ bản đồ nhiệt WiFi.

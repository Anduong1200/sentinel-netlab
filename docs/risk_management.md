# Quản Lý Rủi Ro & Kế Hoạch Giảm Thiểu (Risk Management & Mitigation Plan)

Tài liệu này chi tiết hóa các rủi ro đã nhận diện cho dự án Hybrid WiFi Security Assessment, cùng với các biện pháp phòng ngừa, kế hoạch khắc phục và danh sách kiểm tra (checklist) cho quá trình demo.

## 1. Risk Register (Bảng Rủi Ro Chính)

| ID | Rủi ro | Xác suất | Tác động | Mức độ | Biện pháp phòng ngừa (Preventive) | Giải pháp khắc phục (Remediation) |
|----|--------|----------|----------|--------|-----------------------------------|-----------------------------------|
| 1 | WSL2 không hỗ trợ driver Wi-Fi / monitor mode | Cao | Cao | **Critical** | Thiết kế chuyển sensor sang Linux VM hoặc physical Linux; đưa WSL2 vào phần POC, nêu rõ giới hạn | Dùng Linux VM/physical (Raspberry Pi) hoặc dùng mock data; giải thích rõ trong báo cáo |
| 2 | Module driver/firmware thiếu (`ath9k_htc`, `htc_9271.fw`) | Trung bình | Cao | **High** | Kiểm tra sớm driver bằng `check_driver.py`; chuẩn bị image VM có firmware | Cài firmware, dùng kernel tương thích, hoặc chuyển sang adapter khác |
| 3 | USB passthrough unstable (host hoặc hypervisor) | Trung bình | TB-Cao | **High** | Dùng VirtualBox/VMware có Extension Pack; test trên nhiều host; dự trữ USB adapter | Thử host khác; dùng Raspberry Pi; có mock demo/recorded video |
| 4 | Pháp lý & đạo đức (sniffing / injection trái phép) | Trung bình | Cao (pháp lý) | **Critical** | Disable injection by default; chỉ demo trong lab có consent văn bản | Nếu gặp vấn đề pháp lý, dừng thu thập, dùng PCAP mẫu hợp lệ; bổ sung SOP/consent forms |
| 5 | API không bảo mật / rò rỉ dữ liệu | Trung bình | Cao | **High** | TLS/mTLS hoặc SSH tunnel; API key; firewall; rate limit | Thu hồi key, rotate certs; đóng cổng; audit logs |
| 6 | Quyền (sudo) quá rộng cho sensor process | Trung bình | Cao | **High** | Tách privilege: chỉ grant capability `cap_net_raw`,`cap_net_admin` cho binary helper; dùng least-privilege | Sửa permission; restart service; audit file access |
| 7 | Hiệu năng thấp / mất gói khi density cao | Trung bình | Trung bình | **Medium** | Dùng `tshark` cho capture, điều chỉnh dwell time, adaptive hopping | Tăng dwell trên kênh nhiều beacons; dùng PCAP replay/test; scale bằng multiple sensors |
| 8 | False positive / false negative trong risk scoring | Trung bình | Trung bình | **Medium** | Thiết kế scoring minh bạch; test trên nhiều dataset; tuning weights | Hiệu chỉnh weights, thêm heuristics (OUI, WPS, hidden) và mark confidence |
| 9 | Hỏng/đầy storage (PCAP/DB) | Thấp → TB | Trung bình | **Medium** | Quota & rotation (keep last N PCAPs), giám sát disk; compress older PCAPs | Xóa theo policy; chuyển archive lên external storage |
| 10 | OS/Kernel update break driver | Thấp → TB | Cao | **High** | Lock kernel version for VM; note compatible kernels; snapshot VM trước update | Rollback VM snapshot; rebuild kernel/module; use physical sensor fallback |
| 11 | Người dùng cấu hình sai (UX error) | Trung bình | Thấp → TB | **Medium** | Viết hướng dẫn step-by-step; `check_driver.py` có hướng dẫn fix; validation inputs | Provide troubleshooting guide; remote support; mock mode |
| 12 | Supply chain (adapter fake, TL-WN722N v2/v3 ko tương thích) | Trung bình | Cao | **High** | Mua adapter verified (v1/Alfa); ghi rõ model required trong docs | Replace adapter; have spare verified adapters |
| 13 | Leak dữ liệu nhạy cảm khi export | Thấp | Cao | **High** | Sanitize exports; encrypt sensitive exports; set file perms | Revoke exports; audit logs; notify stakeholders |

> **Ghi chú:** "Critical" = Phải giải quyết triệt để trước khi demo.

---

## 2. Giải Pháp & Hành Động Cụ Thể

### A. Giải pháp Bắt buộc (Must-fix trước Demo)

1.  **Chuyển Sensor sang Linux VM / Physical Linux**
    *   **Lý do:** WSL2 limitations.
    *   **Hành động:** Sử dụng VirtualBox/VMware (đã cập nhật trong `install_guide.md`).

2.  **Check Driver/Firmware Tự động**
    *   **Công cụ:** `check_driver.py` (Phase 4).
    *   **Logic:** Kiểm tra `lsusb`, `lsmod`, firmware path, `dmesg`. Nếu fail -> in hướng dẫn.

3.  **Privilege Hardening**
    *   Không chạy API server dưới quyền root nếu không cần thiết.
    *   Dùng capabilities cho python process: `sudo setcap cap_net_raw,cap_net_admin+ep /usr/bin/python3.8`

4.  **Bảo mật Giao tiếp**
    *   Bắt buộc dùng **API Key** (đã implement).
    *   Rate limiting (đã implement).
    *   Firewall: Chỉ định cho phép IP host (host-only network hoặc static mapping).

5.  **Disable Active Attacks**
    *   Mặc định tắt injection/deauth.
    *   Chỉ bật khi có flag rõ ràng (ví dụ: `--danger-mode`) và cần consent.

### B. Giải pháp Khuyến nghị (Should-fix)

*   **Fallback Plan:** Pre-record demo video, chuẩn bị Mock Mode (`--mock`), Raspberry Pi backup.
*   **PCAP Management:** Rotate last 30 files, auto-delete cũ nhất. (Đã implement trong `storage.py`).
*   **Monitoring:** `/health` endpoint để check status.

### C. Giải pháp Nâng cao (Nice-to-have)

*   Central SIEM (Elasticsearch).
*   ML-based anomaly detection.
*   Automated provisioning (Vagrant).

---

## 3. Runbook / Playbook Khắc Phục Sự Cố

### P1: Driver/Monitor không hoạt động
1.  **Check:** Chạy `sudo python3 check_driver.py`.
2.  **Fix Firmware:** `sudo apt install firmware-atheros` hoặc copy `htc_9271.fw` vào `/lib/firmware/ath9k_htc/`.
3.  **Fix Module:** `sudo modprobe ath9k_htc`. Nếu lỗi, revert kernel hoặc rollback snapshot VM.
4.  **Fallback:** Chạy với flag `--mock` để demo giao diện.

### P2: API Unreachable
1.  **Check:** `curl http://<VM_IP>:5000/health`.
2.  **Inspect:** `sudo ufw status`, `systemctl status wifi-scanner`.
3.  **Restart:** `sudo systemctl restart wifi-scanner`.
4.  **Logs:** `sudo journalctl -u wifi-scanner -n 200`.

### P3: Hardware fail tại ngày Demo
1.  **Switch:** Bật video demo pre-recorded (3-5 phút).
2.  **Mock:** Chạy GUI với mock data (`artifacts/poc.json`).
3.  **Explain:** Giải trình về sự cố phần cứng và trình bày kết quả từ artifacts.

---

## 4. Checklist An Toàn & Compliance

- [ ]  **Consent:** Có văn bản đồng ý khi test trên mạng không sở hữu.
- [ ]  **Passive Only:** Injection features disabled by default.
- [ ]  **Data Privacy:** Mã hóa/xóa PII trong logs/PCAP trước khi share.
- [ ]  **Retention Policy:** PCAP chỉ lưu tối đa 30 ngày (cấu hình trong `config.py`).
- [ ]  **Disclaimer:** Bảng "Responsible Use" trong docs.

---

## 5. Checklist Chuẩn Bị Demo

**Trước ngày Demo:**
- [ ]  **Hardware:** Adapter tested, spare adapter ready.
- [ ]  **VM:** Snapshot created ("Ready for Demo" state).
- [ ]  **Check:** `check_driver.py` pass; `iw dev` thấy monitor interface.
- [ ]  **Service:** `wifi-scanner` active; `/health` OK.
- [ ]  **GUI:** Config đúng IP & API Key.
- [ ]  **Artifacts:** `poc.json`, `gt_output.csv`, `recall_report` sẵn sàng trong `/artifacts`.
- [ ]  **Backup:** Pre-recorded Video (3-5 min) available locally.
- [ ]  **Power/Net:** Dây mạng, sạc đầy đủ.

---

## 6. Lệnh & Snippets Xử Lý Nhanh

**Restart Service & Check Logs:**
```bash
sudo systemctl restart wifi-scanner
sudo journalctl -u wifi-scanner -n 200 --no-pager
```

**Grant Capabilities (thay vì chạy full root):**
```bash
sudo setcap cap_net_raw,cap_net_admin+ep $(which python3)
```

**Generate Self-signed Cert:**
```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -keyout key.pem -out cert.pem -subj "/CN=wifi-sensor"
```

**Rotate PCAPs (thủ công):**
```bash
ls -1tr /var/lib/wifi-scanner/pcaps/*.pcap | head -n -30 | xargs -r rm --
```

---

## 7. Kết Luận

*   **Rủi ro lớn nhất:** Sự không ổn định của WSL2 với driver Wifi USB.
    *   **Giải pháp:** Chuyển sang **Linux VM (VirtualBox/VMware)** là bắt buộc.
*   **Demo:** Ưu tiên tính ổn định (Mock data/Video backup) hơn là live demo rủi ro cao nếu môi trường chưa được kiểm chứng kỹ.
*   **Bảo mật:** Tuân thủ nguyên tắc least-privilege và mã hóa giao tiếp cơ bản.

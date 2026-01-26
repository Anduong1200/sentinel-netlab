# Hướng Dẫn Cài Đặt Hệ Thống Giám Sát WiFi Lai (Hybrid WiFi Monitor)

## 1. Yêu Cầu Hệ Thống
- Windows 10 version 2004+ (Build 19041+) hoặc Windows 11.
- Quyền Administrator.
- Thiết bị WiFi USB hỗ trợ Monitor Mode (TP-Link TL-WN722N v1, Alfa AWUS036NHA, v.v.).

## 2. Cài Đặt Môi Trường Windows (Host)

### 2.1 Cài đặt WSL2 và Kali Linux
Mở PowerShell với quyền Admin và chạy lệnh:
```powershell
wsl --install -d kali-linux
```
*Sau khi chạy xong, restart máy tính nếu được yêu cầu. Sau đó mở ứng dụng "Kali Linux" từ Start Menu để hoàn tất thiết lập user/password.*

> [!IMPORTANT]
> **Lưu ý về Kernel:** WSL2 Kernel mặc định thường **không hỗ trợ** các driver WiFi USB (như `ath9k_htc`) hoặc tính năng `mac80211` cần thiết cho Monitor Mode.
> Nếu bạn gặp lỗi khi bật Monitor Mode, bạn CẦN build lại Kernel WSL2. Xem chi tiết tại `docs/architecture_analysis.md` (Mục 1 - Phương án A).

### 2.2 Cài đặt usbipd-win
Công cụ này cho phép chia sẻ thiết bị USB từ Windows vào WSL2.
```powershell
winget install dorssel.usbipd-win
```
*Khởi động lại terminal sau khi cài đặt.*

## 3. Cấu Hình Thiết Bị USB

### 3.1 Gắn USB vào WSL2
1. Cắm USB WiFi vào máy tính.
2. Mở PowerShell (Admin) và liệt kê các thiết bị:
   ```powershell
   usbipd list
   ```
3. Tìm Bus ID của thiết bị WiFi (VD: `1-2`). Bind thiết bị (chỉ cần làm 1 lần):
   ```powershell
   usbipd bind --busid <BUSID>
   ```
4. Attach thiết bị vào WSL2 (làm mỗi khi cần dùng):
   ```powershell
   usbipd attach --wsl --busid <BUSID>
   ```

## 4. Cài Đặt Môi Trường WSL2 (Sensor)

Mở terminal Kali Linux và thực hiện các bước sau:

### 4.1 Cập nhật hệ thống
```bash
sudo apt update && sudo apt upgrade -y
```

### 4.2 Cài đặt Dependencies
Cài đặt Python, pip, và các công cụ mạng:
```bash
sudo apt install -y python3 python3-pip net-tools aircrack-ng wireless-tools pciutils
```

### 4.3 Cài đặt Python Libraries
```bash
pip3 install scapy pandas
```

## 5. Kiểm Tra Hoạt Động

### 5.1 Kiểm tra nhận diện thiết bị
Trong Kali Linux, chạy:
```bash
lsusb
```
*Bạn sẽ thấy thiết bị Atheros (hoặc chipset tương ứng).*

### 5.2 Kiểm tra Interface
```bash
iwconfig
```
*Thường sẽ thấy interface tên `wlan0` hoặc tương tự.*

### 5.3 Chạy thử Script kiểm tra
Di chuyển đến thư mục dự án (được mount tự động, ví dụ tại `/mnt/d/hod_lab`):
```bash
cd /mnt/d/hod_lab/sensor
sudo python3 check_monitor.py
```

## Troubleshooting
- **Lỗi "Access denied" khi attach USB**: Đảm bảo PowerShell chạy dưới quyền Admin.
- **Không thấy interface wlan0**: Thử chạy `sudo modprobe ath9k_htc` (nếu dùng chip Atheros).

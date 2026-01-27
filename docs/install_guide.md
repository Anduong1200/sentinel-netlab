# Hướng Dẫn Cài Đặt - Hybrid WiFi Security Assessment System

## 📋 Tổng Quan

Hệ thống gồm 2 thành phần:
- **Sensor** (Linux VM): Flask API + Scapy, chạy trên VirtualBox/VMware
- **Controller** (Windows): Tkinter GUI gọi API

## 🔧 Yêu Cầu Hệ Thống

### Phần cứng
| Thành phần | Yêu cầu |
|------------|---------|
| CPU | 4 cores recommended |
| RAM | 8GB minimum (4GB cho VM) |
| Disk | 30GB trống cho VM |
| USB WiFi | Atheros AR9271 (TL-WN722N v1, Alfa AWUS036NHA) |

### Phần mềm
- Windows 10/11 (host)
- VirtualBox 7.x + Extension Pack **hoặc** VMware Workstation
- Python 3.8+

---

## 🖥️ Phần 1: Cài đặt VM (Sensor)

### 1.1 Tải và Import Kali Linux VM

**VirtualBox:**
```powershell
# Tải Kali OVA từ https://www.kali.org/get-kali/#kali-virtual-machines
# Import: File → Import Appliance → chọn file .ova
```

**VMware:**
```powershell
# Tải VMware image từ https://www.kali.org/get-kali/#kali-virtual-machines
# Giải nén và mở file .vmx
```

### 1.2 Cấu hình VM

| Setting | Value |
|---------|-------|
| vCPU | 2 |
| RAM | 4096 MB |
| Network | NAT hoặc Bridged |
| USB Controller | USB 2.0 (EHCI) hoặc USB 3.0 |

### 1.3 USB Passthrough

**VirtualBox:**
1. Cài Extension Pack: File → Preferences → Extensions
2. VM Settings → USB → Enable USB Controller → USB 2.0/3.0
3. Add USB Device Filter: chọn WiFi adapter
4. Start VM → Devices → USB → chọn adapter

**VMware:**
1. VM Settings → USB Controller → USB 2.0/3.0
2. Start VM → VM → Removable Devices → chọn adapter → Connect

### 1.4 Verify USB trong VM

```bash
# Kiểm tra nhận diện
lsusb | grep -i atheros

# Kiểm tra interface
iw dev

# Kiểm tra driver
lsmod | grep ath9k
```

---

## 📡 Phần 2: Cài đặt Sensor (trong VM)

### 2.1 Clone Repository

```bash
# Clone vào thư mục home
git clone https://github.com/your-repo/hod_lab.git ~/hod_lab
cd ~/hod_lab/sensor
```

### 2.2 Cài đặt Dependencies

```bash
# System packages
sudo apt update
sudo apt install -y python3 python3-pip aircrack-ng wireless-tools iw

# Python packages
pip3 install -r requirements.txt
```

**requirements.txt:**
```
flask
flask-cors
flask-limiter
scapy
```

### 2.3 Cấu hình Firewall

```bash
# Mở port 5000 cho API
sudo ufw allow 5000/tcp
sudo ufw enable
```

### 2.4 Chạy Sensor

```bash
cd ~/hod_lab/sensor

# Test mode (mock data)
python3 api_server.py

# Real mode với sudo (cần cho monitor mode)
sudo python3 api_server.py
```

**Output mong đợi:**
```
Starting WiFi Scanner API Server...
API Key: student-project-2024
Endpoints:
  GET /health - Health check
  GET /scan - Scan networks
  GET /history - Get scan history
  GET /export/csv - Export CSV
 * Running on http://0.0.0.0:5000
```

### 2.5 Lấy IP của VM

```bash
ip addr show | grep "inet "
# Ghi nhớ IP (VD: 192.168.1.100)
```

---

## 🖼️ Phần 3: Cài đặt Controller (Windows)

### 3.1 Clone Repository

```powershell
git clone https://github.com/your-repo/hod_lab.git D:\hod_lab
cd D:\hod_lab\controller
```

### 3.2 Cài đặt Dependencies

```powershell
pip install -r requirements.txt
```

**requirements.txt:**
```
requests
```

### 3.3 Cấu hình API Endpoint

Mở `scanner_gui.py` và chỉnh dòng:
```python
self.api_url = "http://192.168.1.100:5000"  # IP của VM
self.api_key = "student-project-2024"
```

### 3.4 Chạy Controller

```powershell
python scanner_gui.py
```

---

## ✅ Phần 4: Kiểm tra Hoạt động

### 4.1 Test API từ Windows

```powershell
# Health check
curl http://192.168.1.100:5000/health

# Scan (với API key)
curl -H "X-API-Key: student-project-2024" http://192.168.1.100:5000/scan
```

### 4.2 Test GUI

1. Mở GUI (`scanner_gui.py`)
2. Click "Test Connection" → Status: Connected
3. Click "Start Scan" → Networks hiển thị trong list
4. Click "Export CSV" → File CSV được tạo

---

## 🔧 Troubleshooting

### USB không xuất hiện trong VM

```bash
# Trong VM - kiểm tra USB subsystem
lsusb

# Thử unplug/replug adapter
# Trong VirtualBox: Devices → USB → Re-attach
```

### Không thể bật Monitor Mode

```bash
# Kiểm tra driver
lsmod | grep ath9k_htc

# Load driver thủ công
sudo modprobe ath9k_htc

# Kiểm tra firmware
ls /lib/firmware/ath9k_htc/
```

### API Connection Refused

```bash
# Trong VM - kiểm tra service đang chạy
curl localhost:5000/health

# Kiểm tra firewall
sudo ufw status

# Kiểm tra IP
ip addr show
```

### GUI không kết nối được

1. Verify IP VM đúng
2. Verify port 5000 mở
3. Verify API Key đúng
4. Thử ping VM từ Windows: `ping 192.168.1.100`

---

## 🚀 Quick Start Checklist

- [ ] VirtualBox/VMware đã cài
- [ ] Kali VM đã import
- [ ] USB adapter đã passthrough vào VM
- [ ] `lsusb` thấy adapter trong VM
- [ ] `pip install -r requirements.txt` trong VM
- [ ] `api_server.py` đang chạy
- [ ] Ghi nhớ IP của VM
- [ ] `pip install requests` trên Windows
- [ ] Cấu hình IP trong `scanner_gui.py`
- [ ] GUI kết nối thành công

---

## 📚 Tài liệu Thêm

- [Technical Report](technical_report.md) - Báo cáo kỹ thuật đầy đủ
- [API Reference](api_reference.md) - Chi tiết API endpoints
- [README](../README.md) - Tổng quan dự án

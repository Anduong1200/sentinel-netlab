# Hướng dẫn cài đặt Driver WiFi (Monitor Mode)

Để hệ thống Sentinel NetLab (đặc biệt là tiến trình Sensor/Agent) có thể bắt được các gói tin 802.11 Management Frames, card WiFi của bạn **bắt buộc phải hỗ trợ chế độ Monitor Mode và Packet Injection**.

Dưới đây là hướng dẫn tổng quát để nhận diện và cài đặt driver cho mọi loại chipset WiFi phổ biến trên Linux (Ubuntu/Debian, Arch, Kali).

---

## 1. Cách xác định Chipset của USB WiFi

Trước khi tìm driver, bạn phải biết chính xác USB WiFi của mình dùng chip gì.
Cắm USB WiFi vào máy (hoặc kết nối qua USB Passthrough nếu dùng Máy ảo) và gõ lệnh:

```bash
lsusb
```

Bạn sẽ thấy một danh sách các thiết bị USB đang kết nối. Hãy tìm dòng có chứa chữ `WLAN`, `Wireless`, `802.11` hoặc tên hãng (TP-Link, Alfa, Realtek, Ralink, Atheros).
*Ví dụ output:*
`Bus 001 Device 003: ID 148f:3070 Ralink Technology, Corp. RT2870/RT3070 Wireless Adapter`
=> Chipset của bạn là **Ralink RT3070**.

---

## 2. Phân loại Chipset và Hướng dẫn Cài đặt

### Nhóm 1: "Cắm là chạy" (Plug & Play - Khuyên dùng)
Nhóm này có driver mã nguồn mở đã được tích hợp sẵn vào nhân Linux (Linux Kernel) từ rất lâu. Bạn không cần cài đặt gì thêm, cứ cắm vào là nhận Monitor Mode ngạy lập tức.

* **Atheros AR9271** (Ví dụ: Alfa AWUS036NHA, TP-Link WN722N v1 cực kỳ nổi tiếng)
* **Ralink RT3070** (Ví dụ: Alfa AWUS036NH)
* **Ralink RT5370**

**Cách kiểm tra:**
Cắm vào và gõ lệnh `ip link` hoặc `iwconfig`. Nếu thấy xuất hiện card mạng (VD: `wlan1`), bạn có thể cấu hình Monitor Mode ngay (Xem Mục 3).

### Nhóm 2: MediaTek (Thế hệ mới, Cắm là chạy trên Kernel mới)
* **MediaTek MT7612U** (Ví dụ: Alfa AWUS036ACM - Bắt được cả dải 2.4GHz và 5GHz)
* Dòng này nếu dùng Ubuntu 22.04+ hoặc Kali Linux mới nhất thì cũng nhận diện tự động vì driver `mt76` đã được gộp vào Kernel.
* Nếu không nhận, hãy thử cập nhật Kernel: `sudo apt update && sudo apt upgrade -y`

### Nhóm 3: Realtek (Cần phải biên dịch Driver bằng tay - Phức tạp)
Đây là nhóm phổ biến trên thị trường nhưng Linux driver mặc định của chúng rất kém hoặc không hỗ trợ Monitor Mode. Bạn phải cài driver custom từ Github (thường là dự án của aircrack-ng hoặc morrownr).

* **RTL8812AU** (Thường thấy ở các USB WiFi 2 râu, chuẩn AC1200)
* **RTL8188EUS** (TP-Link WN722N v2/v3)

**Ví dụ cách cài RTL8812AU trên Ubuntu/Kali:**
```bash
sudo apt update
sudo apt install -y dkms build-essential libelf-dev linux-headers-$(uname -r) git
git clone https://github.com/aircrack-ng/rtl8812au.git
cd rtl8812au
sudo make dkms_install
```
Sau đó khởi động lại máy hoặc rút ra cắm lại USB WiFi.

**Ví dụ cách cài trên Arch Linux:**
```bash
sudo pacman -Syu dkms linux-headers git base-devel
yay -S rtl88xxau-aircrack-dkms-git
```

---

## 3. Cách ép Card WiFi sang Monitor Mode (Bước Test quan trọng)

Sau khi card đã nhận diện (chuẩn bị lệnh `iwconfig` để xem tên, thường là `wlan0` hoặc `wlan1`). Chạy chuỗi lệnh sau:

```bash
# 1. Tắt card mạng
sudo ip link set wlan1 down

# 2. Ngắt các tiến trình mạng có thể gây nhiễu (NetworkManager, wpa_supplicant)
sudo airmon-ng check kill

# 3. Chuyển sang Monitor Mode
sudo iw wlan1 set type monitor

# 4. Bật lại card mạng
sudo ip link set wlan1 up

# 5. Kiểm tra kết quả
iw wlan1 info
```
Nếu dòng kết quả có chữ `type monitor`, xin chúc mừng, phần cứng của bạn đã sẵn sàng cho Sentinel Sensor.

---

## 4. Xử lý sự cố (Troubleshooting)

- **Lỗi "RTNETLINK answers: Device or resource busy"**: Bạn đang cố đổi sang Monitor mode khi card đang bật (Up). Phải gõ lệnh `sudo ip link set wlanX down` trước.
- **WIFI hay bị văng, ngắt kết nối**: Do xung đột với `NetworkManager`. Lệnh `sudo airmon-ng check kill` sẽ giết các dịch vụ tự động kết nối WiFi của OS. Chú ý: Việc này có thể làm bạn mất kết nối mạng internet (SSH) nếu bạn đang dùng WiFi đó để remote!
- **Card báo Monitor Mode nhưng không bắt được gói tin**: Mở Terminal gõ `sudo tcpdump -i wlan1 -n -e -s 0`. Nếu màn hình đứng im không log ra các dòng Beacon, Probe v.v... nghĩa là driver bị lỗi (thường gặp ở chip Realtek cài sai bản), bạn cần tải bản driver khác.

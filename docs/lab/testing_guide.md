# Hướng dẫn Kiểm thử (Testing Guide) từng tính năng

Tài liệu này hướng dẫn bạn cách xác minh và test từng thành phần của Sentinel NetLab, từ những bước cơ bản đến nâng cao.

---

## Giai đoạn 1: Test Hệ sinh thái cốt lõi (Controller + Dashboard)

Khi bạn khởi động Lab (`make lab-up` hoặc `docker compose ... up -d`), hãy kiểm tra xem hệ thống Control Plane có "sống" không.

### 1. Test Controller API (Liveness & Health)
Mở terminal và gọi lệnh HTTP GET tới endpoint Health Check:
```bash
curl -s http://127.0.0.1:8080/api/v1/health | jq
```
*Bạn nên nhận được phản hồi JSON có chứa `"status": "ok"` và trạng thái kết nối Database/Redis.*

### 2. Test Giao diện Dashboard (Web UI)
* Mở trình duyệt truy cập: `http://127.0.0.1:8080/dashboard/` (Nếu là Lab Mode)
* Giao diện đăng nhập sẽ hiện ra. Sử dụng tài khoản xuất ra từ script sinh mật khẩu (mặc định user: `admin`).
* Hệ thống phải tải được trang Sidebar, các biểu đồ (nếu trống dữ liệu thì đồ thị vẫn sẽ vẽ khung).

---

## Giai đoạn 2: Test Quy trình Nạp dữ liệu giả lập (Mock Data Pipeline)

Nếu bạn không có USB WiFi thật mà vẫn muốn xem Dashboard nhảy số, tính năng Mock Sinh Mock Data chính là thứ để kiểm tra hệ thống Analytics.

### 1. Khởi động Mock Mode
Chạy lệnh Nạp Dữ Liệu (Seed Data):
```bash
docker compose --env-file ops/.env.lab -f ops/docker-compose.lab.yml run --rm seed
```

### 2. Kiểm thử luồng dữ liệu (Data Pipeline Test)
Sau khi Seed thành công:
1. Quay lại trang **Dashboard (`/dashboard/`)**, nhấp vào Tab **"Alerts"**.
2. Bạn phải nhìn thấy ít nhất **1 cảnh báo Deauth/DoS** hoặc một cảnh báo bảo mật giả lập có điểm Risk Score.
3. Chuyển sang Tab **"Access Points"** hoặc **"Heatmap"**. Dữ liệu giả lập về các điểm phát WiFi kèm địa chỉ MAC sẽ hiển thị trên nền tảng.

---

## Giai đoạn 3: Test khả năng Bắt Gói Tin Mạng thật (Sensor)

*(Yêu cầu: Máy có gắn USB WiFi đã được cấu hình sang Monitor Mode, giả sử tên là `wlan1`)*

### 1. Chạy Sensor ở chế độ CLI In ra màn hình
Hãy test Sensor độc lập (Không gửi lên phân hệ Controller) để xem nó có thực sự tóm được gói tin của thiết bị xung quanh hay không:

```bash
# Trong môi trường Python venv
source venv/bin/activate

# Chạy sensor 
sudo python sentinel.py monitor --sensor-id my-test-sensor --iface wlan1
```
*Kết quả:* Terminal của bạn sẽ nhảy liên tục thông tin: Phát hiện AP `MyHomeWiFi`, Ghi nhận Client `00:11...` liên kết. Cứ sau 10 giây (Tùy cấu hình) sẽ có dòng In ra màn hình là đã gom được X frames.

### 2. Liên kết Sensor và Controller (E2E Test)
Chạy Sensor và chỉ định gửi dữ liệu sống về Controller của bạn:
```bash
sudo python sentinel.py monitor \
    --sensor-id "lab-sensor-real" \
    --iface wlan1 \
    --upload-url "http://127.0.0.1:8080/api/v1/telemetry"
```
*(Nếu Controller ở máy khác, thay 127.0.0.1 bằng IP máy chủ Controller)*

*Xác nhận:*
* Nhìn log của Sensor: Xem dòng `[POST /api/v1/telemetry] 201 Created`
* Mở Dashboard: Xem số lượng AP / Client / Frames thay đổi theo thời gian thực (Real-time).

---

## Giai đoạn 4: Test các tính năng Chuyên sâu (Advanced Algorithms)

### 1. Test tấn công Deauth (Denial of Service)
Để kiểm tra thuật toán xem việc phát hiện bị DDoS (Deauthentication flood) có nhạy không:
* Mở điện thoại, bắt WiFi nhà bạn.
* Bạn dùng máy tính có gắn Tool (như Kali Linux) bắn lệnh Hủy xác thực (Deauth):
  `sudo aireplay-ng --deauth 10 -a <MAC_CỦA_WIFI_NHÀ_BẠN> -c <MAC_ĐIỆN_THOẠI> wlan1`
* **Kỳ vọng:** Trong chưa đầy 15 giây, Dashboard của NetLab ở mục Alerts sẽ nhá màu đỏ báo hiệu `DEAUTH_FLOOD_DETECTED` có mức rủi ro CAO.

### 2. Test Wardriving (Vẽ Bản Đồ WiFi)
Tính năng này không cần Controller. Bạn xách Laptop/Pi + USB WiFi đi dạo:
```bash
sudo python sensor/wardrive.py --iface wlan1 --output my_walk.json
```
* **Kỳ vọng:** Khi ngừng chạy, file `my_walk.json` được sinh ra chứa danh sách toàn bộ WiFi bạn đã quét được trên phố. Nếu bạn cắm thêm cổng GPS (Qua cổng USB COM), các thiết bị này sẽ được ghim tọa độ vật lý.

### 3. Test công cụ Audit (Scan Lỗ Hổng Bảo Mật)
Tính năng dùng để đánh giá độ an toàn của cấu hình WiFi (Ví dụ: quét xem mạng nhà bạn có đang dùng WPA1 hay WEP yếu đuối không).
```bash
# Yêu cầu đã thiết lập file cấu hình profle audit trong mã nguồn
python sensor/audit.py --profile home --output audit_report.json
```
* **Kỳ vọng:** Công cụ sẽ xuất ra một file JSON báo cáo: "Mạng nhà bạn đạt chuẩn WPA2/WPA3. Không phát hiện lổ hổng OWE thiếu mã hóa PMF, v.v..."

### 4. Test Định Vị (Geo-Location), Học Máy (ML Boost) & Chạy lại PCAP
Bạn có thể thử nghiệm các tính năng nâng cao trực tiếp từ CLI bằng các cờ đã được tích hợp sẵn:
```bash
# Test Replay gói tin mẫu (thay thế cho việc dùng USB WiFi thật để phát hiện tấn công)
sudo python sensor/cli.py --sensor-id test-pcap --pcap tests/data/captured_attack.pcap

# Khởi chạy Sensor kèm hệ thống học máy (ML Anomaly Detection) và vẽ bản đồ nhiệt (Geo Heatmap)
sudo python sensor/cli.py --sensor-id test-ml --iface wlan1 --enable-ml --enable-geo
```
* **Kỳ vọng:** Khi chạy cờ `--pcap`, hệ thống sẽ đọc gói tin từ file `.pcap` để chấm điểm tấn công thay vì card mạng. Khi chạy với cờ `--enable-ml` và `--enable-geo`, màn hình khởi động (Banner) sẽ thông báo rõ `ML Boost: ENABLED` và `Geo Loc: ENABLED`, đồng thời Pipeline sẽ móc nối dữ liệu Tọa độ và Máy học vào quá trình chấm điểm Risk Score.

---

## 5. Xử lý sự cố thường gặp (Troubleshooting Lab Mode)

Trong quá trình khởi chạy Lab bằng `docker compose`, bạn có thể kiểm tra trạng thái các container bằng lệnh:
```bash
docker compose --env-file ops/.env.lab -f ops/docker-compose.lab.yml ps
```

### 1. Lỗi "Proxy (unhealthy)" và "Sensor (restarting)"
* **Triệu chứng:** Khi check `docker ps`, `sentinel-lab-proxy` báo lỗi `unhealthy`, còn `sentinel-lab-sensor` liên tục khởi động lại (restarting).
* **Nguyên nhân:** File cấu hình Nginx bị kẹt bản cũ chưa cập nhật đúng, hoặc quyền truy cập Volume bị chặn (nhớ xóa `:ro` trong `docker-compose.lab.yml`. 
* **Cách sửa:** Bạn cần lệnh để thay thế (recreate) bắt buộc các container bị đọng cấu hình cũ:
  ```bash
  docker compose --env-file ops/.env.lab -f ops/docker-compose.lab.yml up -d --force-recreate proxy sensor
  ```

### 2. Tải Dashboard bị lỗi trang trắng "Not Found" hoặc "Unable to connect"
* **Triệu chứng:** Trình duyệt Firefox/Chrome báo không kết nối được đến `127.0.0.1:8080` hoặc vào được URL gốc nhưng hiện "Not Found".
* **Nguyên nhân:** App Dashboard mặc định phục vụ ở đường dẫn `/dashboard/`.
* **Cách sửa:** URL chuẩn xác để truy cập bảng điều khiển là: `http://127.0.0.1:8080/dashboard/`. Nếu bạn mới cập nhật Server, hệ thống (Proxy Nginx) sẽ tự chuyển hướng bạn sang đó. Nếu lỗi vẫn tiếp diễn, hãy thử xóa lịch sử/bộ nhớ đệm trình duyệt, hoặc chạy lệnh ép khởi động lại proxy ở lỗi số 1 phía trên.

### 3. Trình duyệt báo lỗi "Secure Connection Failed" (SSL_ERROR_RX_RECORD_TOO_LONG)
* **Triệu chứng:** Truy cập trang web màn hình báo lỗi SSL, URL tự động bị gắn chữ `https://`.
* **Nguyên nhân:** Lab Mode của chúng ta được thiết kế chạy nội bộ (localhost) nhẹ và nhanh nên chỉ dùng đường truyền văn bản (HTTP). Các trình duyệt hiện đại (đặc biệt là Firefox) có tính năng tự động nâng cấp bảo mật, ép kết nối qua giao thức mã hóa HTTPS, trong khi cổng 8080 của chúng ta không cấu hình Chứng chỉ Số (SSL/TLS).
* **Cách sửa:** Bạn phải gõ lại cực chuẩn xác thanh địa chỉ là `http://` thay vì `https://` (Ví dụ: `http://127.0.0.1:8080/dashboard/`). Trường hợp trình duyệt quá "ngoan cố", hãy mở Cửa sổ Ẩn danh (Private/Incognito Mode - Ctrl+Shift+P trên Firefox) dán lại đúng đường dẫn HTTP là xong.

### 4. Lỗi "Failed to create an image... already exists" khi chạy make lab-up
* **Triệu chứng:** Gõ `make lab-up` bị văng lỗi đỏ lòm báo `failed to create an image docker.io/library/sentinel-controller:lab with target... AlreadyExists`.
* **Nguyên nhân:** Lệnh buildx/compose của Docker đang bị "kẹt" bộ nhớ đệm (cache) hoặc xung đột tag ảnh khi cố đè một image đang được container tạm thời chiếm giữ.
* **Cách sửa:** Chạy các lệnh sau để ép Docker xóa sổ ảnh cũ bị lỗi và dọn dẹp cache trước khi build lại:
  ```bash
  # Xóa bỏ image bị kẹt một cách triệt để
  docker rmi sentinel-controller:lab --force
  
  # Dọn dẹp cache builder rác (nếu lệnh trên chưa đủ đô)
  docker builder prune -f
  
  # Khởi động lại lab
  make lab-up
  ```

### 5. Lỗi "Scapy not installed" (dù đã chạy pip install thành công)
* **Triệu chứng:** Bạn kích hoạt `source venv/bin/activate` và gõ `pip install scapy` báo thành công. Nhưng khi chạy Script Wardrive/Sensor thì hệ thống vẫn văng lỗi: `Scapy not installed but required for real capture`.
* **Nguyên nhân:** Có 2 nguyên nhân kinh điển trên các hệ thống Linux:
  1. **Bạn CHƯA dùng lệnh `sudo` (Trường hợp trong ảnh báo lỗi):** Khi gọi `python sensor/wardrive.py` bằng user thường, module `scapy.all` bên dưới sẽ thất bại khi cố gắng nạp các thư viện bắt gói tin mạng ở tầng thấp (do bị OS từ chối quyền - Permission Denied). Lỗi này bị code bắt nhầm thành `ImportError` khiến nó in ra "Scapy not installed".
  2. **Bạn cố dùng `sudo python` nhưng bị văng mất môi trường:** Lệnh `sudo` theo mặc định của Linux sẽ **xóa bỏ toàn bộ biến môi trường PATH** của user. Hệ quả là `sudo python` sẽ gọi bản Python gốc của toàn hệ thống (bản chưa cài Scapy) thay vì gọi Python trong `venv/` của bạn!
* **Cách sửa chuẩn xác 100%:** Luôn kết hợp quyền Root (`sudo`) và gọi chính xác đường dẫn tuyệt đối (Absolute Path) tới file thực thi Python nằm **bên trong venv** của bạn:
  
  ```bash
  # Kích hoạt venv (nếu chưa bật)
  source venv/bin/activate

  # [QUAN TRỌNG] Gọi sudo kèm đường dẫn python CỦA VENV thay vì gõ python không!
  sudo venv/bin/python sensor/wardrive.py --sensor-id alfa-01 --iface wlan0 --output wardrive_session.json
  ```

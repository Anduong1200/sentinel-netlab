# Báo Cáo Đánh Giá Mức Độ Hoàn Thiện Dự Án Sentinel NetLab

**Mục đích**: Tài liệu này đánh giá tổng thể mã nguồn của Sentinel NetLab, cung cấp nhận định từ việc phân tích trực tiếp mã nguồn (Code Review) và đề xuất các kịch bản kiểm thử (Test Scenarios) để chứng minh tính vững chắc của dự án trước hội đồng bảo vệ.

---

## 1. Tiêu chí Kiến trúc và Khả năng Mở rộng (Architecture & Scalability)

### 📌 Nhận định từ Mã nguồn
*   **Kiến trúc Phân tán (Edge - Core)**: Dự án thể hiện rất rõ sự tách biệt giữa Sensor (thu thập) và Controller (xử lý). Sensor (`sensor/sensor_controller.py`) chỉ đóng vai trò đẩy dữ liệu lên qua API mà không nắm quyền quyết định, giúp bảo vệ lớp lõi (Core) kể cả khi phần cứng ở biên bị xâm phạm.
*   **Tính chịu lỗi (Fault Tolerance)**: File `sensor/transport.py` được triển khai theo tiêu chuẩn công nghiệp với cơ chế **Exponential Backoff** (thử lại với độ trễ tăng dần) và **Circuit Breaker** (ngắt mạch khi lỗi liên tục). Nếu kết nối mạng giữa RPi và Server bị đứt, Sensor sẽ không bị crash mà tự động đệm dữ liệu (Spooling/Queue) và gửi lại khi mạng ổn định.

### 🧪 Kịch bản Trình bày Trước Hội đồng (Chi tiết Từng bước)
*   **Mục đích**: Chứng minh khả năng sống sót của thiết bị thu thập (Sensor) khi mất mạng, không bị crash làm mất dữ liệu.
*   **Thao tác**:
    1.  Mở Terminal 1, khởi động toàn hệ thống:
        `make lab-up`
    2.  Mở Terminal 2, chạy một Sensor độc lập đang đẩy dữ liệu:
        `python sensor/cli.py --sensor-id demo-01 --config-file config.yaml`
    3.  *(Vừa làm vừa thuyết minh)* "Thưa hội đồng, giờ em sẽ giả lập trường hợp máy chủ trung tâm bị rớt mạng hoặc mất điện."
    4.  Mở Terminal 3, tắt ngay container của Controller:
        `docker stop ops-controller-1`
    5.  Chỉ vào **Terminal 2 (Log Sensor)** cho hội đồng xem:
        *   Log hiện: `Upload attempt 1 failed: Connection error...`
        *   Log tiếp theo: `Retry after 1.0s` -> `Retry after 2.0s` (Đây là cơ chế Exponential Backoff).
        *   Log báo đỏ: `Circuit breaker opened due to repeated failures` (Hệ thống ngắt mạch bảo vệ CPU, không spam request nữa).
        *   **Nhấn mạnh**: Sensor vẫn đang chạy, không hề văng lỗi (crash) thoát chương trình.
    6.  Khôi phục mạng: `docker start ops-controller-1`. Chỉ vào Terminal 2 thấy Sensor nối lại thành công `Time sync: offset=...` và tiếp tục đẩy hàng đợi (Spooling) bị kẹt.

---

## 2. Tiêu chí Hiệu năng Phát hiện (Detection Performance Metrics)

### 📌 Nhận định từ Mã nguồn
*   **Hệ sinh thái 11-Detector (11 Thuật toán cốt lõi)**: Khác với các công cụ đơn giản chỉ đếm gói tin, thư mục `algos/` của NetLab chứa một tập hợp đầy đủ 11 thuật toán chuyên biệt bao trùm các kỹ thuật tấn công WiFi phức tạp nhất hiện nay:
    *   **Tấn công Mạng (Network Attacks)**: `evil_twin.py` (Trạm phát giả mạo), `karma_detector.py` (Tấn công Karma/Pineapple).
    *   **Từ chối dịch vụ (DoS/Jamming)**: `dos.py` (Deauth Flood), `disassoc_detector.py`, `beacon_flood_detector.py`, `jamming_detector.py` (Phá sóng RF).
    *   **Khai thác Mật mã (Cryptographic Exploits)**: `krack_detector.py` (Khai thác WPA2 KRACK), `pmkid_detector.py` (Đánh cắp Hash PMKID), `wep_iv_detector.py`.
    *   **Trinh sát (Reconnaissance)**: `wardrive_detector.py` (Phát hiện thiết bị đang đi quét mạng).
*   **Cơ chế Phân tích Chuỗi (Exploit Chain Analyzer)**: File `algos/exploit_chain_analyzer.py` đóng vai trò móc nối các sự kiện đơn lẻ thành một cuộc tấn công có chủ đích (APT). Ví dụ: Phát hiện 1 Deauth Flood đi kèm 1 Evil Twin sẽ kích hoạt cảnh báo cực kỳ nghiêm trọng.
*   **Kiến trúc Thuật toán Chuyên sâu**: Thuật toán của NetLab sử dụng cơ chế **Trượt thời gian (Sliding Window)** và **Điểm số Tích lũy (Weighted Scoring)**.
    *   Ví dụ ở Evil Twin: Hệ thống không vội vàng cảnh báo chỉ vì có 2 trạm phát cùng tên (SSID). Nó yêu cầu hội đủ điểm (Score > 80) thông qua việc xét chênh lệch sóng (RSSI Delta), độ trễ báo hiệu (Beacon Jitter), mã OUI của thiết bị và có thời gian xác nhận (Confirmation Window) để loại bỏ hoàn toàn báo động giả (False Positives).
*   **Hỗ trợ Học máy lai (Hybrid ML)**: Cơ sở tính điểm Rủi ro (`algos/risk.py`) không chỉ dựa trên luật cứng (Rule-based) mà còn hỗ trợ đẩy vector thuộc tính vào một mô hình Autoencoder (`ml/anomaly_model.py`) để cộng thêm "điểm bất thường", giúp phát hiện những kiểu tấn công Zero-day hoặc hành vi lạ chưa có chữ ký (Signature).

### 🧪 Kịch bản Trình bày Trước Hội đồng (Chi tiết Từng bước)
*   **Mục đích**: Chứng minh khả năng lọc nhiễu, tỷ lệ False Positive bằng 0% đối với lưu lượng mạng sạch (Normal Traffic).
*   **Thao tác**:
    1.  *(Thuyết minh)* "Để chứng minh hệ thống em không cảnh báo rác, em sẽ bơm một luồng dữ liệu mạng sinh hoạt bình thường vào thẳng đường ống phân tích (Pipeline)."
    2.  Mở Terminal, gõ lệnh chạy bài test Integration chuyên biệt:
        `pytest tests/integration/test_scenarios.py::TestScenarioReplay::test_replay_normal_traffic_no_alerts -v -s`
    3.  Chỉ vào Output cho hội đồng xem:
        *   Code sinh ra 1 file PCAP chứa các gói tin Beacon chuẩn, không có dấu hiệu tấn công.
        *   Dòng chữ xanh lá cây in ra: `PASSED tests/integration/test_scenarios.py...`
        *   Kèm log: `Scenario passed: Normal traffic processed without false positives.`
        *   **Nhấn mạnh**: Hệ thống đọc hơn 10 gói tin nhưng thuật toán đã nhận diện an toàn tuyệt đối, không có bất kỳ `upload_alert` nào bị kích hoạt.

---

## 3. Tiêu chí Mức độ bao phủ Kiểm thử (Testability & QA)

### 📌 Nhận định từ Mã nguồn
*   **Công cụ Replay Mạnh mẽ**: Dự án xây dựng sẵn `PcapCaptureDriver` và `MockCaptureDriver`, cho phép bơm các file PCAP (gói tin đã bắt) chạy thẳng qua toàn bộ đường ống hệ thống (Pipeline) y hệt như đang dùng card WiFi thật.
*   **Test Integration Cấu trúc tốt**: Thư mục `tests/integration/` có các kịch bản kiểm thử từ đầu đến cuối (End-to-End). Việc sinh file PCAP giả tấn công (Evil Twin, Deauth) được tự động hóa.

### 🧪 Kịch bản Trình bày Trước Hội đồng (Chi tiết Từng bước)
*   **Mục đích**: Chứng minh khả năng giả lập tấn công phần mềm (PCAP Replay) thay vì phải hack vật lý rủi ro trên giảng đường.
*   **Thao tác**:
    1.  *(Thuyết minh)* "Giờ em sẽ bơm trực tiếp một luồng gói tin đã được tiêm mã tấn công Evil Twin (trạm phát giả mạo) vào hệ thống."
    2.  Mở Terminal, chạy lệnh:
        `pytest tests/integration/test_scenarios.py::TestScenarioReplay::test_replay_evil_twin_detection -v -s`
    3.  Chỉ vào Output cho hội đồng xem:
        *   Dòng chữ xanh lá cây: `PASSED` xuất hiện.
        *   Chỉ vào đoạn Code Mock: Giải thích rằng Driver ảo (`PcapCaptureDriver`) đã đọc 25 frames (5 thật + 20 giả mạo).
        *   Hàm `mock_transport.upload_alert` đã được gọi, mang theo Payload chứa chữ `"Evil Twin"`.
        *   **Nhấn mạnh**: Quy trình QA được tự động hóa 100% bằng Pytest, bất cứ khi nào code thuật toán bị lỗi, lệnh test này sẽ fail ngay lập tức, đảm bảo chất lượng phần mềm không bị thoái lui (Regression).

---

## 4. Tiêu chí Trải nghiệm người dùng và Giao diện (UI/UX)

### 📌 Nhận định từ Mã nguồn
*   **Dashboard Hiện đại (Dash/Plotly)**: Giao diện web được xây dựng dựa trên Python Dash kết hợp Bootstrap.
*   **Cập nhật Thời gian thực**: Mã nguồn `dashboard/pages/map.py` (và các file khác) sử dụng `dcc.Interval` để gọi callback lấy dữ liệu mới mỗi 3 giây, tạo cảm giác các chỉ số và tọa độ trên Bản đồ Heatmap liên tục nhảy số mà không cần người dùng F5 tải lại trang.

### 🧪 Kịch bản Trình bày Trước Hội đồng (Chi tiết Từng bước)
*   **Mục đích**: Trình diễn Dashboard cập nhật tự động (Real-time) và công cụ trực quan hóa vị trí (Heatmap).
*   **Thao tác**:
    1.  Mở trình duyệt, truy cập Dashboard: `http://localhost:8050`
    2.  Vào Tab **Overview**, chỉ cho hội đồng xem các thẻ `Card` (Tổng số mạng, Cảnh báo). Giải thích rằng nhờ `dcc.Interval` trong code, các số này tự động làm mới mỗi 3 giây (đứng yên không cần F5).
    3.  Chuyển sang Tab **Global Map**.
    4.  Nhấp vào thanh xổ xuống (Dropdown) góc trên bên phải, chọn lọc `"Open / Insecure"`.
    5.  Chỉ vào bản đồ: Các đốm màu (Heatmap) thay đổi, lọc ra những mạng WiFi không cài mật khẩu (Red chấm đỏ).
    6.  **Nhấn mạnh**: Giao diện được tối ưu Dark Mode chuyên nghiệp cho bộ phận giám sát bảo mật (SOC), Plotly xử lý hàng ngàn điểm dữ liệu mà không giật lag trình duyệt.

---

## 5. Tiêu chí Triển khai, Vận hành và Tài liệu (Deployment & Documentation)

### 📌 Nhận định từ Mã nguồn
*   **Tự động hóa hoàn toàn**: Thông qua `Makefile`, toàn bộ vòng đời ứng dụng (từ build Docker, chạy linter `ruff`, test `pytest` đến quét bảo mật `bandit`) đều chỉ cần 1 cú click. Lệnh `make lab-up` kết nối nhiều container lại qua `docker-compose`.
*   **Tài liệu phân mảnh chuẩn**: Cấu trúc `docs/` rất chi tiết, phân định rõ `lab/` (cho giáo dục, dễ dùng, chạy SQLite) và `prod/` (cho vận hành doanh nghiệp, bắt buộc PostgreSQL).

### 🧪 Kịch bản Trình bày Trước Hội đồng (Chi tiết Từng bước)
*   **Mục đích**: Chứng minh khả năng đóng gói "Công nghiệp", người mới tải code về triển khai lên hệ thống chỉ tốn 30 giây.
*   **Thao tác**:
    1.  *(Thuyết minh)* "Thưa hội đồng, để triển khai toàn bộ cụm Server, Database, Message Queue và Dashboard này, người vận hành không cần cài đặt lẻ tẻ."
    2.  Mở Terminal, gõ lệnh "Hủy diệt" toàn bộ môi trường cũ:
        `make lab-down`
    3.  Kiểm tra trình duyệt `http://localhost:8050` -> Lỗi không kết nối được (Đã sập sạch).
    4.  Gõ lệnh tái thiết lập từ đầu:
        `make lab-reset`
    5.  Cho hội đồng xem Terminal tự động làm các việc:
        *   Tự sinh chìa khóa bảo mật mới (`Generating fresh secrets...`).
        *   Build lại Docker (`Starting stack...`).
        *   Tự động nạp dữ liệu mẫu ban đầu (`Seeding data...`).
    6.  Chờ khoảng 15 giây, thông báo xanh `✅ Lab Reset Complete` hiện ra. F5 trình duyệt, Dashboard sống lại với dữ liệu mới tinh.

---

## 6. Tiêu chí Bảo mật hệ thống (System Security Principles)

### 📌 Nhận định từ Mã nguồn
*   **Tiếp cận "Fail-Fast"**: Đọc file `common/security/secrets.py`, hàm `require_secret` được thiết kế cực kỳ gắt gao. Trong môi trường `Production`, nếu quản trị viên quên khai báo biến môi trường hoặc dùng mật khẩu dễ đoán (như "admin", "123456"), ứng dụng sẽ lập tức Crash (chủ động sập) kèm log `CRITICAL: Weak production secret`. Hệ thống từ chối chạy ở trạng thái không an toàn.
*   **Chữ ký Điện tử HMAC**: Toàn bộ luồng giao tiếp API giữa Sensor và Controller đều được ký xác thực bằng thuật toán HMAC-SHA256 (`_sign_payload`). Hacker không thể chen ngang để gửi log giả vào Controller.

### 🧪 Kịch bản Trình bày Trước Hội đồng (Chi tiết Từng bước)
*   **Mục đích**: Chứng minh hệ thống có cơ chế "Fail-fast" (Thà chết chứ không chạy nếu cấu hình ẩu).
*   **Thao tác**:
    1.  Mở Terminal, set nhanh 2 biến môi trường nguy hiểm để chạy file Dashboard độc lập (không qua Docker):
        `export ENVIRONMENT=production`
        `export DASH_PASSWORD=123456`
        `export DASH_USERNAME=admin`
    2.  Chạy thử Dashboard:
        `python dashboard/app.py`
    3.  Chỉ vào đoạn log đỏ chót văng ra ngay tắp lự:
        `CRITICAL: Weak production secret 'DASH_PASSWORD': Value is in blacklist of common weak passwords. Application refused to start.`
        Kèm theo đó là lỗi `RuntimeError` thoát ngay lập tức.
    4.  **Nhấn mạnh**: "Nếu một người quản trị IT cấu hình mật khẩu yếu là '123456', hệ thống em sẽ thẳng thừng từ chối khởi động để bảo vệ máy chủ, thay vì nhắm mắt chạy rủi ro như các đồ án sinh viên thông thường."

---

---

## 7. Tiêu chí Tuân thủ Quyền riêng tư và Pháp lý (Privacy & Compliance)

### 📌 Nhận định từ Mã nguồn
*   **Cơ chế Ẩn danh (Anonymization)**: Thay vì lưu trữ thô địa chỉ MAC của người dùng (có thể vi phạm GDPR hoặc các luật bảo vệ quyền riêng tư), hệ thống cung cấp module `common/privacy.py`. Module này hỗ trợ các chế độ ẩn danh:
    *   `oui`: Giữ lại 3 octet đầu (nhận diện hãng sản xuất) nhưng băm (hash) phần định danh thiết bị cá nhân (VD: `AA:BB:CC:XX:XX:XX`).
    *   `full`: Sử dụng hàm băm một chiều SHA-256 kết hợp với `_PRIVACY_SALT` (chìa khóa muối) sinh ngẫu nhiên theo từng phiên bản cài đặt, biến địa chỉ MAC thật thành một chuỗi giả danh không thể đảo ngược.
*   **Bảo vệ SSID**: Tên mạng WiFi (SSID) cũng có thể bị che giấu độ dài (`*` tương ứng số ký tự) hoặc băm một phần nếu người dùng kích hoạt cờ `--anonymize-ssid`.

### 🧪 Kịch bản Trình bày Trước Hội đồng (Chi tiết Từng bước)
*   **Mục đích**: Chứng minh hệ thống bắt được dữ liệu thật nhưng không xâm phạm thông tin cá nhân.
*   **Thao tác**:
    1.  Chạy Sensor với cờ bảo mật: `python sensor/cli.py --privacy-mode oui`
    2.  Chỉ vào màn hình Terminal đang in ra các gói tin bắt được.
    3.  **Nhấn mạnh**: "Thưa hội đồng, các địa chỉ MAC thu thập được ở đây đã bị che đi một nửa (chỉ còn OUI của nhà sản xuất). Hệ thống của em phân tích hành vi tấn công dựa trên sự thay đổi cường độ sóng và tần suất gói tin, hoàn toàn không cần theo dõi danh tính cá nhân thiết bị của người dùng, tuân thủ nguyên tắc Privacy by Design."

---

## 8. Các Hạng mục Kiểm thử Hệ thống (System Testing Scenarios)
Để bảo vệ toàn diện, dưới đây là chi tiết các kịch bản demo (Runbook) từ cơ bản đến nâng cao cần thực hiện trực tiếp trên máy trước hội đồng:

### 8.1. Kiểm thử Hệ sinh thái cốt lõi (Core Ecosystem)
*   **Controller API (Liveness & Health)**: Chứng minh Control Plane và Database/Redis đang kết nối trơn tru.
    *   *Lệnh thực thi*: `curl -s http://127.0.0.1:5000/api/v1/health | jq`
    *   *Kết quả kỳ vọng*: Terminal trả về mã JSON có trường `"status": "ok"` và hiển thị phiên bản (version), thời gian (timestamp).
*   **Giao diện Dashboard**: Chứng minh Frontend (UI/UX) không bị sập.
    *   *Cách làm*: Mở trình duyệt truy cập `http://127.0.0.1:8050`. Chuyển đổi qua lại giữa các Tab (Overview, Threats, Global Map).
    *   *Kết quả kỳ vọng*: Sidebar phản hồi tức thì, các biểu đồ Plotly render dữ liệu (hoặc khung trống an toàn nếu chưa có mạng) mà không hiện lỗi 404 hay trắng trang.

### 8.2. Kiểm thử Luồng dữ liệu giả lập (Mock Data Pipeline)
*   Mục đích: Chứng minh cơ chế Pipeline (Sensor -> Controller -> Database -> Dashboard) hoạt động mượt mà khi nhận dữ liệu giả.
*   *Cách làm*: Chạy tập lệnh nạp dữ liệu mô phỏng: `make lab-up` (lệnh này tự động gọi script `seed_lab_data.py`).
*   *Kết quả kỳ vọng*:
    1. Nhìn vào màn hình Terminal thấy log sinh ra hàng loạt gói tin giả mạo.
    2. Nhìn lên Dashboard, các bộ đếm số lượng Mạng (Networks) và Điểm rủi ro (Risk Score) bắt đầu thay đổi. Bản đồ nhiệt (Heatmap) xuất hiện các điểm màu đỏ (tương ứng với cảnh báo rủi ro cao).

### 8.3. Kiểm thử Khả năng bắt gói tin mạng thật (Sensor Capture)
*   **Test Sensor độc lập (CLI)**: Chứng minh Driver card WiFi (Monitor Mode) tương tác tốt với hệ điều hành và bắt được gói tin thực tế (Không dùng mạng WiFi của trường học để tránh vi phạm đạo đức, hãy dùng một điểm phát 4G từ điện thoại).
    *   *Lệnh thực thi*: Khởi động Monitor mode: `sudo airmon-ng start wlan0`. Sau đó chạy Sensor: `sudo python sensor/cli.py --iface wlan0mon --sensor-id demo-01`.
    *   *Kết quả kỳ vọng*: Màn hình in ra các gói tin (Beacons/Probes) với BSSID thật, SSID thật của điện thoại phát ra.
*   **Test End-to-End (E2E)**: Chứng minh dữ liệu thực tế đẩy thành công lên Server.
    *   *Cách làm*: Kết hợp lệnh `--config config.yaml` để bật kết nối API. Mở tab "Signals" trên Dashboard.
    *   *Kết quả kỳ vọng*: Địa chỉ MAC của điện thoại (SSID thử nghiệm) phải xuất hiện trên bảng tín hiệu thời gian thực (Real-time signals).

### 8.4. Kiểm thử Tấn công và Tính năng Chuyên sâu

*   **A. Tấn công Từ chối Dịch vụ (Deauth Flood)**:
    *   *Cách làm*: Sử dụng Kali Linux. Khóa mục tiêu vào thiết bị thử nghiệm. Lệnh: `sudo aireplay-ng --deauth 100 -a [MAC_ROUTER] -c [MAC_CLIENT] wlan0mon`.
    *   *Kết quả kỳ vọng*: Luồng dữ liệu bùng nổ, thuật toán `algos/dos.py` phát hiện tốc độ gói tin tăng vọt. Trên Dashboard tab "Threats", lập tức xuất hiện thẻ cảnh báo màu đỏ chót nhấp nháy `DEAUTH_FLOOD_DETECTED`, MTTD (Thời gian phát hiện) đo được dưới 10 giây.

*   **B. Phát lại kịch bản mạng (PCAP Replay) cho Evil Twin**:
    *   *Mục đích*: Chứng minh khả năng phát hiện AP giả mạo (Evil Twin) khi không có điều kiện mang 2 củ phát WiFi vật lý lên hội trường.
    *   *Cách làm*: Nạp file PCAP đã ghi hình trước: `pytest tests/integration/test_scenarios.py::TestScenarioReplay::test_replay_evil_twin_detection -v`.
    *   *Kết quả kỳ vọng*: `PASSED`. Log sẽ chỉ ra rằng hệ thống đã "thấy" sự xuất hiện của 1 BSSID khác nhưng phát cùng SSID, chênh lệch sóng (RSSI) bất thường, và OUI Vendor sai lệch. Cảnh báo Evil Twin được bắn lên hệ thống.

*   **C. Định vị (Geo-Location) & Học máy (ML)**:
    *   *Lệnh thực thi*: `python sensor/cli.py --enable-ml --enable-geo --gps-device /dev/ttyUSB0 --sensor-id demo-01`
    *   *Kết quả kỳ vọng*: Điểm Risk Score của một Access Point sẽ bị cộng thêm 20 điểm (Anomaly Boost) nếu Autoencoder thấy hành vi dị thường. Dữ liệu GPS đẩy lên làm thay đổi vị trí ghim trên Bản đồ (Global Map).

*   **D. Lập bản đồ mạng di động (Wardriving)**:
    *   *Lệnh thực thi*: `python sensor/wardrive.py --iface wlan0mon --output session.json`
    *   *Kết quả kỳ vọng*: File `session.json` sinh ra với danh sách các mạng, toạ độ, chuẩn mã hóa. File này có thể import lên giao diện Live Viewer (`live_wardrive_viewer.py`) để quan sát ngoại tuyến.

*   **E. Phân tích Khai thác Mã hóa (KRACK / PMKID)**:
    *   *Mục đích*: Chứng minh hệ thống bắt được các cuộc tấn công đánh cắp mật khẩu hiện đại nhất.
    *   *Cách làm*: Bơm file PCAP giả lập tấn công WPA2 PMKID Roaming: `pytest tests/integration/test_scenarios.py::TestScenarioReplay::test_replay_pmkid_attack` (nếu có) hoặc xem code logic `algos/pmkid_detector.py`.
    *   *Kết quả kỳ vọng*: Hệ thống phát hiện gói tin EAPOL chứa tag `RSN PMKID` bất thường gửi từ một Client chưa từng xác thực trước đó, bung ra thông báo `PMKID_HARVESTING_ATTACK`.

*   **F. Công cụ Kiểm toán Bảo mật (Security Auditor)**:
    *   *Lệnh thực thi*: `python sensor/audit.py --profile strict --output report.json`
    *   *Kết quả kỳ vọng*: Hệ thống Sensor.Auditor quét 12 bộ Policy khắt khe đánh giá tiêu chuẩn mã hóa. Console báo lỗi màu vàng (Warning) cảnh báo mạng WEP/WPA (tkip) đang dùng cấu hình yếu, xuất báo cáo HTML/JSON rõ ràng.

---

## 9. Các chỉ số Đánh giá Hiệu năng thuật toán (Dành cho Slide báo cáo)
Để hội đồng thấy rõ tính khoa học của hệ thống WIDS, hãy trình bày các số liệu đo lường (Metrics) sau:

*   **Precision (Độ chính xác)**: Tỷ lệ cảnh báo thực sự là tấn công thật so với tổng số cảnh báo WIDS phát ra (`TP / (TP + FP)`). Chỉ số này cao chứng tỏ hệ thống **không bị báo động giả** gây phiền nhiễu.
*   **Recall (Tỷ lệ phát hiện)**: Xác suất cuộc tấn công bị hệ thống tóm gọn so với thực tế các cuộc tấn công đã xảy ra (`TP / (TP + FN)`). Chỉ số này cao chứng tỏ hệ thống **không bỏ lọt tội phạm**.
*   **F1-Score**: Điểm trung bình điều hòa giữa Precision và Recall, phản ánh sức mạnh tổng hợp cân bằng của thuật toán.
*   **MTTD (Mean Time to Detection)**: Thời gian trung bình từ lúc gói tin tấn công đầu tiên bay trong không khí đến khi hệ thống tạo ra một cảnh báo hiển thị trên giao diện (thường đo bằng giây). Yếu tố này quyết định khả năng *phản ứng thời gian thực* của NetLab.

---

## 10. Bộ Câu Hỏi Phản Biện Mở Rộng & Gợi Ý Trả Lời (Q&A)
Dưới đây là một danh sách đồ sộ các câu hỏi hóc búa hội đồng có thể đặt ra, bao quát mọi ngóc ngách của dự án. Bạn hãy học thuộc logic trả lời dựa trên mã nguồn thực tế:

### Nhóm 1: Kiến trúc và Thiết kế Hệ thống
**Q1: "Tại sao lại tách riêng Sensor và Controller? Gộp lại chạy trên 1 máy tính có phải dễ hơn không?"**
*   **Gợi ý**: Chạy gộp chỉ hợp với đồ án môn học nhỏ. Thực tiễn doanh nghiệp cần hàng chục thiết bị cảm biến (Raspberry Pi) rải rác để phủ sóng toàn tòa nhà, trong khi xử lý dữ liệu nặng phải đẩy về máy chủ trung tâm. Kiến trúc Edge-Core giúp dễ mở rộng (Scalability) và nếu Sensor bị trộm, hệ thống CSDL trung tâm vẫn an toàn.

**Q2: "Tại sao em lại dùng PostgreSQL cho Production mà bản Lab lại dùng SQLite? Không sợ lệch hành vi à?"**
*   **Gợi ý**: Dự án dùng SQLAlchemy làm ORM trung gian. Mã nguồn ứng dụng (logic) không tương tác trực tiếp với SQL thô mà qua mô hình Object, do đó hành vi hoàn toàn đồng nhất. Dùng SQLite cho chế độ Lab giúp triển khai cực nhanh bằng 1 lệnh `make lab-up` mà không tốn RAM chạy container DB, phù hợp cho học tập.

**Q3: "Cơ chế quản lý cấu hình (Config) của hệ thống được thực hiện thế nào để tránh rò rỉ?"**
*   **Gợi ý**: (Nhắc đến `sensor/config.py` và `common/security/secrets.py`). Hệ thống áp dụng mẫu thiết kế **Fail-Fast Secrets**. Chìa khóa (API Key, HMAC Secret) bắt buộc phải truyền qua biến môi trường. Nếu quên cấu hình hoặc dùng pass yếu như `admin`, ứng dụng sẽ chủ động Crash ngay lúc khởi động chứ không chạy nhắm mắt. Các cấu hình được export ra ngoài luôn bị "Mask" (che dấu sao `***`).

### Nhóm 2: Hiệu năng và Thuật toán
**Q4: "Làm sao em chứng minh hệ thống xử lý được hàng chục ngàn gói tin trong một cuộc tấn công Deauth Flood mà không bị sập CPU?"**
*   **Gợi ý**: Em đã tối ưu ở 3 lớp:
    1. Tầng Sensor: Gom gói tin thành cụm (**Batching**) và nén **GZIP** trước khi đẩy qua API.
    2. Thuật toán (`algos/dos.py`): Dùng cơ chế **Cửa sổ trượt (Sliding Window)** và cấu trúc `Hash Map` (`dict`/`set`) để tra cứu tốc độ O(1) thay vì duyệt mảng tuyến tính O(N).
    3. Hàng đợi: Dùng Redis Queue để xử lý bất đồng bộ (Asynchronous worker) tách biệt luồng nhận dữ liệu và luồng phân tích học máy.

**Q5: "Thuật toán Evil Twin hoạt động thế nào để không bắt nhầm (False Positive) các cục phát WiFi Mesh (ví dụ Aruba, TP-Link Mesh) cùng SSID?"**
*   **Gợi ý**: Không chỉ dựa vào tên mạng (SSID), thuật toán dùng **Chấm điểm Đa thuộc tính (Weighted Scoring)**:
    *   Xét `RSSI Delta`: Trạm Mesh thường có vùng phủ sóng ổn định, Evil Twin thường có sóng đè cực mạnh.
    *   Xét `Vendor OUI`: Router Mesh thật là Cisco/Aruba, nếu thấy trạm cùng tên mã OUI là Intel/Espressif thì trừ điểm rủi ro cực nặng.
    *   Đặc biệt, có **Confirmation Window** (Cửa sổ chờ xác nhận thời gian) để lọc bỏ nhiễu ngẫu nhiên.

**Q6: "Vai trò của Machine Learning (Autoencoder) trong dự án này là gì? Có bắt buộc phải có không?"**
*   **Gợi ý**: Không bắt buộc nhưng nâng tầm hệ thống (Hybrid ML Boost). Luật cứng (Rule-based) rất tốt nhưng dễ bị vượt qua bằng kỹ thuật mới (Zero-day). Autoencoder (`ml/anomaly_model.py`) học "nhịp độ bình thường" của mạng (Baseline). Khi có sự kiện lạ, nó không tự cảnh báo ngay mà **cộng thêm Anomaly Score** vào Hàm Risk. Cơ chế lai này giúp bắt rủi ro lạ nhưng vẫn kiểm soát tỷ lệ báo động giả.

### Nhóm 3: Bảo mật, Quyền riêng tư và Phục hồi sự cố
**Q7: "Nếu Sensor bắt được gói tin nhưng đứt cáp Internet tới Server, dữ liệu có mất trắng không?"**
*   **Gợi ý**: Dạ không. File `sensor/transport.py` có cài **Circuit Breaker** (Ngắt mạch) và **Spooling** (Hàng đợi đệm SQLite). Mất mạng -> Lưu tạm cục bộ -> Áp dụng **Exponential Backoff** (chờ 1s, 2s, 4s, 8s để thử kết nối lại). Có mạng -> Nhả (flush) toàn bộ dữ liệu bị kẹt (In-flight Recovery) lên Server.

**Q8: "Em thu thập thông tin địa chỉ MAC của điện thoại sinh viên trong trường, có vi phạm quyền riêng tư không?"**
*   **Gợi ý**: Hệ thống tuân thủ GDPR qua file `common/privacy.py`. Có các chế độ `--privacy-mode`. Ở chế độ `oui`, 3 octet cuối của điện thoại bị xóa thành `XX:XX:XX`. Ở chế độ `full`, địa chỉ MAC bị **Hash SHA-256** (băm một chiều trộn với muối ngẫu nhiên `_PRIVACY_SALT`). Hệ thống nhận diện tần suất tấn công dựa trên các "Hash" ẩn danh này, không thể dịch ngược ra người dùng thật.

**Q9: "API Server của em chặn các yêu cầu gửi dữ liệu giả mạo từ hacker như thế nào?"**
*   **Gợi ý**: Mọi luồng API tải lên từ Sensor đều được đính kèm Header `X-Signature`. Chữ ký này sinh ra bằng thuật toán **HMAC-SHA256** băm Payload dữ liệu cùng với `SENSOR_HMAC_SECRET`. Hacker có thể thấy gói tin gửi đi nhưng không thể giả mạo chữ ký nếu không có Secret Key mã hóa trong Sensor.

### Nhóm 4: Kiểm thử và Vận hành
**Q10: "Làm sao em biết các thuật toán Evil Twin, KRACK, hay Deauth của em code đúng nếu không dùng máy tính thật để đi tấn công phá hoại?"**
*   **Gợi ý**: Dự án có cơ chế **PCAP Replay** (tiêm gói tin ảo). Class `PcapCaptureDriver` và `MockCaptureDriver` cho phép bơm các kịch bản mạng (đã được quay lại bằng Wireshark) trực tiếp vào luồng xử lý. Em dùng `pytest` chạy tích hợp luồng (Integration Tests). Nếu đổi code mà lệnh `pytest tests/integration` báo Pass, nghĩa là logic thuật toán vẫn chuẩn 100% không bị thoái lui (Regression).

**Q11: "Trong module phân quyền (RBAC), nếu muốn cấp quyền cho một Admin mới quản lý toàn bộ tính năng, em phải làm thủ công từng quyền à?"**
*   **Gợi ý**: Đọc `controller/api/auth.py`, `Role.ADMIN` được gán động bằng `list(Permission)`. Khi em thêm một tính năng mới (Enum Permission mới), người dùng có Role Admin sẽ tự động thừa kế quyền đó mà không cần sửa DB hay ánh xạ thủ công.

---

## 11. Các Bài Test Tình Huống Thực Tế (Chứng minh Hệ thống Hữu dụng)
Để hội đồng hoàn toàn tin phục rằng hệ thống **thực sự hoạt động được và có giá trị ứng dụng cao**, hãy trình bày 3 bài test mô phỏng các mối đe dọa phổ biến nhất hiện nay:

### 🌟 Bài Test 1: Bảo vệ Sinh viên/Nhân viên khỏi điểm phát WiFi giả mạo (Evil Twin)
*   **Ngữ cảnh thực tế**: Một hacker ngồi ở quán cà phê trước cổng trường, mở laptop phát ra một mạng WiFi không mật khẩu tên là `Truong_DH_Khach`. Sinh viên thấy WiFi miễn phí liền ấn kết nối. Khi sinh viên đăng nhập vào Facebook/Ngân hàng, hacker sẽ dùng Wireshark bắt trọn mật khẩu.
*   **Cách Sentinel NetLab giải quyết (Thực hành)**:
    1.  Cài đặt 1 Sensor (Raspberry Pi) của dự án tại sảnh trường.
    2.  Dùng điện thoại phát 1 mạng tên là `Truong_DH_Khach` (để giả làm hacker).
    3.  **Kết quả**: Chỉ trong vòng 30 giây, thuật toán của NetLab lập tức báo động trên màn hình quản trị của phòng IT: **"Cảnh báo: Phát hiện trạm phát sóng bất thường trùng tên SSID, mã thiết bị (OUI) không thuộc tài sản nhà trường, cường độ sóng cao bất thường"**.
    4.  **Kết luận**: Nhờ có NetLab, bộ phận IT phát hiện ngay lập tức có kẻ xấu đang giăng bẫy trước khi có bất kỳ sinh viên nào bị mất tài khoản.

### 🌟 Bài Test 2: Chống Phá sóng Camera An ninh (Camera Jamming / Deauth Flood)
*   **Ngữ cảnh thực tế**: Kẻ gian muốn đột nhập vào nhà xưởng nhưng sợ bị Camera WiFi ghi hình. Kẻ gian dùng 1 chiếc đồng hồ thông minh hoặc NodeMCU ESP8266 (giá chưa tới 100k VNĐ) liên tục phát ra gói tin "Deauth" (hủy xác thực) ép chiếc Camera văng khỏi mạng WiFi. Camera mất mạng, ngừng ghi hình, và kẻ gian thản nhiên hành động.
*   **Cách Sentinel NetLab giải quyết (Thực hành)**:
    1.  Cho 1 laptop kết nối vào mạng WiFi.
    2.  Bật Kali Linux, chạy lệnh `aireplay-ng --deauth 1000` nhắm thẳng vào MAC của laptop đó. Laptop lập tức bị rớt mạng.
    3.  **Kết quả**: Ngay giây thứ 2 sau khi cuộc tấn công bắt đầu, Dashboard của NetLab chớp đỏ liên hồi: **"Cảnh báo: Tấn công Deauth Flood. Mục tiêu: [MAC_Laptop]. Tốc độ: 150 gói/giây"**.
    4.  **Kết luận**: NetLab chứng minh nó đóng vai trò như một chiếc "Hệ thống báo trộm vô hình", ngay khi sóng WiFi bị can thiệp phá hoại, bảo vệ hoặc chủ nhà lập tức nhận được cảnh báo để kiểm tra hiện trường.

### 🌟 Bài Test 3: Rà soát Định kỳ và Đánh giá Cấu hình (Wardriving & Security Audit)
*   **Ngữ cảnh thực tế**: Công ty mới thuê một tòa nhà làm văn phòng. Giám đốc IT muốn biết xung quanh tòa nhà có những mạng WiFi nào, có mạng nào của hàng xóm đang xài chuẩn WEP cũ (rất dễ bị hack mật khẩu trong 5 phút) và nhân viên công ty vô tình kết nối vào làm lộ lọt dữ liệu nội bộ hay không.
*   **Cách Sentinel NetLab giải quyết (Thực hành)**:
    1.  Mang laptop chạy NetLab đi một vòng quanh hành lang công ty, gõ lệnh rà quét: `python sensor/wardrive.py --iface wlan0mon`.
    2.  Sau 10 phút, hệ thống gom được 100 điểm mạng WiFi quanh đó. Tiếp tục gõ lệnh kiểm toán: `python sensor/audit.py --profile strict --output report.html`.
    3.  **Kết quả**: Module Auditor (với 12 bộ luật Policy kiểm tra Mật mã, Quyền riêng tư, Lỗ hổng) tự động xuất 1 file báo cáo HTML màu đỏ chỉ đích danh: "Mạng WiFi `Cong_Ty_Tang_3` đang dùng mã hóa TKIP lỗi thời, rủi ro cao bị bẻ khóa mật khẩu".
    4.  **Kết luận**: Hệ thống Sentinel NetLab chứng minh giá trị của một công cụ Đánh giá Chủ động (Proactive Security), giúp kỹ sư IT dọn dẹp "lỗ hổng" môi trường thay vì chỉ ngồi đợi hacker tới đánh phá (Bị động).

### 🌟 Bài Test 4: Chống Tấn công Khai thác Chuỗi (Exploit Chain / APT)
*   **Ngữ cảnh thực tế**: Hacker chuyên nghiệp hiếm khi dùng 1 kỹ thuật tấn công duy nhất. Hacker sẽ dùng 1 máy tính để Jamming (phá sóng) mạng WiFi gốc của công ty, đồng thời mở 1 máy tính thứ 2 giả dạng Evil Twin cùng tên để dụ thiết bị kết nối vào.
*   **Cách Sentinel NetLab giải quyết (Thực hành)**:
    1.  Cơ chế `Exploit Chain Analyzer` của hệ thống liên tục "nghe ngóng" các cảnh báo đơn lẻ.
    2.  Hệ thống phát hiện có 1 cuộc tấn công Deauth Flood. Chỉ 5 giây sau, thuật toán Evil Twin lại phát hiện 1 AP lạ mọc lên.
    3.  **Kết quả**: Bộ Correlator (tương quan) của NetLab nhận ra ngay đây là một "Tấn công chuỗi" (Multi-stage Attack). Nó tự động gộp 2 sự kiện rời rạc này thành 1 cảnh báo duy nhất ở mức độ **CRITICAL** (Nghiêm trọng nhất): `MULTI_STAGE_APT_DETECTED`.
    4.  **Kết luận**: Tính năng này giúp phòng SOC không bị choáng ngợp bởi hàng trăm thông báo rác lặp đi lặp lại. Nó chứng minh hệ thống có tư duy thông minh của một chuyên gia phân tích an ninh thực thụ (Threat Hunter).

---

## 12. Cơ chế Độ tin cậy và Tự động Khôi phục (Reliability & Auto-Recovery)
Bên cạnh việc phát hiện chính xác, một hệ thống an ninh mạng cấp doanh nghiệp cần phải có tính kiên cường (Resilience). Dưới đây là 4 lớp bảo vệ mà dự án đã triển khai để chống lại lỗi phần mềm và sự cố môi trường:

### 12.1. Cấp độ Quản lý Tiến trình (Process/Service)
*   **Sensor (Edge)**: Được quản lý bởi dịch vụ hệ điều hành `Systemd` với cấu hình tự động khởi động lại khi có lỗi (`Restart=on-failure`). Để tránh tình trạng khởi động lại liên tục vô tận gây tốn tài nguyên (restart storms), hệ thống áp dụng cơ chế chờ (`RestartSec=5s`) và giới hạn số lần khởi động lại khắt khe (`StartLimitIntervalSec=300` và `StartLimitBurst=3`).
*   **Controller / Dashboard (Core)**: Lớp lõi được triển khai qua hệ sinh thái Docker Compose với chính sách `restart: unless-stopped` cho tất cả các service (API, Worker, Database, Redis, v.v.). Hệ thống cũng tích hợp các cơ chế `Healthchecks` chuyên sâu để phân biệt giữa trạng thái "đang chạy nhưng bị treo" và "đã crash hẳn", từ đó có biện pháp xử lý phù hợp.

### 12.2. Cấp độ Ứng dụng (Application-Level / Fail-fast)
*   Thay vì phó mặc sinh mệnh cho Hệ điều hành (OS) quyết định khởi động lại tiến trình, ứng dụng Sensor sở hữu vòng lặp tự kiểm tra trạng thái hoạt động bên trong (Health-loop).
*   Vòng lặp này sẽ liên tục tự đặt câu hỏi: *"Card mạng còn đang ở chế độ giám sát (Monitor mode) không?"* và *"Có gói tin nào mới được nhận trong 30 giây qua không?"*. Nếu bất kỳ câu trả lời nào là không và lặp lại quá số lần cho phép, ứng dụng sẽ chủ động chọn chiến lược **"Fail-fast"** (Tự tử tiến trình/Thoát ngay lập tức) để ép Systemd phải khởi động lại toàn bộ chu trình một cách sạch sẽ.

### 12.3. Cấp độ Phần cứng (Hardware / USB Watchdog)
*   Hệ thống có trang bị một module `USBWatchdog` chạy ngầm, chuyên nhiệm vụ giám sát kết nối vật lý của chiếc USB WiFi adapter.
*   Nếu phát hiện USB bị lỏng, ngắt kết nối đột ngột hoặc xảy ra lỗi Firmware, nó có khả năng tự động khôi phục (Auto-recovery) bằng cách thử tháo gỡ và nạp lại driver mạng (thông qua lệnh `modprobe -r` và `modprobe`) mà hoàn toàn không cần sự can thiệp thủ công của con người (IT Admin).

### 12.4. Khôi phục Dữ liệu (Reliability & Spooling)
*   **Persistent Queue**: Nếu kết nối mạng đường dài từ điểm đặt Sensor về trung tâm Controller bị đứt, dữ liệu bắt được sẽ không bao giờ bị mất. Sentinel NetLab sử dụng hàng đợi lưu trữ cố định (Persistent Queue) ghi thẳng xuống cơ sở dữ liệu nội bộ SQLite (Spool) để lưu tạm dữ liệu ngay tại bộ nhớ của Sensor.
*   **Exponential Backoff**: Nó sở hữu cơ chế thử gửi lại dữ liệu (retry) với thời gian chờ tăng dần theo cấp số nhân (exponential backoff) nếu việc tải lên thất bại, tránh việc spam làm sập thêm mạng.
*   **In-flight Recovery**: Trong trường hợp tồi tệ nhất là cúp điện hoặc crash đột ngột ngay trong lúc gói tin đang bay trên đường truyền (trạng thái 'inflight'), hệ thống được thiết kế vòng đời giao dịch thông minh để tự động khôi phục các gói tin bị kẹt này về lại trạng thái chờ gửi (pending) ngay trong lần khởi động tiếp theo.

---

## Tổng kết

Sentinel NetLab không phải là một bài tập lớn chắp vá, mà là một **sản phẩm phần mềm thực thụ**. Dự án tuân thủ đầy đủ các nguyên lý về Thiết kế phần mềm (Design Patterns), Kiến trúc phân tán chịu lỗi (Microservices/Edge Computing), có cơ chế Test bao phủ tự động (CI/CD Ready), và tư duy bảo mật (Security by Design) ngay từ những dòng code đầu tiên. Với danh sách kịch bản kiểm thử toàn diện trên, hội đồng có thể hoàn toàn an tâm về chất lượng kỹ thuật của hệ thống này.
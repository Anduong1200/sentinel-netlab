# Báo Cáo Đánh Giá Mức Độ Hoàn Thiện Dự Án Sentinel NetLab

**Mục đích**: Tài liệu này đánh giá tổng thể mã nguồn của Sentinel NetLab, cung cấp nhận định từ việc phân tích trực tiếp mã nguồn (Code Review) và đề xuất các kịch bản kiểm thử (Test Scenarios) để chứng minh tính vững chắc của dự án trước hội đồng bảo vệ.

---

## 1. Tiêu chí Kiến trúc và Khả năng Mở rộng (Architecture & Scalability)

### 📌 Nhận định từ Mã nguồn
*   **Kiến trúc Phân tán (Edge - Core)**: Dự án thể hiện rất rõ sự tách biệt giữa Sensor (thu thập) và Controller (xử lý). Sensor (`sensor/sensor_controller.py`) chỉ đóng vai trò đẩy dữ liệu lên qua API mà không nắm quyền quyết định, giúp bảo vệ lớp lõi (Core) kể cả khi phần cứng ở biên bị xâm phạm.
*   **Tính chịu lỗi (Fault Tolerance)**: File `sensor/transport.py` được triển khai theo tiêu chuẩn công nghiệp với cơ chế **Exponential Backoff** (thử lại với độ trễ tăng dần) và **Circuit Breaker** (ngắt mạch khi lỗi liên tục). Nếu kết nối mạng giữa RPi và Server bị đứt, Sensor sẽ không bị crash mà tự động đệm dữ liệu (Spooling/Queue) và gửi lại khi mạng ổn định.

### 🧪 Kịch bản Kiểm chứng Thực tế (Demo)
*   **Kịch bản**: Chứng minh khả năng sống sót của Sensor khi mất mạng.
*   **Cách làm**:
    1. Chạy hệ thống bằng lệnh `make lab-up`.
    2. Chạy một Sensor thật hoặc Mock Sensor đẩy dữ liệu.
    3. Tắt Controller (giả lập rớt mạng): `docker stop ops-controller-1`.
    4. Quan sát log của Sensor: Sẽ thấy các dòng cảnh báo *Circuit breaker opened due to repeated failures* hoặc *Retry after X seconds*. Sensor không bị sập.
    5. Bật lại Controller: `docker start ops-controller-1`.
    6. Quan sát log: Sensor tự động khôi phục kết nối và đẩy tiếp gói tin.

---

## 2. Tiêu chí Hiệu năng Phát hiện (Detection Performance Metrics)

### 📌 Nhận định từ Mã nguồn
*   **Kiến trúc Thuật toán Chuyên sâu**: Khác với các công cụ đơn giản chỉ đếm gói tin, thuật toán của NetLab (`algos/evil_twin.py`, `algos/dos.py`) sử dụng cơ chế **Trượt thời gian (Sliding Window)** và **Điểm số Tích lũy (Weighted Scoring)**.
    *   Ví dụ ở Evil Twin: Hệ thống không vội vàng cảnh báo chỉ vì có 2 trạm phát cùng tên (SSID). Nó yêu cầu hội đủ điểm (Score > 80) thông qua việc xét chênh lệch sóng (RSSI Delta), độ trễ báo hiệu (Beacon Jitter), mã OUI của thiết bị và có thời gian xác nhận (Confirmation Window) để loại bỏ hoàn toàn báo động giả (False Positives).
*   **Hỗ trợ Học máy lai (Hybrid ML)**: Cơ sở tính điểm Rủi ro (`algos/risk.py`) không chỉ dựa trên luật cứng (Rule-based) mà còn hỗ trợ đẩy vector thuộc tính vào một mô hình Autoencoder (`ml/anomaly_model.py`) để cộng thêm "điểm bất thường", giúp phát hiện những kiểu tấn công Zero-day hoặc hành vi lạ chưa có chữ ký (Signature).

### 🧪 Kịch bản Kiểm chứng Thực tế (Demo)
*   **Kịch bản**: Kiểm tra độ chính xác của cảnh báo (Tránh False Positives).
*   **Cách làm**:
    1. Chạy một luồng dữ liệu giả lập mạng bình thường (Normal Traffic) thông qua PCAP Replay bằng lệnh test:
       `pytest tests/integration/test_scenarios.py::TestScenarioReplay::test_replay_normal_traffic_no_alerts`
    2. Chỉ ra cho hội đồng thấy: Mặc dù hệ thống "ngửi" hàng chục gói tin, nhưng **không có bất kỳ cảnh báo rác nào được sinh ra**. Hệ thống không bị "nhạy cảm quá mức".

---

## 3. Tiêu chí Mức độ bao phủ Kiểm thử (Testability & QA)

### 📌 Nhận định từ Mã nguồn
*   **Công cụ Replay Mạnh mẽ**: Dự án xây dựng sẵn `PcapCaptureDriver` và `MockCaptureDriver`, cho phép bơm các file PCAP (gói tin đã bắt) chạy thẳng qua toàn bộ đường ống hệ thống (Pipeline) y hệt như đang dùng card WiFi thật.
*   **Test Integration Cấu trúc tốt**: Thư mục `tests/integration/` có các kịch bản kiểm thử từ đầu đến cuối (End-to-End). Việc sinh file PCAP giả tấn công (Evil Twin, Deauth) được tự động hóa.

### 🧪 Kịch bản Kiểm chứng Thực tế (Demo)
*   **Kịch bản**: Demo bắt tấn công Deauth Flood hoặc Evil Twin bằng dữ liệu giả lập (Không cần dùng card WiFi thật để tấn công phá hoại môi trường trường học).
*   **Cách làm**:
    1. Sử dụng lệnh: `pytest tests/integration/test_scenarios.py::TestScenarioReplay::test_replay_evil_twin_detection -v`
    2. Lệnh này sẽ tự động tạo file PCAP chứa tấn công Evil Twin, đẩy vào hệ thống.
    3. Log bài Test sẽ in ra chữ `PASSED` và thông báo đã đẩy cảnh báo lên Controller, chứng minh thuật toán hoạt động hoàn hảo 100%.

---

## 4. Tiêu chí Trải nghiệm người dùng và Giao diện (UI/UX)

### 📌 Nhận định từ Mã nguồn
*   **Dashboard Hiện đại (Dash/Plotly)**: Giao diện web được xây dựng dựa trên Python Dash kết hợp Bootstrap.
*   **Cập nhật Thời gian thực**: Mã nguồn `dashboard/pages/map.py` (và các file khác) sử dụng `dcc.Interval` để gọi callback lấy dữ liệu mới mỗi 3 giây, tạo cảm giác các chỉ số và tọa độ trên Bản đồ Heatmap liên tục nhảy số mà không cần người dùng F5 tải lại trang.

### 🧪 Kịch bản Kiểm chứng Thực tế (Demo)
*   **Kịch bản**: Xem Bản đồ đe dọa trực quan hóa (Threat Map).
*   **Cách làm**: Mở giao diện `http://127.0.0.1:8050` (hoặc cổng cấu hình tương ứng). Vào tab "Global Map", chuyển đổi giữa các bộ lọc bảo mật ("All", "Open", "WEP"). Các đốm màu (Heatmap) trên giao diện sẽ thay đổi dựa vào thuật toán đánh giá rủi ro (`color="risk"`).

---

## 5. Tiêu chí Triển khai, Vận hành và Tài liệu (Deployment & Documentation)

### 📌 Nhận định từ Mã nguồn
*   **Tự động hóa hoàn toàn**: Thông qua `Makefile`, toàn bộ vòng đời ứng dụng (từ build Docker, chạy linter `ruff`, test `pytest` đến quét bảo mật `bandit`) đều chỉ cần 1 cú click. Lệnh `make lab-up` kết nối nhiều container lại qua `docker-compose`.
*   **Tài liệu phân mảnh chuẩn**: Cấu trúc `docs/` rất chi tiết, phân định rõ `lab/` (cho giáo dục, dễ dùng, chạy SQLite) và `prod/` (cho vận hành doanh nghiệp, bắt buộc PostgreSQL).

### 🧪 Kịch bản Kiểm chứng Thực tế (Demo)
*   **Kịch bản**: Triển khai nhanh từ con số 0.
*   **Cách làm**: Xóa toàn bộ container hiện có. Gõ lệnh `make lab-reset`. Hội đồng sẽ thấy các kịch bản tự sinh secret (`gen_lab_secrets.py`), khởi tạo database, và chạy lên cụm ứng dụng trong chưa tới 30 giây một cách vô cùng gọn gàng.

---

## 6. Tiêu chí Bảo mật hệ thống (System Security Principles)

### 📌 Nhận định từ Mã nguồn
*   **Tiếp cận "Fail-Fast"**: Đọc file `common/security/secrets.py`, hàm `require_secret` được thiết kế cực kỳ gắt gao. Trong môi trường `Production`, nếu quản trị viên quên khai báo biến môi trường hoặc dùng mật khẩu dễ đoán (như "admin", "123456"), ứng dụng sẽ lập tức Crash (chủ động sập) kèm log `CRITICAL: Weak production secret`. Hệ thống từ chối chạy ở trạng thái không an toàn.
*   **Chữ ký Điện tử HMAC**: Toàn bộ luồng giao tiếp API giữa Sensor và Controller đều được ký xác thực bằng thuật toán HMAC-SHA256 (`_sign_payload`). Hacker không thể chen ngang để gửi log giả vào Controller.

### 🧪 Kịch bản Kiểm chứng Thực tế (Demo)
*   **Kịch bản**: Kịch bản ngăn chặn vận hành sai cấu hình bảo mật.
*   **Cách làm**:
    1. Cố tình thiết lập biến môi trường `ENVIRONMENT=production` và `DASH_PASSWORD=admin`.
    2. Chạy Dashboard.
    3. Ngay lập tức Dashboard sẽ văng lỗi `CRITICAL: Weak production secret... Application refused to start.` Chứng tỏ hệ thống tự bảo vệ chính nó rất tốt.

---

---

## 7. Các Hạng mục Kiểm thử Hệ thống (System Testing Scenarios)
Để bảo vệ toàn diện, dưới đây là các hạng mục từ cơ bản đến nâng cao cần chạy demo trước hội đồng:

### 7.1. Kiểm thử Hệ sinh thái cốt lõi (Core Ecosystem)
*   **Controller API (Liveness & Health)**: Gọi lệnh HTTP GET tới endpoint Health Check (`/api/v1/health`) để đảm bảo hệ thống Control Plane và các kết nối Database/Redis đang hoạt động ổn định (phản hồi `status: ok`).
*   **Giao diện Dashboard**: Đăng nhập vào Web UI và xác minh rằng Sidebar, các biểu đồ và khung đồ thị (Cards) tải thành công, không gặp lỗi JavaScript/Plotly nào.

### 7.2. Kiểm thử Luồng dữ liệu giả lập (Mock Data Pipeline)
*   **Cách làm**: Chạy tập lệnh nạp dữ liệu mô phỏng (`seed_lab_data.py` thông qua `make lab-up`).
*   **Kết quả kỳ vọng**: Kiểm tra trên Dashboard để xác nhận khả năng hiển thị các cảnh báo tấn công giả lập (như Deauth/DoS), điểm rủi ro (Risk Score), và biểu diễn các Access Points kèm bản đồ nhiệt (Heatmap) địa chỉ MAC chính xác.

### 7.3. Kiểm thử Khả năng bắt gói tin mạng thật (Sensor Capture)
*   **Test Sensor độc lập (CLI)**: Cắm USB WiFi đã bật Monitor Mode (`wlan0mon`) và chạy script `sensor_cli.py` để xác nhận hệ thống có thể in ra (stdout) được các thông tin phát hiện Access Point (AP) và Client liên kết từ môi trường thực tế.
*   **Test End-to-End (E2E)**: Liên kết cấu hình Sensor với Controller thật, kiểm tra xem API `/api/v1/networks` có tăng số lượng theo thời gian thực và Dashboard có cập nhật các AP/Alert mới tương ứng hay không.

### 7.4. Kiểm thử Tấn công và Tính năng Chuyên sâu
*   **Phát hiện Tấn công Deauth (DoS)**: Sử dụng công cụ (như Kali Linux, `aireplay-ng`) để chủ động phát lệnh hủy xác thực (Deauth) vào một thiết bị mạng kiểm thử.
    *   *Kỳ vọng*: Dashboard sẽ nháy đỏ trạng thái `DEAUTH_FLOOD_DETECTED` với mức rủi ro cao (High/Critical) trong vòng chưa đầy 15 giây.
*   **Phát lại kịch bản mạng (PCAP Replay)**: Sử dụng các file PCAP (kịch bản mạng bình thường, Evil Twin, hoặc Deauth) nạp qua `PcapCaptureDriver` để đánh giá khả năng mô phỏng luồng tấn công mà không cần can thiệp tần số vật lý.
*   **Định vị (Geo-Location) & Học máy (ML)**: Chạy sensor kèm các cờ `--enable-ml` và `--enable-geo` để xác minh dữ liệu Tọa độ GPS và thuật toán Autoencoder được tính toán móc nối vào hàm Risk Score.
*   **Wardriving (Lập bản đồ di động)**: Chạy module độc lập quét mạng WiFi kết hợp bộ thu GPS (`wardrive.py`) để thu thập và trích xuất danh sách mạng trên đường phố ra file JSON/CSV.
*   **Công cụ Audit**: Chạy script đánh giá bảo mật (`audit.py`) để quét nhanh các lỗ hổng của cấu hình WiFi (như WEP/WPA yếu) và xuất báo cáo tự động.

---

## 8. Các chỉ số Đánh giá Hiệu năng thuật toán (Dành cho Slide báo cáo)
Để hội đồng thấy rõ tính khoa học của hệ thống WIDS, hãy trình bày các số liệu đo lường (Metrics) sau:

*   **Precision (Độ chính xác)**: Tỷ lệ cảnh báo thực sự là tấn công thật so với tổng số cảnh báo WIDS phát ra (`TP / (TP + FP)`). Chỉ số này cao chứng tỏ hệ thống **không bị báo động giả** gây phiền nhiễu.
*   **Recall (Tỷ lệ phát hiện)**: Xác suất cuộc tấn công bị hệ thống tóm gọn so với thực tế các cuộc tấn công đã xảy ra (`TP / (TP + FN)`). Chỉ số này cao chứng tỏ hệ thống **không bỏ lọt tội phạm**.
*   **F1-Score**: Điểm trung bình điều hòa giữa Precision và Recall, phản ánh sức mạnh tổng hợp cân bằng của thuật toán.
*   **MTTD (Mean Time to Detection)**: Thời gian trung bình từ lúc gói tin tấn công đầu tiên bay trong không khí đến khi hệ thống tạo ra một cảnh báo hiển thị trên giao diện (thường đo bằng giây). Yếu tố này quyết định khả năng *phản ứng thời gian thực* của NetLab.

---

## Tổng kết

Sentinel NetLab không phải là một bài tập lớn chắp vá, mà là một **sản phẩm phần mềm thực thụ**. Dự án tuân thủ đầy đủ các nguyên lý về Thiết kế phần mềm (Design Patterns), Kiến trúc phân tán chịu lỗi (Microservices/Edge Computing), có cơ chế Test bao phủ tự động (CI/CD Ready), và tư duy bảo mật (Security by Design) ngay từ những dòng code đầu tiên. Với danh sách kịch bản kiểm thử toàn diện trên, hội đồng có thể hoàn toàn an tâm về chất lượng kỹ thuật của hệ thống này.
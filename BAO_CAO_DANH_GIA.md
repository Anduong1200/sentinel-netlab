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
Để bảo vệ toàn diện, dưới đây là chi tiết các kịch bản demo (Runbook) từ cơ bản đến nâng cao cần thực hiện trực tiếp trên máy trước hội đồng:

### 7.1. Kiểm thử Hệ sinh thái cốt lõi (Core Ecosystem)
*   **Controller API (Liveness & Health)**: Chứng minh Control Plane và Database/Redis đang kết nối trơn tru.
    *   *Lệnh thực thi*: `curl -s http://127.0.0.1:5000/api/v1/health | jq`
    *   *Kết quả kỳ vọng*: Terminal trả về mã JSON có trường `"status": "ok"` và hiển thị phiên bản (version), thời gian (timestamp).
*   **Giao diện Dashboard**: Chứng minh Frontend (UI/UX) không bị sập.
    *   *Cách làm*: Mở trình duyệt truy cập `http://127.0.0.1:8050`. Chuyển đổi qua lại giữa các Tab (Overview, Threats, Global Map).
    *   *Kết quả kỳ vọng*: Sidebar phản hồi tức thì, các biểu đồ Plotly render dữ liệu (hoặc khung trống an toàn nếu chưa có mạng) mà không hiện lỗi 404 hay trắng trang.

### 7.2. Kiểm thử Luồng dữ liệu giả lập (Mock Data Pipeline)
*   Mục đích: Chứng minh cơ chế Pipeline (Sensor -> Controller -> Database -> Dashboard) hoạt động mượt mà khi nhận dữ liệu giả.
*   *Cách làm*: Chạy tập lệnh nạp dữ liệu mô phỏng: `make lab-up` (lệnh này tự động gọi script `seed_lab_data.py`).
*   *Kết quả kỳ vọng*:
    1. Nhìn vào màn hình Terminal thấy log sinh ra hàng loạt gói tin giả mạo.
    2. Nhìn lên Dashboard, các bộ đếm số lượng Mạng (Networks) và Điểm rủi ro (Risk Score) bắt đầu thay đổi. Bản đồ nhiệt (Heatmap) xuất hiện các điểm màu đỏ (tương ứng với cảnh báo rủi ro cao).

### 7.3. Kiểm thử Khả năng bắt gói tin mạng thật (Sensor Capture)
*   **Test Sensor độc lập (CLI)**: Chứng minh Driver card WiFi (Monitor Mode) tương tác tốt với hệ điều hành và bắt được gói tin thực tế (Không dùng mạng WiFi của trường học để tránh vi phạm đạo đức, hãy dùng một điểm phát 4G từ điện thoại).
    *   *Lệnh thực thi*: Khởi động Monitor mode: `sudo airmon-ng start wlan0`. Sau đó chạy Sensor: `sudo python sensor/sensor_cli.py --iface wlan0mon`.
    *   *Kết quả kỳ vọng*: Màn hình in ra các gói tin (Beacons/Probes) với BSSID thật, SSID thật của điện thoại phát ra.
*   **Test End-to-End (E2E)**: Chứng minh dữ liệu thực tế đẩy thành công lên Server.
    *   *Cách làm*: Kết hợp lệnh `--config config.yaml` để bật kết nối API. Mở tab "Signals" trên Dashboard.
    *   *Kết quả kỳ vọng*: Địa chỉ MAC của điện thoại (SSID thử nghiệm) phải xuất hiện trên bảng tín hiệu thời gian thực (Real-time signals).

### 7.4. Kiểm thử Tấn công và Tính năng Chuyên sâu

*   **A. Tấn công Từ chối Dịch vụ (Deauth Flood)**:
    *   *Cách làm*: Sử dụng Kali Linux. Khóa mục tiêu vào thiết bị thử nghiệm. Lệnh: `sudo aireplay-ng --deauth 100 -a [MAC_ROUTER] -c [MAC_CLIENT] wlan0mon`.
    *   *Kết quả kỳ vọng*: Luồng dữ liệu bùng nổ, thuật toán `algos/dos.py` phát hiện tốc độ gói tin tăng vọt. Trên Dashboard tab "Threats", lập tức xuất hiện thẻ cảnh báo màu đỏ chót nhấp nháy `DEAUTH_FLOOD_DETECTED`, MTTD (Thời gian phát hiện) đo được dưới 10 giây.

*   **B. Phát lại kịch bản mạng (PCAP Replay) cho Evil Twin**:
    *   *Mục đích*: Chứng minh khả năng phát hiện AP giả mạo (Evil Twin) khi không có điều kiện mang 2 củ phát WiFi vật lý lên hội trường.
    *   *Cách làm*: Nạp file PCAP đã ghi hình trước: `pytest tests/integration/test_scenarios.py::TestScenarioReplay::test_replay_evil_twin_detection -v`.
    *   *Kết quả kỳ vọng*: `PASSED`. Log sẽ chỉ ra rằng hệ thống đã "thấy" sự xuất hiện của 1 BSSID khác nhưng phát cùng SSID, chênh lệch sóng (RSSI) bất thường, và OUI Vendor sai lệch. Cảnh báo Evil Twin được bắn lên hệ thống.

*   **C. Định vị (Geo-Location) & Học máy (ML)**:
    *   *Lệnh thực thi*: `python sensor/sensor_cli.py --enable-ml --enable-geo --gps /dev/ttyUSB0`
    *   *Kết quả kỳ vọng*: Điểm Risk Score của một Access Point sẽ bị cộng thêm 20 điểm (Anomaly Boost) nếu Autoencoder thấy hành vi dị thường. Dữ liệu GPS đẩy lên làm thay đổi vị trí ghim trên Bản đồ (Global Map).

*   **D. Lập bản đồ mạng di động (Wardriving)**:
    *   *Lệnh thực thi*: `python sensor/wardrive.py --iface wlan0mon --output session.json`
    *   *Kết quả kỳ vọng*: File `session.json` sinh ra với danh sách các mạng, toạ độ, chuẩn mã hóa. File này có thể import lên giao diện Live Viewer (`live_wardrive_viewer.py`) để quan sát ngoại tuyến.

*   **E. Công cụ Kiểm toán Bảo mật (Audit)**:
    *   *Lệnh thực thi*: `python sensor/audit.py --profile home --output report.json`
    *   *Kết quả kỳ vọng*: Console báo lỗi màu vàng (Warning) cảnh báo mạng WEP/WPA (tkip) đang dùng cấu hình yếu, xuất báo cáo HTML/JSON rõ ràng.

---

## 8. Các chỉ số Đánh giá Hiệu năng thuật toán (Dành cho Slide báo cáo)
Để hội đồng thấy rõ tính khoa học của hệ thống WIDS, hãy trình bày các số liệu đo lường (Metrics) sau:

*   **Precision (Độ chính xác)**: Tỷ lệ cảnh báo thực sự là tấn công thật so với tổng số cảnh báo WIDS phát ra (`TP / (TP + FP)`). Chỉ số này cao chứng tỏ hệ thống **không bị báo động giả** gây phiền nhiễu.
*   **Recall (Tỷ lệ phát hiện)**: Xác suất cuộc tấn công bị hệ thống tóm gọn so với thực tế các cuộc tấn công đã xảy ra (`TP / (TP + FN)`). Chỉ số này cao chứng tỏ hệ thống **không bỏ lọt tội phạm**.
*   **F1-Score**: Điểm trung bình điều hòa giữa Precision và Recall, phản ánh sức mạnh tổng hợp cân bằng của thuật toán.
*   **MTTD (Mean Time to Detection)**: Thời gian trung bình từ lúc gói tin tấn công đầu tiên bay trong không khí đến khi hệ thống tạo ra một cảnh báo hiển thị trên giao diện (thường đo bằng giây). Yếu tố này quyết định khả năng *phản ứng thời gian thực* của NetLab.

---

## 9. Bộ Câu Hỏi Phản Biện Dự Kiến & Gợi Ý Trả Lời (Q&A)
Dưới đây là một số câu hỏi hội đồng có thể đặt ra dựa trên kiến trúc của Sentinel NetLab, kèm theo cách trả lời (bám sát mã nguồn và thiết kế hệ thống):

### Q1: "Tại sao lại tách riêng Sensor và Controller? Nếu gộp lại chạy trên 1 máy tính có phải dễ hơn không?"
*   **Gợi ý trả lời**: Việc gộp chung rất dễ cho sinh viên làm đồ án nhỏ, nhưng **không mang tính thực tiễn công nghiệp**. Trong thực tế, các doanh nghiệp hoặc tòa nhà có diện tích lớn cần đặt hàng chục thiết bị cảm biến (Sensor như Raspberry Pi) rải rác để thu thập sóng WiFi, trong khi dữ liệu cần được xử lý tập trung ở một Server mạnh (Controller). Kiến trúc phân tán (Distributed) giúp:
    1.  **Dễ mở rộng (Scalability)**: Gắn thêm bao nhiêu Sensor cũng được mà không làm chậm Server.
    2.  **Bảo mật (Security)**: Nếu một Sensor ở ngoài sảnh bị hacker tháo trộm, hệ thống cốt lõi vẫn an toàn vì Sensor không chứa Database hay toàn quyền quản trị.

### Q2: "Thuật toán Evil Twin của em hoạt động thế nào để tránh bắt nhầm (False Positive) các cục phát WiFi mesh (như Google WiFi, TP-Link Mesh) phát cùng tên SSID?"
*   **Gợi ý trả lời**: Hệ thống của em không chỉ nhìn vào tên mạng (SSID) mà dùng cơ chế **Chấm điểm Đa thuộc tính (Weighted Scoring)** (có thể mở code `algos/evil_twin.py` để minh họa):
    1.  Em kiểm tra độ chênh lệch sóng (`RSSI Delta`). Điểm Mesh hợp lệ thường có vùng phủ sóng riêng, nhưng Evil Twin thường cố ý phát sóng cực mạnh đè lên sóng thật.
    2.  Em kiểm tra mã nhà sản xuất (Vendor OUI). Router thật của trường là Cisco, nếu có cục phát cùng tên nhưng mã OUI là Intel/TP-Link thì bị trừ điểm rủi ro rất nặng.
    3.  Em kiểm tra độ lệch thời gian Beacon (`Beacon Jitter`) và loại mã hóa (Security Mismatch).
    4.  Đặc biệt, hệ thống có **Confirmation Window** (Cửa sổ xác nhận), không cảnh báo ngay ở gói tin đầu tiên mà theo dõi sự kiên định của trạm phát để lọc nhiễu.

### Q3: "Vai trò của Machine Learning (Autoencoder) trong hệ thống này là gì? Có thực sự cần thiết không?"
*   **Gợi ý trả lời**: Các thuật toán rập khuôn (Rule-based) như so sánh chữ ký rất tốt nhưng dễ bị vượt qua nếu hacker đổi thủ đoạn (Zero-day). Em áp dụng cơ chế Học máy lai (**Hybrid ML Boost**).
    *   Mô hình Autoencoder (`ml/anomaly_model.py`) sẽ học các "hành vi bình thường" của mạng.
    *   Khi có sự kiện mới, nó không tự mình ra quyết định cảnh báo ngay, mà nó **cộng thêm điểm bất thường (Anomaly Score)** vào Hàm Risk Score. Cơ chế này giúp hệ thống linh hoạt phát hiện rủi ro lạ mà vẫn kiểm soát được tỷ lệ báo động giả (False Positive).

### Q4: "Nếu Sensor bắt được gói tin nhưng bị đứt kết nối Internet tới Controller, dữ liệu có bị mất không?"
*   **Gợi ý trả lời**: Dạ không ạ. Trong mã nguồn phần truyền tải (`sensor/transport.py`), em đã cài đặt cơ chế **Circuit Breaker** (Ngắt mạch) và **Spooling** (Hàng đợi đệm). Khi mất mạng, Sensor tự động lưu tạm gói tin vào bộ nhớ/ổ đĩa. Cơ chế **Exponential Backoff** sẽ thử kết nối lại với độ trễ tăng dần (tránh làm sập mạng khi có lại). Khi có mạng, Sensor sẽ dội toàn bộ gói tin cũ lên Controller.

### Q5: "Làm sao em chứng minh hệ thống của em xử lý được hàng ngàn gói tin trong một cuộc tấn công từ chối dịch vụ (Deauth Flood) mà không bị sập hay giật lag (Bottleneck)?"
*   **Gợi ý trả lời**: Em đã tối ưu ở 2 lớp:
    1.  **Lớp Sensor**: Không gửi từng gói tin một, mà dùng cơ chế **Batching** (Gom cụm) và nén **GZIP** trước khi gửi qua API để tiết kiệm băng thông.
    2.  **Lớp Cấu trúc dữ liệu**: Thuật toán của em (như `algos/dos.py`) dùng cấu trúc dữ liệu hiệu quả cao như Sliding Window (Cửa sổ trượt) và Hash Map để tra cứu tốc độ O(1) thay vì duyệt mảng O(N). Do đó, việc nạp 1 file PCAP chứa hàng chục ngàn gói tin vẫn được xử lý trong thời gian tính bằng mili-giây.

---

## Tổng kết

Sentinel NetLab không phải là một bài tập lớn chắp vá, mà là một **sản phẩm phần mềm thực thụ**. Dự án tuân thủ đầy đủ các nguyên lý về Thiết kế phần mềm (Design Patterns), Kiến trúc phân tán chịu lỗi (Microservices/Edge Computing), có cơ chế Test bao phủ tự động (CI/CD Ready), và tư duy bảo mật (Security by Design) ngay từ những dòng code đầu tiên. Với danh sách kịch bản kiểm thử toàn diện trên, hội đồng có thể hoàn toàn an tâm về chất lượng kỹ thuật của hệ thống này.
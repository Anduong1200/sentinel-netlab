# Bộ Câu Hỏi Bảo Vệ Đồ Án Tốt Nghiệp: Sentinel NetLab
*(Sắp xếp từ dễ đến khó theo từng phần)*

---

## Phần 1: Tổng quan dự án & Kiến trúc hệ thống

**Câu 1: Sentinel NetLab là gì?**
**Trả lời:** Là một hệ thống phát hiện xâm nhập mạng không dây (WIDS) phân tán, lai ghép (hybrid). Nó kết hợp giữa phát hiện dựa trên luật (signature-based) và phân tích bất thường bằng Machine Learning để giám sát, cảnh báo các mối đe dọa trên mạng WiFi.

**Câu 2: Tại sao gọi dự án này là hệ thống "WIDS" thay vì "WIPS"?**
**Trả lời:** Vì hệ thống chỉ tập trung vào việc giám sát, thu thập dữ liệu thụ động (Passive Monitoring) và cảnh báo (Intrusion Detection - IDS) các cuộc tấn công. Nó không thực hiện các hành động can thiệp chủ động (như gửi gói tin ngắt kết nối lại kẻ tấn công) để ngăn chặn (Intrusion Prevention - IPS), nhằm đảm bảo tuân thủ pháp luật và đạo đức bảo mật.

**Câu 3: Kiến trúc của Sentinel NetLab gồm những thành phần chính nào?**
**Trả lời:** Hệ thống có 3 thành phần chính:
1. **Sensor Layer (Edge):** Các cảm biến (như Raspberry Pi) thu thập gói tin WiFi, tiền xử lý và chạy các thuật toán phát hiện tại biên.
2. **Controller Layer (Core):** Máy chủ trung tâm (Flask API) nhận dữ liệu từ cảm biến, lưu trữ, đánh giá rủi ro tổng thể và quản lý cảnh báo.
3. **Dashboard:** Giao diện web (Dash/Plotly) để trực quan hóa dữ liệu và bản đồ nhiệt theo thời gian thực.

**Câu 4: Dự án sử dụng những công nghệ lõi nào?**
**Trả lời:** Backend và Sensor viết bằng Python 3.11+. Dữ liệu được lưu ở PostgreSQL, dùng Redis làm message queue/cache. Mô hình Machine Learning sử dụng PyTorch. Giao diện dùng Plotly Dash.

**Câu 5: Tại sao hệ thống lại xử lý thuật toán phát hiện (như Evil Twin, DoS) ngay tại Sensor thay vì gửi toàn bộ gói tin về Controller xử lý?**
**Trả lời:** Việc này gọi là Edge Computing (xử lý tại biên). Giúp giảm tải băng thông mạng (không cần gửi toàn bộ gói tin PCAP lớn về server), giảm độ trễ cảnh báo (phát hiện và cảnh báo ngay lập tức), và tăng tính riêng tư (chỉ gửi metadata/chỉ số thay vì nội dung gói tin).

---

## Phần 2: Cảm biến (Sensor) & Thu thập dữ liệu

**Câu 6: Cảm biến (Sensor) hoạt động ở chế độ mạng nào để thu thập dữ liệu?**
**Trả lời:** Cảm biến bắt buộc phải hoạt động ở **Monitor Mode** (chế độ giám sát) để có thể bắt được các Management Frames (gói tin quản lý 802.11) của mọi thiết bị xung quanh mà không cần kết nối vào mạng WiFi đó.

**Câu 7: Quá trình (Pipeline) xử lý dữ liệu của Sensor diễn ra như thế nào?**
**Trả lời:** Gồm 4 bước:
1. **Ingestor:** Driver (IwCapture/MockCapture) đọc gói tin thô.
2. **Parser & Normalizer:** Giải mã khung 802.11, chuẩn hóa dữ liệu thành JSON và ẩn danh MAC address.
3. **Analyzer:** Đưa siêu dữ liệu qua các engine phát hiện (Evil Twin, DoS, KRACK...).
4. **Exporter:** Đẩy dữ liệu vào hàng đợi (Spool queue) để gửi lên Controller theo từng lô (batch).

**Câu 8: Tính năng "Channel Hopping" trong Sensor có tác dụng gì?**
**Trả lời:** Mạng WiFi hoạt động trên nhiều kênh (channel) khác nhau. `ChannelHopper` giúp card mạng liên tục chuyển đổi giữa các kênh (với độ trễ `dwell_time` cố định) để có thể giám sát toàn bộ phổ tần thay vì chỉ mù quáng nghe trên một kênh duy nhất.

**Câu 9: Hệ thống giải quyết vấn đề mất mạng tạm thời của Sensor như thế nào?**
**Trả lời:** Sensor sử dụng mô hình "Spool Queue" (lưu vào SQLite database `spool.db`). Nếu không có kết nối tới Controller, telemetry/cảnh báo sẽ được lưu tạm xuống ổ đĩa cứng. Khi có mạng lại, `TransportWorker` sẽ tự động đọc từ queue và tải lên (upload) tiếp.

---

## Phần 3: Thuật toán phát hiện tấn công (Detection Algos)

**Câu 10: Cuộc tấn công Deauth Flood (Từ chối dịch vụ WiFi) được hệ thống phát hiện dựa trên cơ chế nào?**
**Trả lời:** `DeauthFloodDetector` đếm số lượng gói tin Deauth/Disassoc hướng đến một Client hoặc Broadcast (ff:ff:ff:ff:ff:ff) trong một khoảng thời gian (sliding window). Nếu tốc độ (rate) vượt qua ngưỡng `threshold_per_sec` (ví dụ 10 gói/giây), hệ thống sẽ cảnh báo.

**Câu 11: Làm sao hệ thống phát hiện ra điểm phát sóng giả mạo (Evil Twin)?**
**Trả lời:** Thuật toán `AdvancedEvilTwinDetector` dùng mô hình **chấm điểm trọng số (weighted scoring)**:
- Tìm các AP có cùng tên (SSID) nhưng khác BSSID (MAC).
- Cộng điểm nếu có dấu hiệu bất thường: Cường độ tín hiệu (RSSI) tự nhiên mạnh hơn bất thường (nhảy vọt dB), sai khác về nhà sản xuất (OUI), chuẩn bảo mật thay đổi (WPA3 xuống WPA2/Open), khác biệt khoảng thời gian Beacon, và các chênh lệch Information Elements (IEs).
- Nếu điểm vượt ngưỡng (VD: > 60) sẽ tạo cảnh báo.

**Câu 12: Việc "Temporal confirmation" (Xác nhận theo thời gian) trong Evil Twin Detector có ý nghĩa gì?**
**Trả lời:** Tránh cảnh báo giả (False Positive) do nhiễu sóng hoặc roaming hợp lệ. Hệ thống không cảnh báo ngay khi điểm số cao, mà yêu cầu AP đáng ngờ phải tồn tại và duy trì điểm số cao trong một "cửa sổ thời gian" (`confirmation_window_seconds`) trước khi chính thức phát cảnh báo.

**Câu 13: Hệ thống làm thế nào để tránh việc cảnh báo liên tục một cuộc tấn công đang diễn ra (Alert Spam)?**
**Trả lời:** Sử dụng cơ chế Cooldown/Deduplication. Tại Sensor có `AlertManager` và tại thuật toán (như DoS) có lưu `last_alert`. Một cuộc tấn công cùng loại vào cùng mục tiêu sẽ bị chặn (cooldown) trong ví dụ 60-600 giây trước khi có thể phát một cảnh báo mới.

**Câu 14: Tại sao trong thuật toán phát hiện, cấu trúc dữ liệu Set (tập hợp) và Dictionary (bảng băm) lại được sử dụng nhiều (ví dụ O(1) lookups)?**
**Trả lời:** Vì dữ liệu mạng luân chuyển rất nhanh (hàng nghìn gói tin mỗi giây). Phải dùng Set/Dictionary để tìm kiếm (lookups) theo MAC/BSSID với độ phức tạp thời gian là O(1), đảm bảo hệ thống không bị nghẽn (bottleneck) so với việc dùng List O(N).

---

## Phần 4: Backend Controller & API

**Câu 15: Tại sao API Server của Controller (Flask) không nhận trực tiếp Raw PCAP mà lại nhận JSON Telemetry?**
**Trả lời:** Để tối ưu băng thông và bảo mật. Gói tin PCAP rất lớn và chứa nội dung dữ liệu (payload). JSON Telemetry chỉ chứa các siêu dữ liệu (metadata) đã được trích xuất (MAC, RSSI, loại Frame, mã hóa) và kích thước rất nhỏ, phù hợp truyền tải qua Internet.

**Câu 16: An toàn thông tin giữa Sensor và Controller được đảm bảo như thế nào?**
**Trả lời:** Controller sử dụng mTLS (hoặc TLS/HTTPS cơ bản) để mã hóa đường truyền. Đồng thời, xác thực các Request tải dữ liệu từ Sensor bằng API Key và HMAC Signature, nhằm đảm bảo dữ liệu không bị giả mạo trên đường truyền.

**Câu 17: Middleware trong Flask API đóng vai trò gì trong hệ thống này?**
**Trả lời:** Middleware (như `ObservabilityMiddleware`, `TrustedProxyMiddleware`) chạy trước khi request vào logic chính. Nó giúp đếm số lượng request (metrics Prometheus), kiểm tra giới hạn tốc độ (Rate Limiting), và phân tích chính xác IP thật của Sensor nếu đi qua Nginx/Proxy.

---

## Phần 5: Machine Learning (Phân tích bất thường)

**Câu 18: Mô hình Machine Learning trong dự án sử dụng kiến trúc mạng nơ-ron nào và tại sao?**
**Trả lời:** Sử dụng **Autoencoder** (Mạng nơ-ron tự mã hóa - PyTorch). Autoencoder học cách "nén" và "giải nén" các dữ liệu mạng bình thường (baseline). Với mạng bình thường, lỗi giải nén (Reconstruction Error - MSE Loss) sẽ thấp.

**Câu 19: Làm sao Autoencoder phát hiện được sự bất thường (Anomaly)?**
**Trả lời:** Khi có một vector đặc trưng mạng chứa dấu hiệu tấn công (chưa từng xuất hiện trong lúc học), Autoencoder sẽ không thể giải nén chính xác, dẫn đến sai số (MSE Loss) vượt qua một ngưỡng (Threshold) đã định. Khi đó, nó kết luận đó là Anomaly.

**Câu 20: ML Autoencoder ở đây là học có giám sát (Supervised) hay không giám sát (Unsupervised)? Lý do chọn?**
**Trả lời:** Là **Học không giám sát (Unsupervised)**. Lý do là trong thực tế, các cuộc tấn công Zero-day hoặc hành vi biến đổi rất khó có đủ nhãn (labels) để huấn luyện. Unsupervised learning chỉ cần học hành vi "bình thường" để phát hiện bất cứ thứ gì "bất thường".

---

## Phần 6: Vận hành, Thực tế & Bảo mật riêng tư

**Câu 21: Dự án tuân thủ quyền riêng tư (Privacy) của người dùng mạng WiFi như thế nào?**
**Trả lời:** Hệ thống cung cấp module `common/privacy.py`. Các địa chỉ MAC của người dùng sẽ được mã hóa băm (anonymize) cùng với một `Salt` bí mật trước khi gửi về trung tâm hoặc lưu trữ. Do đó, hệ thống không lưu trữ danh tính thật (MAC) của thiết bị cá nhân.

**Câu 22: "Lab Mode" và "Production Mode" khác nhau thế nào trong dự án này?**
**Trả lời:**
- **Lab Mode:** Dùng SQLite, Docker Compose nhẹ nhàng, cấu hình bảo mật lỏng lẻo (http), Mock Interface, hướng tới mục đích demo, học tập, chạy local (cổng 8050).
- **Production Mode:** Dùng PostgreSQL, có mTLS, yêu cầu cấu hình bí mật (.env chặt chẽ), chạy bằng Nginx/Gunicorn, hệ thống giám sát Prometheus/Grafana thực thụ.

**Câu 23: Nếu nâng cấp hệ thống trong tương lai, em sẽ cải thiện điều gì?**
**Trả lời:** (Gợi ý trả lời)
1. Thêm hỗ trợ phân tích khung bảo mật WPA3 PMF (Protected Management Frames).
2. Tối ưu hóa mô hình ML chạy trực tiếp trên các chip NPU/TPU nhúng của Raspberry Pi.
3. Thêm tính năng định vị trí địa lý của nguồn tấn công (Geo-Location trilateration) trực tiếp trên bản đồ web.
4. Triển khai Kafka thay cho REST API để xử lý telemetry khối lượng lớn hơn.
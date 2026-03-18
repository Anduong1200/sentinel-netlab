# Bộ Câu Hỏi Bảo Vệ Đồ Án Tốt Nghiệp: Sentinel NetLab
*(Sắp xếp từ dễ đến khó theo từng phần, cung cấp câu hỏi nền tảng và câu hỏi chuyên sâu)*

---

## Phần 1: Tổng quan dự án & Kiến trúc hệ thống (Bổ sung câu hỏi nền tảng và câu hỏi khó)

**Câu 1: Sentinel NetLab là gì?**
**Trả lời:** Là một hệ thống phát hiện xâm nhập mạng không dây (WIDS) phân tán, lai ghép (hybrid). Nó kết hợp giữa phát hiện dựa trên luật (signature-based) và phân tích bất thường bằng Machine Learning để giám sát, cảnh báo các mối đe dọa trên mạng WiFi.

**Câu 2: Tại sao gọi dự án này là hệ thống "WIDS" thay vì "WIPS"?**
**Trả lời:** Vì hệ thống chỉ tập trung vào việc giám sát, thu thập dữ liệu thụ động (Passive Monitoring) và cảnh báo (Intrusion Detection - IDS) các cuộc tấn công. Nó không thực hiện các hành động can thiệp chủ động (như gửi gói tin ngắt kết nối lại kẻ tấn công) để ngăn chặn (Intrusion Prevention - IPS), nhằm đảm bảo tuân thủ pháp luật và đạo đức bảo mật.

**Câu 3: (Nền tảng) WIDS phân tán (Distributed WIDS) khác gì với WIDS tập trung? Tại sao dự án này chọn mô hình phân tán?**
**Trả lời:**
- **WIDS tập trung** dùng một cảm biến duy nhất bao phủ một khu vực nhỏ.
- **WIDS phân tán (Distributed)** sử dụng nhiều cảm biến nhỏ gọn (Sensor/Raspberry Pi) rải rác khắp tòa nhà. Dữ liệu từ các cảm biến sẽ hội tụ về một máy chủ trung tâm (Controller) để xử lý.
- **Lý do chọn:** Mạng WiFi có giới hạn vật lý về độ phủ sóng. Để giám sát một doanh nghiệp lớn, bắt buộc phải dùng nhiều cảm biến đặt ở nhiều vị trí để bao phủ toàn bộ không gian RF, đồng thời mô hình phân tán cũng giúp thực hiện được thuật toán định vị (Geo-Location Trilateration) dựa trên nhiều nguồn thu.

**Câu 4: Kiến trúc của Sentinel NetLab gồm những thành phần chính nào?**
**Trả lời:** Hệ thống có 3 thành phần chính:
1. **Sensor Layer (Edge):** Các cảm biến (như Raspberry Pi) thu thập gói tin WiFi, tiền xử lý và chạy các thuật toán phát hiện tại biên.
2. **Controller Layer (Core):** Máy chủ trung tâm (Flask API) nhận dữ liệu từ cảm biến, lưu trữ, đánh giá rủi ro tổng thể và quản lý cảnh báo.
3. **Dashboard:** Giao diện web (Dash/Plotly) để trực quan hóa dữ liệu và bản đồ nhiệt theo thời gian thực.

**Câu 5: Tại sao hệ thống lại xử lý thuật toán phát hiện (như Evil Twin, DoS) ngay tại Sensor thay vì gửi toàn bộ gói tin về Controller xử lý?**
**Trả lời:** Việc này gọi là Edge Computing (xử lý tại biên). Giúp giảm tải băng thông mạng (không cần gửi toàn bộ gói tin PCAP lớn về server), giảm độ trễ cảnh báo (phát hiện và cảnh báo ngay lập tức), và tăng tính riêng tư (chỉ gửi metadata/chỉ số thay vì nội dung gói tin).

**Câu 6: (Khó) Trong mô hình phân tán, làm sao hệ thống giải quyết vấn đề "Trùng lặp sự kiện" (Event Deduplication) khi một cuộc tấn công WiFi bị ghi nhận đồng thời bởi nhiều cảm biến khác nhau?**
**Trả lời:** Tại trung tâm (Controller), hệ thống sử dụng module `Alerts/Dedup` (có thể ứng dụng Redis hoặc cấu trúc dữ liệu in-memory của AlertManager). Nếu nhiều cảm biến (Sensor-01, Sensor-02) cùng gửi về một cảnh báo giống hệt nhau (ví dụ Deauth Flood từ MAC A đến MAC B) trong một "khoảng thời gian cửa sổ" (`dedup_window` ví dụ 60 giây), Controller sẽ gộp (merge) chúng lại thành một sự kiện duy nhất nhưng ghi nhận "Danh sách các cảm biến" đã phát hiện (để ứng dụng vào Geo-mapping) thay vì gửi 2 email cảnh báo riêng biệt cho người quản trị.

---

## Phần 2: Cảm biến (Sensor) & Lý thuyết mạng 802.11 (Bổ sung nền tảng và chuyên sâu)

**Câu 7: (Nền tảng) Cảm biến (Sensor) hoạt động ở chế độ mạng nào để thu thập dữ liệu? Nó khác gì với chế độ Promiscuous?**
**Trả lời:** Cảm biến bắt buộc phải hoạt động ở **Monitor Mode** (chế độ giám sát).
- **Promiscuous Mode:** Bắt mọi gói tin của mạng mà thiết bị *đã kết nối* (thường dùng trong mạng dây LAN hoặc WiFi đã có mật khẩu).
- **Monitor Mode:** Bắt trực tiếp tín hiệu radio thô ở tầng vật lý (MAC Layer 802.11) của *mọi mạng* đang phát trên kênh đó mà *không cần* kết nối vào bất kỳ mạng nào.

**Câu 8: (Nền tảng) Management Frames (Khung quản lý 802.11) là gì? Kể tên một vài loại frame mà dự án của em tập trung phân tích?**
**Trả lời:** Khung quản lý là các gói tin dùng để thiết lập, duy trì và kết thúc kết nối WiFi (không chứa dữ liệu người dùng). Dự án thường tập trung vào:
- **Beacon Frame:** AP phát ra để thông báo sự tồn tại (dùng phát hiện Evil Twin).
- **Probe Request/Response:** Client dò tìm mạng (dùng trong Wardriving/Karma).
- **Deauthentication/Disassociation:** Ngắt kết nối (dùng phát hiện DoS).

**Câu 9: Quá trình (Pipeline) xử lý dữ liệu của Sensor diễn ra như thế nào?**
**Trả lời:** Gồm 4 bước:
1. **Ingestor:** Driver (IwCapture/MockCapture) đọc gói tin thô.
2. **Parser & Normalizer:** Giải mã khung 802.11, chuẩn hóa dữ liệu thành JSON và ẩn danh MAC address.
3. **Analyzer:** Đưa siêu dữ liệu qua các engine phát hiện (Evil Twin, DoS, KRACK...).
4. **Exporter:** Đẩy dữ liệu vào hàng đợi (Spool queue) để gửi lên Controller theo từng lô (batch).

**Câu 10: Tính năng "Channel Hopping" trong Sensor có tác dụng gì?**
**Trả lời:** Mạng WiFi hoạt động trên nhiều kênh (channel) khác nhau. `ChannelHopper` giúp card mạng liên tục chuyển đổi giữa các kênh (với độ trễ `dwell_time` cố định) để có thể giám sát toàn bộ phổ tần thay vì chỉ mù quáng nghe trên một kênh duy nhất.

**Câu 11: (Khó) Làm thế nào hệ thống đảm bảo không bị quá tải bộ nhớ RAM khi phải xử lý hàng nghìn gói tin mỗi giây?**
**Trả lời:**
1. Sử dụng thiết kế Producer-Consumer: Luồng bắt gói tin (Capture) đưa vào một bộ đệm vòng (BufferManager) có giới hạn kích thước (`max_memory_items` ví dụ 10,000).
2. Luồng đẩy dữ liệu (Upload Thread) liên tục đọc theo từng "Batch" (`batch_size=200`) và đẩy xuống SQLite persistent queue (`Spool.db`).
3. Nếu RAM đầy, gói tin cũ/không quan trọng sẽ bị drop (Fail-safe) để tránh crash hệ thống (OOM - Out of Memory).

**Câu 12: Hệ thống giải quyết vấn đề mất mạng tạm thời của Sensor như thế nào?**
**Trả lời:** Sensor sử dụng mô hình "Spool Queue" (lưu vào SQLite database `spool.db`). Nếu không có kết nối tới Controller, telemetry/cảnh báo sẽ được lưu tạm xuống ổ đĩa cứng. Khi có mạng lại, `TransportWorker` sẽ tự động đọc từ queue và tải lên (upload) tiếp.

---

## Phần 3: Thuật toán phát hiện tấn công & Exploit Chains (Bổ sung phân tích chuỗi)

**Câu 13: (Nền tảng) Tấn công Evil Twin là gì? Tại sao nó nguy hiểm?**
**Trả lời:** Evil Twin là kẻ tấn công tạo ra một điểm phát sóng (AP) giả mạo có cùng tên (SSID) với mạng hợp pháp, thường phát tín hiệu mạnh hơn để lừa thiết bị người dùng kết nối vào. Từ đó, kẻ tấn công có thể nghe lén mật khẩu, đánh cắp cookie hoặc thực hiện tấn công Man-in-the-Middle (MitM).

**Câu 14: Cuộc tấn công Deauth Flood (Từ chối dịch vụ WiFi) được hệ thống phát hiện dựa trên cơ chế nào?**
**Trả lời:** `DeauthFloodDetector` đếm số lượng gói tin Deauth/Disassoc hướng đến một Client hoặc Broadcast (ff:ff:ff:ff:ff:ff) trong một khoảng thời gian (sliding window). Nếu tốc độ (rate) vượt qua ngưỡng `threshold_per_sec` (ví dụ 10 gói/giây), hệ thống sẽ cảnh báo.

**Câu 15: Làm sao hệ thống phát hiện ra điểm phát sóng giả mạo (Evil Twin)?**
**Trả lời:** Thuật toán `AdvancedEvilTwinDetector` dùng mô hình **chấm điểm trọng số (weighted scoring)**:
- Tìm các AP có cùng tên (SSID) nhưng khác BSSID (MAC).
- Cộng điểm nếu có dấu hiệu bất thường: Cường độ tín hiệu (RSSI) tự nhiên mạnh hơn bất thường (nhảy vọt dB), sai khác về nhà sản xuất (OUI), chuẩn bảo mật thay đổi (WPA3 xuống WPA2/Open), khác biệt khoảng thời gian Beacon, và các chênh lệch Information Elements (IEs).
- Nếu điểm vượt ngưỡng (VD: > 60) sẽ tạo cảnh báo.

**Câu 16: Việc "Temporal confirmation" (Xác nhận theo thời gian) trong Evil Twin Detector có ý nghĩa gì?**
**Trả lời:** Tránh cảnh báo giả (False Positive) do nhiễu sóng hoặc roaming hợp lệ. Hệ thống không cảnh báo ngay khi điểm số cao, mà yêu cầu AP đáng ngờ phải tồn tại và duy trì điểm số cao trong một "cửa sổ thời gian" (`confirmation_window_seconds`) trước khi chính thức phát cảnh báo.

**Câu 17: Hệ thống làm thế nào để tránh việc cảnh báo liên tục một cuộc tấn công đang diễn ra (Alert Spam)?**
**Trả lời:** Sử dụng cơ chế Cooldown/Deduplication. Tại Sensor có `AlertManager` và tại thuật toán (như DoS) có lưu `last_alert`. Một cuộc tấn công cùng loại vào cùng mục tiêu sẽ bị chặn (cooldown) trong ví dụ 60-600 giây trước khi có thể phát một cảnh báo mới.

**Câu 18: Tại sao trong thuật toán phát hiện, cấu trúc dữ liệu Set (tập hợp) và Dictionary (bảng băm) lại được sử dụng nhiều (ví dụ O(1) lookups)?**
**Trả lời:** Vì dữ liệu mạng luân chuyển rất nhanh (hàng nghìn gói tin mỗi giây). Phải dùng Set/Dictionary để tìm kiếm (lookups) theo MAC/BSSID với độ phức tạp thời gian là O(1), đảm bảo hệ thống không bị nghẽn (bottleneck) so với việc dùng List O(N).

**Câu 19: (Khó) Khái niệm "Exploit Chain" trong dự án là gì? Nó giúp phát hiện điều gì mà các thuật toán đơn lẻ không làm được?**
**Trả lời:** Exploit Chain (chuỗi khai thác) là việc kết hợp nhiều cảnh báo rời rạc lại với nhau để tìm ra một cuộc tấn công phức tạp.
Ví dụ: Thuật toán đơn lẻ phát hiện (1) Một mạng Evil Twin và (2) Một cuộc Deauth Flood. Tuy nhiên, `ExploitChainAnalyzer` sẽ theo dõi và thấy kẻ tấn công vừa tạo Evil Twin, *ngay sau đó* bắn Deauth Flood để ép người dùng ngắt kết nối từ mạng gốc và văng sang mạng giả. Cảnh báo "Chain" sẽ có mức độ nghiêm trọng (Critical) cao hơn nhiều so với từng cảnh báo đơn lẻ.

**Câu 20: (Khó) Cuộc tấn công KARMA/Pineapple (Karma Detector) hoạt động dựa trên cơ chế bắt gói tin nào?**
**Trả lời:** Client (điện thoại) thường lưu tên các mạng WiFi cũ (Saved Networks) và liên tục phát ra `Probe Request` (hỏi "Mạng X có ở đây không?"). Kẻ tấn công dùng WiFi Pineapple nghe lén Probe Request này và lập tức phát ra `Probe Response` giả mạo (trả lời "Có, tao là mạng X đây") bất chấp tên mạng là gì. Hệ thống phát hiện bằng cách tìm một AP (cùng BSSID) nhưng liên tục trả lời bằng nhiều SSID khác nhau trong thời gian ngắn.

---

## Phần 4: Backend Controller & API

**Câu 21: Tại sao API Server của Controller (Flask) không nhận trực tiếp Raw PCAP mà lại nhận JSON Telemetry?**
**Trả lời:** Để tối ưu băng thông và bảo mật. Gói tin PCAP rất lớn và chứa nội dung dữ liệu (payload). JSON Telemetry chỉ chứa các siêu dữ liệu (metadata) đã được trích xuất (MAC, RSSI, loại Frame, mã hóa) và kích thước rất nhỏ, phù hợp truyền tải qua Internet.

**Câu 22: An toàn thông tin giữa Sensor và Controller được đảm bảo như thế nào?**
**Trả lời:** Controller sử dụng mTLS (hoặc TLS/HTTPS cơ bản) để mã hóa đường truyền. Đồng thời, xác thực các Request tải dữ liệu từ Sensor bằng API Key và HMAC-SHA256 Signature, nhằm đảm bảo dữ liệu không bị giả mạo trên đường truyền.

**Câu 23: Middleware trong Flask API đóng vai trò gì trong hệ thống này?**
**Trả lời:** Middleware (như `ObservabilityMiddleware`, `TrustedProxyMiddleware`) chạy trước khi request vào logic chính. Nó giúp đếm số lượng request (metrics Prometheus), kiểm tra giới hạn tốc độ (Rate Limiting), và phân tích chính xác IP thật của Sensor nếu đi qua Nginx/Proxy.

---

## Phần 5: Machine Learning (Phân tích bất thường)

**Câu 24: Mô hình Machine Learning trong dự án sử dụng kiến trúc mạng nơ-ron nào và tại sao?**
**Trả lời:** Sử dụng **Autoencoder** (Mạng nơ-ron tự mã hóa - PyTorch). Autoencoder học cách "nén" và "giải nén" các dữ liệu mạng bình thường (baseline). Với mạng bình thường, lỗi giải nén (Reconstruction Error - MSE Loss) sẽ thấp.

**Câu 25: Làm sao Autoencoder phát hiện được sự bất thường (Anomaly)?**
**Trả lời:** Khi có một vector đặc trưng mạng chứa dấu hiệu tấn công (chưa từng xuất hiện trong lúc học), Autoencoder sẽ không thể giải nén chính xác, dẫn đến sai số (MSE Loss) vượt qua một ngưỡng (Threshold) đã định. Khi đó, nó kết luận đó là Anomaly.

**Câu 26: ML Autoencoder ở đây là học có giám sát (Supervised) hay không giám sát (Unsupervised)? Lý do chọn?**
**Trả lời:** Là **Học không giám sát (Unsupervised)**. Lý do là trong thực tế, các cuộc tấn công Zero-day hoặc hành vi biến đổi rất khó có đủ nhãn (labels) để huấn luyện. Unsupervised learning chỉ cần học hành vi "bình thường" để phát hiện bất cứ thứ gì "bất thường".

---

## Phần 6: Vận hành, Thực tế & Bảo mật dự án (Bổ sung câu hỏi khó về Design Pattern và Bảo mật)

**Câu 27: (Nền tảng) Dự án tuân thủ quyền riêng tư (Privacy) của người dùng mạng WiFi như thế nào?**
**Trả lời:** Hệ thống cung cấp module `common/privacy.py`. Các địa chỉ MAC của người dùng sẽ được mã hóa băm (anonymize) cùng với một `Salt` bí mật trước khi gửi về trung tâm hoặc lưu trữ. Do đó, hệ thống không lưu trữ danh tính thật (MAC) của thiết bị cá nhân.

**Câu 28: (Nền tảng) "Lab Mode" và "Production Mode" khác nhau thế nào trong dự án này?**
**Trả lời:**
- **Lab Mode:** Dùng SQLite, Docker Compose nhẹ nhàng, cấu hình bảo mật lỏng lẻo (http), Mock Interface, hướng tới mục đích demo, học tập, chạy local.
- **Production Mode:** Dùng PostgreSQL, có mTLS, yêu cầu cấu hình bí mật (.env chặt chẽ), chạy bằng Nginx/Gunicorn, hệ thống giám sát Prometheus/Grafana thực thụ.

**Câu 29: (Khó) Trong hệ thống cấu hình (`sensor/config.py`), dự án sử dụng mô hình "Fail-Fast Secret" là gì và tại sao nó quan trọng?**
**Trả lời:** Fail-Fast Secret (Lỗi nhanh) là nguyên tắc thiết kế yêu cầu ứng dụng phải **chết/dừng khởi động ngay lập tức** nếu các biến môi trường nhạy cảm (như SENSOR_HMAC_SECRET, API_KEY) bị thiếu, độ dài quá ngắn, hoặc quá yếu (vd dùng mật khẩu mặc định trong Production). Thay vì để hệ thống chạy ngầm với cấu hình không an toàn và bị hack sau này, việc "crash" sớm buộc quản trị viên phải cấu hình đúng chuẩn bảo mật trước khi hệ thống có thể lên sóng.

**Câu 30: (Khó) Nếu một kẻ tấn công gửi ngập lụt (flood) các cảnh báo giả mạo lên API của Controller nhằm làm sập Database, em xử lý tình huống đó ở Backend ra sao?**
**Trả lời:** Dự án sử dụng kết hợp nhiều lớp phòng thủ:
1. **Rate Limiting:** Middleware giới hạn số lượng request API/phút (ví dụ Flask-Limiter).
2. **Authentication:** Bắt buộc có API Token hợp lệ và kiểm tra HMAC signature cho mỗi payload. Nếu sai, rớt ngay ở vòng ngoài (401/403).
3. **Queue / Message Broker:** API không ghi trực tiếp vào Database PostgreSQL, mà sẽ đưa dữ liệu vào Redis Queue/Celery worker để xử lý bất đồng bộ, giúp DB không bị khóa nghẽn (locking) khi có luồng dữ liệu khổng lồ đẩy tới.

**Câu 31: Khó khăn lớn nhất trong việc kiểm thử (Testing) module Sensor thu thập gói tin không dây (Wi-Fi 802.11) là gì và dự án giải quyết như thế nào?**
**Trả lời:** Khó khăn lớn nhất là việc bắt gói tin thực tế (Live Capture) đòi hỏi quyền root (sudo) và phần cứng card mạng đặc thù hỗ trợ Monitor Mode.
Dự án giải quyết bằng cách áp dụng **Dependency Injection (Mocking)**: Thay vì dùng card thật, bài test dùng `MockCaptureDriver` để tự sinh ra các gói dữ liệu ảo, hoặc dùng `PcapCaptureDriver` để đọc và "replay" (phát lại) dữ liệu từ các file `.pcap` đã ghi âm sẵn. Điều này giúp hệ thống test (CI/CD) có thể chạy ổn định trên mọi máy chủ mà không cần phần cứng WiFi vật lý.

**Câu 32: Nếu nâng cấp hệ thống trong tương lai, em sẽ cải thiện điều gì?**
**Trả lời:** (Gợi ý trả lời)
1. Thêm hỗ trợ phân tích khung bảo mật WPA3 PMF (Protected Management Frames), vì hiện tại PMF mã hóa khung quản lý khiến việc bắt gói tin thụ động gặp khó khăn.
2. Tối ưu hóa mô hình ML chạy trực tiếp trên các chip NPU/TPU nhúng của Raspberry Pi.
3. Cải thiện độ chính xác tính năng định vị vị trí địa lý của nguồn tấn công (Geo-Location trilateration) trực tiếp trên bản đồ web.
4. Triển khai Kafka thay cho REST API nếu quy mô lên đến hàng nghìn cảm biến.
# DNS Cache Poisoning (Đầu độc bộ nhớ đệm DNS)

> **Phạm vi:** tập trung vào **DNS cache poisoning** (tiêm/cấy bản ghi sai vào cache của recursive resolver/forwarder) để chuyển hướng truy cập, nghe lén hoặc phân phối mã độc.  
> **Ghi chú an toàn:** nội dung phục vụ **phòng thủ, đánh giá an ninh được ủy quyền, đào tạo**. Không cung cấp hướng dẫn khai thác dạng step-by-step/command.

---

## 1) Thông tin kỹ thuật (Technical Information)

### 1.1 Giao thức liên quan (DNS là lõi; 802.11/EAP chỉ là lớp truy cập)
**(A) DNS & hạ tầng DNS**
- **DNS (Domain Name System)**: hệ thống phân giải tên miền ↔ địa chỉ IP, gồm:
  - **Stub resolver** trên client (OS/app),
  - **Recursive resolver / caching resolver** (thường do ISP/Doanh nghiệp cung cấp, hoặc chạy trên router/AP gateway),
  - **Authoritative name server** (nơi “nguồn sự thật” của zone).
- **DNS over UDP/TCP**: truyền thống dùng UDP (nhanh) và chuyển sang TCP khi phản hồi lớn (ví dụ DNSSEC/zone transfer).
- **EDNS(0)**: mở rộng DNS, thường làm phản hồi lớn hơn (liên quan tới fallback TCP và một số tình huống phân mảnh).
- **DNSSEC**: cơ chế **xác thực tính toàn vẹn & tính xác thực** của dữ liệu DNS (ký RRsets), giúp chống cache poisoning ở mức dữ liệu (resolver “validate” chữ ký).

**(B) Encrypted DNS (giảm rủi ro on-path giữa client ↔ resolver)**
- **DoT (DNS-over-TLS)**: mã hóa truy vấn DNS giữa client và resolver.
- **DoH (DNS-over-HTTPS)**: DNS chạy qua HTTPS.
> Lưu ý: DoH/DoT **không thay thế DNSSEC**. DoH/DoT chủ yếu bảo vệ **tính bí mật & chống sửa đổi trên đường truyền** giữa client và resolver; còn DNSSEC bảo vệ **tính xác thực dữ liệu DNS** từ authoritative.

**(C) IEEE 802.11 / WPA / EAP (liên quan theo ngữ cảnh triển khai)**
- **IEEE 802.11 (Wi‑Fi):** DNS traffic chạy “trên” IP qua Wi‑Fi. Nếu attacker đã vào cùng WLAN/VLAN thì DNS cache poisoning xảy ra ở lớp DNS, **không phụ thuộc trực tiếp** vào AES/SAE của Wi‑Fi.
- **WPA2/WPA3:** bảo vệ liên kết radio (client ↔ AP).  
- **EAP/802.1X (Enterprise):** giảm khả năng attacker “vào được mạng” (một điều kiện quan trọng cho nhiều kiểu tấn công nội bộ), và hỗ trợ **segment** theo danh tính thiết bị/người dùng.

### 1.2 Phân tích cơ chế hoạt động của AP / client / IoT device

**(A) Access Point / Router / IoT Gateway (vai trò DNS forwarder/caching)**
- Trong thực tế, rất nhiều AP/router chạy **DNS forwarder + cache** (ví dụ dnsmasq/unbound/implementations tương tự) và cấp DNS server cho client qua DHCP.
- Vì thế, “điểm cache” dễ bị nhắm tới nhất thường là:
  - **Router/AP gateway** của mạng gia đình/quán café,
  - **Recursive resolver** nội bộ doanh nghiệp,
  - **Resolver của ISP** (quy mô lớn).
- Nếu attacker có vị trí phù hợp (trong cùng LAN hoặc on‑path), họ có thể cố làm resolver **cache** bản ghi sai (A/AAAA/CNAME/NS/glue…) hoặc kéo dài TTL không hợp lý để duy trì ảnh hưởng.

**(B) Client (Windows/macOS/Linux/mobile)**
Luồng phân giải điển hình:
1. Ứng dụng gọi stub resolver: “tên miền X → IP?”
2. Stub gửi query tới DNS server được cấu hình (thường do DHCP cấp).
3. Recursive resolver:
   - kiểm tra cache,
   - nếu cache miss → truy vấn tiếp tới authoritative (theo các bước root → TLD → authoritative).
4. Nếu resolver nhận/“tin” một phản hồi giả (race/spoof), nó có thể **lưu vào cache**, khiến mọi client sau đó bị chuyển hướng.

**(C) IoT device**
- IoT thường phụ thuộc nặng vào DNS để gọi cloud endpoints (update, telemetry).
- Rủi ro hay gặp:
  - Firmware/stack DNS **cũ** hoặc “simplified” (randomization yếu),
  - Thiết bị không hỗ trợ DoH/DoT,
  - Hardcode DNS server hoặc không có cơ chế pinning/certificate hygiene ở tầng ứng dụng.
- Khi cache poisoning xảy ra ở gateway/resolver, IoT có thể bị:
  - chuyển hướng tới endpoint giả (command/control),
  - tải firmware giả (nếu quy trình update không ký/không kiểm tra chặt).

### 1.3 Công cụ & phần mềm thường dùng (tấn công & phòng thủ) — ở mức khái quát
> Chỉ liệt kê để hiểu hệ sinh thái; không hướng dẫn dùng.

**Quan sát/phòng thủ**
- **Wireshark/tcpdump**: phân tích DNS query/response, TTL bất thường, source port/TxID entropy.
- **Zeek/Suricata/Snort**: phát hiện “DNS anomalies”, domain bất thường, trả lời không khớp truy vấn.
- **BIND/Unbound/dnsmasq logs**: querylog, thống kê cache hit/miss, SERVFAIL/NXDOMAIN spikes.
- **Threat intel/Protective DNS**: sinkhole, blocklist, RPZ (Response Policy Zone) theo chính sách.

**Trong đánh giá an ninh được ủy quyền**
- Bộ công cụ MITM/packet crafting (ví dụ framework tạo gói), công cụ test hiệu năng (dnsperf), và công cụ audit Wi‑Fi (Kismet/Aircrack‑ng) chỉ đóng vai trò “giúp attacker vào mạng” hoặc quan sát RF — không phải là lõi của DNS poisoning.

---

## 2) Thuật toán (Algorithms)

### 2.1 Thuật toán mã hóa/xác thực bị khai thác (hoặc thiếu vắng)
- **DNS truyền thống (không DNSSEC):** gần như **không có xác thực dữ liệu** ở tầng DNS → cache poisoning tập trung vào “forge response đúng định danh truy vấn”.
- **DNSSEC:** dùng **chữ ký số** để xác thực RRsets:
  - Thuật toán ký thường gặp: **RSA** và **ECDSA** (tùy zone và nhà vận hành).
  - Cơ chế chain-of-trust: DS/DNSKEY, validating resolver kiểm tra chữ ký trước khi chấp nhận dữ liệu.
- **DoT/DoH (TLS):** dùng thuật toán của TLS (AES-GCM/ChaCha20-Poly1305, ECDHE…) để bảo vệ kênh client↔resolver.

### 2.2 Thuật toán tấn công (khái niệm)
- **Spoofing + race**: gửi phản hồi giả “nhanh hơn” phản hồi thật.
- **Brute-force/guessing entropy**:
  - đoán **Transaction ID (TxID)** và/hoặc **UDP source port** của truy vấn,
  - thành công khi trúng tổ hợp và phản hồi giả đến trước.
- **Birthday-style / flooding**: tăng xác suất trúng bằng cách tăng số lượng phản hồi/biến thể.
- **Poisoning NS/glue (khái niệm lịch sử):** một số kỹ thuật nhắm đến cấy thông tin máy chủ tên (NS) hoặc glue record để mở rộng ảnh hưởng.
- **On‑path manipulation**: nếu attacker ở vị trí on‑path (hoặc kiểm soát router), họ có thể sửa/tiêm phản hồi DNS dễ hơn (nhưng khi đó thường gần với DNS hijacking + MITM).

### 2.3 Thuật toán phòng thủ (entropy-based, ML/DL, và kiểm soát cấu hình)
**(A) Tăng entropy / harden resolver (theo các khuyến nghị tiêu chuẩn)**
- **Source port randomization** (UDP) + **TxID randomization**.
- **0x20 encoding** (case-randomization cho QNAME) như một lớp “extra entropy” trong một số triển khai.
- **Giảm khả năng bị lợi dụng qua NAT**: một số NAT làm giảm entropy (port bị cố định/tuần tự) → cần kiểm thử thực tế.

**(B) Xác thực dữ liệu**
- **DNSSEC validation** (ưu tiên số 1 để chống poisoning ở mức dữ liệu).
- Kỷ luật quản lý **trust anchors**, xử lý rollover.

**(C) Encrypted DNS & giảm bề mặt on-path**
- **DoT/DoH** từ client → resolver tin cậy giúp giảm khả năng attacker trên Wi‑Fi công cộng sửa DNS.

**(D) Detection**
- **Entropy-based detection**:
  - tần suất truy vấn thất bại/NXDOMAIN tăng đột ngột,
  - TTL bất thường (quá dài/quá ngắn so với baseline),
  - thay đổi đột ngột NS/CNAME chain.
- **ML/DL anomaly detection**:
  - mô hình hóa hành vi DNS theo user/host (time-series),
  - phát hiện domain mới/hiếm (rare domains), DGA-like,
  - phát hiện “resolver behavior drift” (bỗng query tới authoritative lạ).
> Nhiều tổ chức dùng ML/DL ở tầng SIEM/EDR/Protective DNS thay vì nhúng trực tiếp vào resolver.

---

## 3) Dependencies

### 3.1 Phụ thuộc firmware/driver/hệ điều hành
- **Phần mềm resolver**: BIND, Unbound, PowerDNS Recursor, dnsmasq, Windows DNS Server… (mỗi loại có mặc định/hardening khác nhau).
- **Router/AP firmware**: thiết bị consumer có thể:
  - chạy resolver cũ, khó vá,
  - có NAT làm giảm entropy,
  - có bug khiến dễ bị poisoning.
- **OS stub resolver**: hành vi retry, cache cục bộ, DoH/DoT support (Windows/macOS/Android/iOS khác nhau).

### 3.2 Phụ thuộc cấu hình người dùng
- Dùng DNS server mặc định (router/ISP) không có DNSSEC/DoH.
- Trên Wi‑Fi: **PSK yếu/WPS bật** → attacker dễ vào cùng mạng (điều kiện để tấn công nội bộ).  
  *Nhưng lưu ý: đây là điều kiện “vào mạng”, không phải cơ chế poisoning cốt lõi.*
- Không dùng VPN/không bật encrypted DNS khi ở mạng công cộng.

### 3.3 Phụ thuộc hạ tầng mạng
- **Mô hình DNS**: recursive resolver nội bộ vs dùng public resolver.
- **Anti-spoofing trên mạng**: nếu hạ tầng cho phép spoof IP dễ dàng, off‑path spoofing khả thi hơn.
- **Segmentation**: guest Wi‑Fi không cách ly khỏi hạ tầng DNS nội bộ sẽ tăng rủi ro.

---

## 4) Context

### 4.1 Môi trường triển khai
- **Mạng công cộng**: quán café, sân bay (rủi ro on‑path/rogue gateway, captive portal).
- **Doanh nghiệp**: resolver nội bộ phục vụ hàng nghìn máy; poisoning ảnh hưởng diện rộng.
- **IoT**: gateway nội bộ, thiết bị khó cập nhật.
- **Mesh/home**: router “all-in-one” (DHCP + DNS cache) — điểm yếu phổ biến.

### 4.2 Kịch bản tấn công (ví dụ)
- **Café Wi‑Fi**: attacker cùng VLAN guest, tìm cách can thiệp DNS để chuyển hướng người dùng tới trang giả/phishing.
- **Doanh nghiệp**: máy nội bộ bị compromise, sau đó tìm cách tác động resolver/forwarder để điều hướng traffic tới hạ tầng attacker.
- **IoT**: poisoning làm thiết bị gọi về cloud giả, hoặc chặn update thật để kéo dài thời gian tồn tại.

---

## 5) Core Weakness (điểm yếu cốt lõi)

- **DNS truyền thống thiếu xác thực dữ liệu**: resolver chấp nhận phản hồi nếu “trông có vẻ khớp” với truy vấn (TxID/port/QNAME/QTYPE…).
- **Cơ chế cache**: một khi bản ghi sai được cache, tác động lan rộng tới nhiều client.
- **Entropy không đủ** (TxID/port dự đoán được, NAT làm giảm randomization) → tăng xác suất spoof.
- **Hệ sinh thái router/AP/IoT**: firmware cập nhật kém, cấu hình mặc định yếu.

---

## 6) Cost & Risk

### 6.1 Chi phí triển khai tấn công
- **Thấp → trung bình** tùy vị trí:
  - **In‑LAN/on‑path**: thường dễ hơn.
  - **Off‑path**: khó hơn (phụ thuộc spoofing và entropy), nhưng vẫn có lịch sử tấn công thực tế khi cấu hình kém.

### 6.2 Chi phí phòng thủ
- **Trung bình**: harden resolver (randomization, logging), IDS/Protective DNS.
- **Trung bình → cao**: triển khai **DNSSEC validation** diện rộng, quản trị trust anchor/rollover, và triển khai DoH/DoT theo chính sách.

### 6.3 Rủi ro
- **Mất dữ liệu**: bị chuyển hướng tới server giả (credential theft/malware).
- **Gián đoạn dịch vụ**: poisoning có thể gây lỗi truy cập dịch vụ quan trọng.
- **Pháp lý/tuân thủ**: nếu gây rò rỉ dữ liệu cá nhân, có thể vi phạm quy định nội bộ/luật.

---

## 7) Control Surface (các lớp kiểm soát)

### 7.1 Access Point / Router / Gateway
- Update firmware định kỳ; thay thiết bị end-of-life.
- Tắt “DNS proxy/cache” nếu không cần, hoặc thay bằng resolver được harden.
- Với Wi‑Fi: ưu tiên WPA3/WPA2‑Enterprise (802.1X) cho mạng nội bộ; bật client isolation cho guest.

### 7.2 Client
- Bật **DoH/DoT** tới resolver tin cậy (theo chính sách tổ chức) khi phù hợp.
- Dùng **VPN** khi ở mạng công cộng (giảm rủi ro on‑path).
- Cập nhật OS/Browser để bảo vệ TLS/HSTS; chú ý certificate warnings (DNS poisoning thường dẫn tới lỗi chứng chỉ nếu site dùng HTTPS đúng).

### 7.3 Network Layer
- **DNSSEC validating resolver** nội bộ; enforce sử dụng resolver chuẩn (chặn DNS trực tiếp ra Internet nếu cần).
- IDS/IPS/Zeek theo dõi:
  - TTL bất thường,
  - thay đổi NS/glue,
  - SERVFAIL spikes (có thể gợi ý vấn đề DNSSEC/poisoning/DoS).
- Triển khai **anti-spoofing** (ingress/egress filtering) để giảm khả năng giả mạo nguồn IP.

### 7.4 Policy Layer
- Chuẩn hóa cấu hình DNS trong tổ chức: resolver tập trung + logging + retention.
- Quy trình IR: playbook khi nghi poisoning (flush cache, pin resolver, kiểm tra chain DNSSEC, so sánh “known good”).
- Đào tạo người dùng: cảnh giác trang HTTPS báo lỗi chứng chỉ, không bỏ qua warning.

---

## 8) Chain Value (chuỗi giá trị liên quan)

- **Nhà sản xuất phần cứng:** router/AP/gateway, chipset, thiết bị IoT.
- **Nhà cung cấp phần mềm:** resolver software (BIND/Unbound…), OS stub resolver, EDR/IDS/SIEM, Protective DNS.
- **Doanh nghiệp triển khai:** network/security team vận hành DNS, SOC giám sát, IT hỗ trợ endpoint.
- **Người dùng cuối:** phụ thuộc vào DNS để truy cập dịch vụ; hành vi khi gặp cảnh báo HTTPS.
- **Kẻ tấn công:** tận dụng vị trí trong mạng hoặc sai cấu hình/entropy yếu.
- **Cơ quan quản lý/chuẩn:** IETF (RFC), NIST/CISA (guidance), cơ quan viễn thông/ISP policy.

---

## References (kèm “Source Preference” và URL)

### P1 — Chuẩn/tiêu chuẩn & tài liệu chính thức
- RFC 1034 — Domain Names: Concepts and Facilities:  
  https://www.rfc-editor.org/rfc/rfc1034
- RFC 1035 — Domain Names: Implementation and Specification:  
  https://www.rfc-editor.org/rfc/rfc1035
- RFC 5452 — Measures for Making DNS More Resilient against Forged Answers:  
  https://www.rfc-editor.org/rfc/rfc5452
- RFC 4033 — DNS Security Introduction and Requirements (DNSSEC):  
  https://www.rfc-editor.org/rfc/rfc4033
- RFC 4034 — Resource Records for the DNS Security Extensions:  
  https://www.rfc-editor.org/rfc/rfc4034
- RFC 4035 — Protocol Modifications for the DNS Security Extensions:  
  https://www.rfc-editor.org/rfc/rfc4035
- RFC 7858 — DNS over TLS (DoT):  
  https://www.rfc-editor.org/rfc/rfc7858
- RFC 8484 — DNS over HTTPS (DoH):  
  https://www.rfc-editor.org/rfc/rfc8484
- NIST SP 800-81-2 (Final) — Secure DNS Deployment Guide (Revision 2):  
  https://csrc.nist.gov/pubs/sp/800/81/2/final
- NIST SP 800-81r3 (IPD) — Secure DNS Deployment Guide (Revision 3, bản dự thảo công khai):  
  https://csrc.nist.gov/pubs/sp/800/81/r3/ipd

### P2 — Hướng dẫn/công cụ từ cơ quan/khung vận hành
- CISA — Protective DNS Resolver Service:  
  https://www.cisa.gov/resources-tools/services/protective-domain-name-system-dns-resolver
- CISA — Encrypted DNS Implementation Guidance:  
  https://www.cisa.gov/resources-tools/resources/encrypted-dns-implementation-guidance
- BCP38 / anti-spoofing (RFC 2827, cập nhật bởi RFC 3704):  
  https://www.rfc-editor.org/rfc/rfc2827  
  https://www.rfc-editor.org/rfc/rfc3704

### P3 — Nghiên cứu học thuật/whitepaper
- Herzberg & Shulman — *Unilateral Antidotes to DNS Poisoning* (arXiv PDF):  
  https://arxiv.org/pdf/1209.1482
- DNS-OARC slide deck (cache poisoning protection math/operational):  
  https://indico.dns-oarc.net/event/43/contributions/917/attachments/883/1640/Cache%20Poisoning%20Protection%20for%20Authoritative%20Queries.pdf

### P4 — Vendor/triển khai tham khảo (bổ sung góc nhìn vận hành)
- Google Security Blog — Public DNS approach to fight cache poisoning:  
  https://security.googleblog.com/2024/03/google-public-dnss-approach-to-fight.html

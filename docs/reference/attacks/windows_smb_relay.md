# Windows Name Resolution & SMB Attacks (LLMNR/NBT-NS/WPAD Poisoning + NTLM/SMB Relay)

> **Phạm vi:** mô tả kỹ thuật và kiểm soát **phòng thủ** cho nhóm tấn công lợi dụng cơ chế phân giải tên trong Windows và phiên SMB/NTLM để **thu thập/relay chứng thực**, dẫn đến **lateral movement**.  
> **Nguyên tắc an toàn:** không cung cấp lệnh/chuỗi thao tác khai thác; chỉ mô tả cơ chế, điều kiện, dấu hiệu nhận biết và biện pháp giảm thiểu.

---

## 1) Thông tin kỹ thuật (Technical Information)

### 1.1 Giao thức liên quan (ưu tiên đúng bối cảnh Windows/SMB; Wi‑Fi chỉ là “lớp vận chuyển”)
**(A) Lớp truy cập mạng (Wired/Wi‑Fi)**
- **IEEE 802.11 (Wi‑Fi):** nếu nạn nhân/attacker ở cùng WLAN, các frame 802.11 chỉ là “carrier” cho lưu lượng IP.  
  - **WPA2/WPA3:** bảo vệ **over‑the‑air** (giữa client ↔ AP), nhưng **không tự động ngăn** kẻ tấn công đã “ở trong mạng” (đã kết nối Wi‑Fi/được cấp VLAN) thực hiện poisoning/relay trong cùng broadcast domain.  
  - **EAP/802.1X (Enterprise):** giúp kiểm soát ai được vào mạng, cấp VLAN/ACL động, giảm khả năng attacker “chỉ cần biết PSK” là vào được mạng.
- **Ethernet (802.3):** tương tự, nếu attacker cắm vào cùng L2 segment thì broadcast/multicast dễ bị lạm dụng.

**(B) Phân giải tên/khám phá dịch vụ**
- **DNS:** cơ chế chuẩn để phân giải tên; khi thất bại hoặc truy vấn “flat name” (tên ngắn), Windows có thể kích hoạt cơ chế thay thế.
- **LLMNR (Link‑Local Multicast Name Resolution):** dựa trên format DNS, hoạt động nội bộ **trong local‑link** qua multicast, dùng cổng riêng (không phải DNS) → dễ bị “spoof” trong cùng L2 nếu không vô hiệu hóa.  
- **NetBIOS Name Service (NBT‑NS / NetBT):** cơ chế legacy để phân giải tên NetBIOS trong LAN; phát sinh broadcast/multicast trong subnet.
- **mDNS (Multicast DNS):** đôi khi xuất hiện trong môi trường đa nền tảng (đặc biệt .local); không phải trọng tâm của attack này nhưng có thể tạo thêm “bề mặt metadata”.

**(C) Proxy auto‑discovery**
- **WPAD (Web Proxy Auto‑Discovery):** client có thể tìm PAC/proxy bằng DNS/DHCP/NetBIOS…; nếu bị hijack có thể chuyển hướng traffic hoặc hỗ trợ đánh cắp/relay chứng thực trong một số kịch bản.

**(D) Truy cập tài nguyên & xác thực**
- **SMB (Server Message Block) v2/v3:** giao thức chia sẻ file/printer/IPC trên Windows; thường chạy TCP/445.
  - **SMB Signing:** đảm bảo **tính toàn vẹn** thông điệp SMB; là biện pháp then chốt giảm rủi ro **SMB relay**.
  - **SMB Encryption:** bảo vệ bí mật & toàn vẹn dữ liệu SMB end‑to‑end (client ↔ server).
- **NTLM / NTLMv2:** cơ chế xác thực legacy; dễ bị lợi dụng theo kiểu “trick client gửi NTLM” và **relay** nếu đích không yêu cầu bảo vệ.  
- **Kerberos:** cơ chế hiện đại hơn trong AD; giảm phụ thuộc NTLM và có mô hình ticket (nhưng vẫn cần hardening đúng).

### 1.2 Phân tích cơ chế hoạt động: AP / Client / IoT device

**(A) Access Point / Switch (vai trò L2/L3)**
- AP/switch duy trì **broadcast domain**; các truy vấn LLMNR/NBT‑NS thường là multicast/broadcast trong subnet → bất kỳ host nào trong cùng subnet có thể “nghe” và (nếu không bị chặn) **phản hồi giả**.
- Một số tính năng có thể giảm rủi ro:
  - **Client isolation / AP isolation** (đặc biệt cho guest Wi‑Fi): hạn chế client ↔ client ở L2, giảm khả năng poisoning/relay nội bộ.
  - **Segmentation** (VLAN/ACL): tách workstation khỏi IoT/guest.
  - **802.1X/EAP**: chỉ cho thiết bị hợp lệ vào đúng VLAN.

**(B) Windows client (nạn nhân thường gặp)**
Chuỗi điển hình (mô tả khái niệm):
1. Ứng dụng/user truy cập tài nguyên theo **tên** (ví dụ `\\FILESRV\share`, hoặc truy vấn “wpad”, hoặc truy cập host name nội bộ).
2. Nếu DNS không trả lời/không đúng suffix/flat name, client có thể phát truy vấn **LLMNR/NBT‑NS** trong local link.
3. Attacker trong cùng subnet có thể **giả làm “nguồn phân giải tên”** bằng cách trả lời nhanh → khiến client kết nối nhầm tới host của attacker (hoặc một “relay point”).
4. Khi client cố truy cập SMB/HTTP/LDAP…, cơ chế “integrated authentication” có thể tự động gửi **NTLM challenge‑response**.
5. Attacker có thể:
   - **Harvest**: thu thập vật liệu chứng thực (ví dụ NetNTLMv2 challenge‑response) để phục vụ tấn công offline, hoặc
   - **Relay**: chuyển tiếp quá trình xác thực tới một dịch vụ đích (SMB/LDAP/HTTP…) nếu dịch vụ đích không áp dụng bảo vệ phù hợp.

**(C) IoT / thiết bị biên (NAS, printer, camera, gateway…)**
- Nhiều IoT/NAS/printer hỗ trợ **SMB** (thậm chí SMBv1/guest) → có thể trở thành:
  - **Target yếu** (không hỗ trợ/không bật signing/encryption),
  - **Nguồn name discovery** (đặt tên thiết bị/NetBIOS),
  - **Điểm pivot** nếu bị compromise.
- IoT thường khó cập nhật firmware/khó áp chính sách domain → cần **segmentation** và “deny by default”.

### 1.3 Công cụ & phần mềm thường gặp (theo hướng quan sát/đánh giá an ninh)
> Danh sách dưới đây nhằm **nhận diện** và **phòng thủ**; không kèm hướng dẫn vận hành khai thác.

- **Phân tích gói & điều tra:**  
  - Wireshark (LLMNR/NBNS/SMB/NTLM traffic), tcpdump (Linux), Windows Message Analyzer (legacy).
- **Giám sát Windows/AD:**  
  - Windows Event Logs (Security + SMB logs), Sysmon, EDR (Microsoft Defender for Endpoint…), SIEM (Splunk/Elastic/Sentinel…).
- **Giám sát mạng:**  
  - IDS/IPS (Suricata/Snort), Zeek, NetFlow.
- **Đánh giá Wi‑Fi (chỉ khi attack diễn ra trên WLAN):**  
  - Kismet (RF recon/WIDS), Aircrack‑ng (audit WLAN), survey tools.
- **Công cụ tấn công “thường được nhắc tới trong nghiên cứu/đánh giá”:**  
  - Bộ công cụ mô phỏng poisoning/relay trong AD labs (ví dụ Responder, Inveigh, Impacket/ntlmrelay*).  
  *Lưu ý: chỉ nêu tên để hiểu threat landscape; không cung cấp cách dùng.*

---

## 2) Thuật toán (Algorithms)

### 2.1 Thuật toán mã hóa/xác thực bị khai thác / liên quan
**(A) NTLM / NTLMv2**
- “Điểm mấu chốt” không phải bẻ AES như Wi‑Fi, mà là:
  - **challenge‑response** có thể bị thu thập (harvest) hoặc **relay** trong một số điều kiện,
  - phụ thuộc vào việc client tự động gửi chứng thực tới “đích” mà nó tin là hợp lệ.  
- NTLM gắn với các primitive như **MD4 (NT hash)** và **HMAC‑MD5 (NTLMv2)** (mô tả khái niệm).

**(B) SMB Signing / Encryption (SMB2/SMB3)**
- SMB2 **trước đây** dùng **HMAC‑SHA256** cho signing; SMB3 dùng cơ chế signing mới hơn như **AES‑CMAC** và với SMB 3.1.1 có **AES‑128‑GMAC** (tùy nền tảng/phiên bản).  
- SMB 3.1.1 encryption hỗ trợ **AES‑128/256 GCM/CCM** (tùy Windows version và cấu hình).  
- Các cơ chế này nhằm chống **tampering/relay** và **eavesdropping**.

**(C) Wi‑Fi crypto (chỉ là “lớp ngoài” nếu attacker vào WLAN)**
- **WPA2:** AES‑CCMP (chuẩn), TKIP (legacy/không khuyến nghị).  
- **WPA3:** SAE cho auth (Personal) + yêu cầu PMF mạnh hơn.  
→ Các thuật toán này bảo vệ liên kết radio, nhưng attack LLMNR/NBT‑NS/SMB xảy ra **sau khi attacker đã vào mạng**.

### 2.2 Thuật toán tấn công (mô tả khái niệm)
- **Poisoning / Spoofing (race‑based):** trả lời nhanh/“thuyết phục” hơn để client tin là “đúng”.
- **Relay (store‑and‑forward):** chuyển tiếp luồng xác thực sang dịch vụ đích mà không cần giải mã mật khẩu.
- **Offline guessing (dictionary/brute‑force):** nếu attacker thu được material để thử offline (phụ thuộc chính sách & loại vật liệu).
- **Recon/clustering (bổ trợ):** gom nhóm hostnames/traffic để tìm mục tiêu relay “ngon” (NAS/printer/servers không harden).

### 2.3 Thuật toán phòng thủ (detection/response)
- **Entropy‑based / statistical detection:**  
  - phát hiện spike truy vấn LLMNR/NBT‑NS bất thường,  
  - tỷ lệ NXDOMAIN/failure cao,  
  - hostnames “lạ” hoặc tần suất WPAD probes tăng.
- **ML/DL anomaly detection (tùy tổ chức):**  
  - bất thường theo “ngữ cảnh”: user A nhưng đăng nhập SMB từ host X không quen thuộc,  
  - chuỗi sự kiện “name query → SMB auth failure/success” bất thường,  
  - đồ thị quan hệ giữa endpoints/servers thay đổi đột ngột.
- **Policy‑as‑code:** baseline config enforcement + drift detection.

---

## 3) Dependencies

### 3.1 Phụ thuộc firmware/driver/OS
- **Windows client/server version** (hành vi name resolution, SMB defaults).  
- **SMB dialects** hỗ trợ (SMB 3.1.1 mới có nhiều cơ chế bảo vệ mạnh).  
- **Firmware AP/switch**: có/không client isolation, ACL, 802.1X, DHCP snooping/DAI (nếu triển khai).

### 3.2 Phụ thuộc cấu hình người dùng / endpoint
- Bật **LLMNR/NBT‑NS** (mặc định/legacy compatibility).  
- Bật/để mặc định **WPAD auto‑detect** trong một số môi trường.  
- Cho phép **NTLM** rộng rãi; tự động gửi integrated auth.
- Mật khẩu yếu/tái sử dụng → nếu handshake bị thu thập thì rủi ro tăng.
- Nếu ở Wi‑Fi: **PSK yếu / WPS bật** có thể giúp attacker vào mạng dễ hơn (sau đó mới làm poisoning/relay).

### 3.3 Phụ thuộc hạ tầng mạng
- **Cùng broadcast domain** (LAN/WLAN/VLAN) là điều kiện rất phổ biến.
- Thiếu **segmentation** giữa user ↔ server ↔ IoT.
- SMB signing/encryption **không bắt buộc** trên target (hoặc target là thiết bị bên thứ ba thiếu hỗ trợ).
- DNS/WINS suffix search hoặc cấu hình “flat name” tạo nhiều fallback queries.

---

## 4) Context (ngữ cảnh triển khai & kịch bản)

### 4.1 Môi trường
- **Mạng công cộng:** quán café/khách sạn (Wi‑Fi open hoặc WPA2‑PSK chia sẻ).  
- **Doanh nghiệp/campus:** VLAN user + IoT + server.  
- **IoT:** printer/NAS/camera cùng subnet với PC.  
- **Mesh/home lab:** nhiều thiết bị consumer, hardening yếu.

### 4.2 Kịch bản điển hình
- **Public Wi‑Fi:** attacker vào cùng SSID; nạn nhân truy cập share nội bộ/VPN split‑tunnel hoặc bị trigger WPAD → rò credential/phiên.
- **Doanh nghiệp:** máy trạm bị compromise; attacker thu thập/relay credential nội bộ để mở rộng quyền.
- **Campus:** rogue IoT/thiết bị khách tạo bề mặt relay (SMB guest, SMB1).

---

## 5) Core Weakness (điểm yếu cốt lõi)

- **Fallback name resolution** (LLMNR/NBT‑NS) thiếu xác thực nguồn trả lời trong local link.
- **Tự động chứng thực** (integrated auth) khiến client có thể gửi NTLM tới “đích giả”.
- **Legacy/compatibility pressure:** NetBIOS/WPAD/NTLM tồn tại để tương thích, tạo bề mặt tấn công lâu dài.
- **Misconfig SMB:** không yêu cầu signing/encryption; tồn tại SMB1/guest hoặc thiết bị bên thứ ba không hỗ trợ.

---

## 6) Cost & Risk

### 6.1 Chi phí tấn công
- **Thấp** nếu attacker đã ở trong cùng LAN/WLAN: máy tính phổ thông + phần mềm miễn phí là đủ để nghe/đáp ứng broadcast.
- **Tăng** nếu cần vượt qua NAC/802.1X, hoặc phải on‑path ở cấp routing.

### 6.2 Chi phí phòng thủ
- **Trung bình → cao** tùy mức độ legacy:
  - Tắt LLMNR/NBT‑NS/WPAD và migrate app có thể cần **pilot** và xử lý tương thích.
  - Bắt buộc SMB signing/encryption có thể ảnh hưởng thiết bị cũ/third‑party.
  - WIDS/WIPS/EDR/SIEM cần ngân sách + nhân sự vận hành.

### 6.3 Rủi ro
- **Mất dữ liệu & chiếm tài khoản:** account takeover, lateral movement.
- **Gián đoạn dịch vụ:** nếu bật hardening không có lộ trình, có thể gây “break” legacy.
- **Pháp lý:** thu thập chứng thực/giám sát trái phép trên mạng công cộng có thể vi phạm luật/quy định.

---

## 7) Control Surface (các lớp kiểm soát)

### 7.1 Access Point / Access Layer (Wi‑Fi & switch)
- **WPA3‑Enterprise / WPA2‑Enterprise (802.1X/EAP‑TLS)** để hạn chế ai được vào LAN/WLAN; cấp VLAN/ACL theo thiết bị.
- **Guest Wi‑Fi:** bật **client isolation**, chặn east‑west.
- **Segmentation:** tách **User VLAN** khỏi **IoT VLAN**; chỉ mở port cần thiết (ví dụ chặn TCP/445 ở guest/IoT nếu không cần).
- **Giám sát RF & rogue device** (nếu attack xảy ra trên WLAN).

### 7.2 Client (Windows endpoints)
- **Vô hiệu hóa LLMNR** trên máy trạm/domain (theo GPO/MDM) khi không cần.
- **Giảm/loại NTLM** theo lộ trình; ưu tiên Kerberos; bật các cơ chế bảo vệ credential phù hợp (EDR/LSASS protection).
- **SMB client hardening:** yêu cầu signing/encryption khi có thể; tránh dùng IP khi map share; hạn chế CNAME trong một số kịch bản.
- **WPAD hardening:** giảm auto‑proxy discovery khi môi trường không dùng; kiểm soát DNS/DHCP cho bản ghi/option WPAD.

### 7.3 Network Layer
- **IDS/IPS**: rule phát hiện LLMNR/NBNS spoofing, spike WPAD lookups, SMB auth anomalies.
- **ACL/Firewall:** chặn UDP 5355 (LLMNR), UDP 137 (NBNS) giữa các segment (tùy nhu cầu); hạn chế SMB (TCP/445) chỉ trong server VLAN.
- **Logging:** NetFlow + Zeek + correlation với event log DC/file server.

### 7.4 Policy Layer
- **Baseline cấu hình:** ADMX/GPO/Intune; kiểm soát drift.
- **Quy định dùng Wi‑Fi công cộng:** bắt buộc VPN, tắt auto‑join, không truy cập SMB trực tiếp.
- **Đào tạo người dùng & IT:** nhận biết rủi ro “share theo tên”, “proxy/captive portal”, password hygiene.

---

## 8) Chain Value (chuỗi giá trị liên quan)

- **Nhà sản xuất phần cứng:** Wi‑Fi chipset/AP/controller, switch, endpoint NIC, IoT/NAS/printer.
- **Nhà cung cấp phần mềm:** Windows/AD, SMB stack, EDR, IDS/IPS, proxy/PAC management.
- **Doanh nghiệp triển khai:** Network team, Identity team, SOC/SIEM, IT operations.
- **Người dùng cuối:** hành vi kết nối mạng công cộng, thói quen dùng share.
- **Kẻ tấn công:** tận dụng broadcast domain + legacy auth.
- **Cơ quan/chuẩn/pháp luật:** IETF RFC, NIST/CISA guidance, quy định an toàn thông tin.

---

## References (kèm “Source Preference” và URL)

### P1 — Chuẩn/tiêu chuẩn & tài liệu chính thức
- RFC 4795 — Link‑Local Multicast Name Resolution (LLMNR):  
  https://www.rfc-editor.org/rfc/rfc4795
- RFC 1001 — NetBIOS over TCP/UDP (concepts & methods):  
  https://www.rfc-editor.org/rfc/rfc1001
- (Companion) RFC 1002 — NetBIOS over TCP/UDP (detailed specs):  
  https://www.rfc-editor.org/rfc/rfc1002
- Microsoft Learn — SMB security enhancements (encryption suites, signing algorithms):  
  https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security
- Microsoft Learn — SMB security hardening (SMB signing mặc định, relay protection, SMB over QUIC…):  
  https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening
- Microsoft Learn — Control SMB signing behavior:  
  https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing
- Microsoft Learn — Block NTLM connections on SMB:  
  https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking
- Microsoft Learn — NTLM overview:  
  https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview
- Microsoft Learn — ADMX_DnsClient Policy CSP (bao gồm “Turn off multicast name resolution” và mapping registry):  
  https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-dnsclient
- Microsoft Security Bulletin MS16‑077 — WPAD:  
  https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-077
- Microsoft Support — MS16‑077 security update article:  
  https://support.microsoft.com/en-us/topic/ms16-077-security-update-for-wpad-june-14-2016-2490f086-dc17-4a6e-2799-a974d1af385e
- NIST SP 800‑153 — Guidelines for Securing Wireless LANs (bối cảnh Wi‑Fi/802.11):  
  https://csrc.nist.gov/pubs/sp/800/153/final

### P2 — Khung tri thức/hướng dẫn cơ quan
- MITRE ATT&CK — T1557.001 (LLMNR/NBT‑NS Poisoning and SMB Relay):  
  https://attack.mitre.org/techniques/T1557/001/
- CISA — Eviction Strategies (T1557.001):  
  https://www.cisa.gov/eviction-strategies-tool/info-attack/T1557.001

### P3/P4 — Bổ sung ngữ cảnh triển khai (không phải nguồn chuẩn)
- Wireshark docs (phân tích gói):  
  https://www.wireshark.org/docs/
- Kismet docs (WIDS/RF recon):  
  https://www.kismetwireless.net/docs/readme/

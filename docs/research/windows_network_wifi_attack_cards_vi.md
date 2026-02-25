# Tổng hợp kỹ thuật & phòng thủ cho các kiểu tấn công mạng/Wi‑Fi (dạng “attack cards”)

> **Mục đích:** tài liệu phục vụ **phòng thủ, đánh giá an ninh, và đào tạo**.  
> **Lưu ý an toàn:** nội dung **không** cung cấp hướng dẫn khai thác từng bước/command cụ thể; chỉ mô tả cơ chế ở mức kỹ thuật và các biện pháp giảm thiểu/giám sát.

## Quy ước “Source Preference”
- **P1 (Ưu tiên cao nhất):** Chuẩn/tiêu chuẩn & tài liệu chính thức (RFC/IETF, NIST, Microsoft Learn/whitepaper, Wi‑Fi Alliance, IEEE/nhà sản xuất).
- **P2:** Khung tri thức & hướng dẫn cơ quan nhà nước/phi lợi nhuận (MITRE ATT&CK, CISA, MANRS…).
- **P3:** Nghiên cứu học thuật/whitepaper hội nghị (USENIX/Black Hat…).
- **P4:** Tài liệu vendor/primer (Fortinet, Cisco Meraki docs, Aruba docs…) khi cần thêm ngữ cảnh triển khai.

---

## 1) Windows Name Resolution & SMB Attacks (LLMNR/NBT‑NS/WPAD/SMB Relay)

### 1. Thông tin kỹ thuật (Technical Information)
- **Giao thức liên quan:** LLMNR (UDP/5355), NBT‑NS/NetBIOS (UDP/137), (thường đi kèm) WPAD, **SMB** (TCP/445), xác thực **NTLM**.
- **Cơ chế hoạt động:** Khi **DNS không trả lời/không có bản ghi**, Windows có thể **fallback** sang LLMNR/NBT‑NS để phân giải tên; kẻ tấn công có thể giả làm “nguồn phân giải tên” để **dẫn hướng** lưu lượng và khiến nạn nhân **gửi vật liệu xác thực** (NTLM) tới máy của kẻ tấn công → **thu thập/relay**.
- **Công cụ/PM thường gặp (quan sát/đánh giá):** Wireshark để phân tích LLMNR/NBNS/SMB; log Windows Security; công cụ WIDS/IDS nội bộ để phát hiện broadcast/poisoning; hardening bằng GPO.

### 2. Thuật toán (Algorithms)
- **Mã hóa/xác thực bị khai thác:** NTLM là cơ chế challenge‑response dựa trên “password‑derived key/hash”; SMB dùng ký/niêm phong (signing/encryption) nếu bật.
- **Thuật toán tấn công (khái niệm):** spoofing/poisoning (phản hồi nhanh hơn), relay (chuyển tiếp chứng thực), replay.
- **Thuật toán phòng thủ:** bắt buộc **SMB signing/encryption**, giảm bề mặt NTLM; phát hiện bất thường dựa trên entropy/độ hiếm truy vấn LLMNR, ML anomaly detection trên broadcast + pattern đăng nhập.

### 3. Dependencies
- **OS/driver:** Windows client/Server; tuỳ phiên bản và chính sách bảo mật.
- **Cấu hình người dùng:** bật auto-discovery (WPAD), cho phép NTLM, dùng local admin tái sử dụng.
- **Hạ tầng:** LAN có broadcast; switch/AP không chặn LLMNR/NBNS; SMB signing không bắt buộc.

### 4. Context
- **Môi trường:** doanh nghiệp/campus, đặc biệt VLAN nội bộ.
- **Kịch bản:** thiết bị người dùng truy cập share “\\server\share” nhưng DNS lỗi → fallback → bị dẫn hướng.

### 5. Core Weakness
- **Điểm yếu cốt lõi:** cơ chế **fallback name resolution** không có xác thực; phụ thuộc vào việc nạn nhân tự gửi NTLM tới “máy được tin là đúng”.
- **Yếu tố con người:** người dùng dễ bấm/nhập vào share/tài nguyên theo tên.

### 6. Cost & Risk
- **Chi phí tấn công:** thấp (phần mềm miễn phí, 1 máy trong LAN).
- **Chi phí phòng thủ:** vừa (GPO hardening, SMB signing, giám sát).
- **Rủi ro:** lộ thông tin đăng nhập, lateral movement, chiếm domain nếu kết hợp kỹ thuật khác.

### 7. Control Surface
- **Client:** tắt LLMNR/NBT‑NS nếu không cần; giảm NTLM; Credential Guard.
- **Server/SMB:** bắt buộc SMB signing; cân nhắc SMB encryption.
- **Network:** chặn UDP/5355, UDP/137 ở nơi phù hợp; segmentation; IDS/IPS.
- **Policy:** chuẩn hoá cấu hình Windows; kiểm kê dịch vụ legacy.

### 8. Chain Value
- **Chuỗi giá trị:** Microsoft (OS/SMB/NTLM), nhà cung cấp switch/IDS, doanh nghiệp triển khai AD, người dùng cuối, kẻ tấn công, cơ quan/chuẩn (MITRE/CISA).

### References (ưu tiên)
- **P1:** Microsoft SMB security hardening: https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening  
- **P2:** MITRE ATT&CK – LLMNR/NBT‑NS Poisoning & SMB Relay (T1557.001): https://attack.mitre.org/techniques/T1557/001/  
- **P2:** CISA – Adversary-in-the-Middle (T1557): https://www.cisa.gov/eviction-strategies-tool/info-attack/T1557  

---

## 2) DNS Cache Poisoning

### 1. Thông tin kỹ thuật
- **Giao thức:** DNS (RFC 1034/1035), caching recursive resolver; DNSSEC (RFC 4033+) cho xác thực dữ liệu DNS.
- **Cơ chế:** kẻ tấn công tìm cách làm “resolver cache” lưu bản ghi sai (A/AAAA/NS…) bằng cách **tiêm** phản hồi giả với TxID/port khớp hoặc tận dụng sai sót cấu hình (open recursion, weak randomization).
- **Công cụ quan sát/đánh giá:** Wireshark/pcap, log BIND/Unbound, hệ thống Protective DNS.

### 2. Thuật toán
- **Mã hóa/xác thực:** DNSSEC dùng chữ ký số (RSA/ECDSA tuỳ triển khai) để xác thực RRsets.
- **Tấn công:** spoofing, replay; “guessing”/birthday‑style trên entropy của TxID/port.
- **Phòng thủ:** DNSSEC validation; tăng entropy (port + TxID + 0x20 encoding); anomaly detection theo “NXDOMAIN spikes”, TTL bất thường.

### 3. Dependencies
- **Hệ điều hành/phần mềm:** resolver (BIND/Unbound/Windows DNS…).
- **Cấu hình:** open recursion, không bật DNSSEC validation, NAT làm giảm entropy.
- **Hạ tầng:** upstream DNS, mạng có khả năng on‑path/off‑path.

### 4. Context
- **Môi trường:** ISP/corporate DNS; IoT gateway dùng DNS yếu.
- **Kịch bản:** chuyển hướng người dùng tới host giả/phishing/malware; phá vỡ cập nhật.

### 5. Core Weakness
- DNS truyền thống trên UDP **không có xác thực** nội dung; cache tin vào phản hồi “đúng định danh truy vấn”.

### 6. Cost & Risk
- **Chi phí tấn công:** từ thấp→vừa (tuỳ vị trí on‑path).
- **Chi phí phòng thủ:** vừa→cao (DNSSEC, vận hành trust anchor, giám sát).
- **Rủi ro:** chiếm phiên, phishing quy mô lớn, gián đoạn dịch vụ.

### 7. Control Surface
- **Resolver:** bật DNSSEC, harden recursion, randomization.
- **Network:** chặn spoofing (BCP38/ingress filtering), DoT/DoH cho client khi phù hợp.
- **Policy:** quản trị DNS tập trung, kiểm kê subdomain.

### 8. Chain Value
- IETF/RFC, NIST, nhà cung cấp DNS (Microsoft/ISC), doanh nghiệp vận hành, người dùng.

### References
- **P1:** RFC 5452 – DNS Cache Poisoning defenses: https://www.rfc-editor.org/rfc/rfc5452  
- **P1:** RFC 1034 – DNS concepts: https://www.rfc-editor.org/rfc/rfc1034  
- **P1:** RFC 4033 – DNSSEC intro: https://www.rfc-editor.org/rfc/rfc4033  
- **P1/P2:** NIST SP 800-81 Rev.3 (IPD) – Secure DNS Deployment: https://csrc.nist.gov/pubs/sp/800/81/r3/ipd  

---

## 3) SNMP Exploits

### 1. Thông tin kỹ thuật
- **Giao thức:** SNMPv1/v2c (community string), SNMPv3 (USM/VACM, auth/privacy).
- **Cơ chế:** lạm dụng **community string yếu/mặc định**, cấu hình “read‑write”, lộ MIB; đôi khi SNMP bị lợi dụng cho **reflection/amplification** nếu mở ra Internet.
- **Công cụ:** Wireshark; công cụ kiểm kê/giám sát SNMP; log thiết bị mạng.

### 2. Thuật toán
- **Mã hóa/xác thực:** SNMPv3 USM hỗ trợ xác thực và bảo mật nội dung (auth/integrity/confidentiality).
- **Tấn công:** dictionary/brute force vào community; enumeration; replay khi cấu hình yếu.
- **Phòng thủ:** chuyển sang SNMPv3; ACL theo IP quản trị; anomaly detection trên tần suất truy vấn/varBind.

### 3. Dependencies
- Firmware router/switch/printer; cấu hình community mặc định; mở UDP/161/162.

### 4. Context
- Doanh nghiệp/OT/IoT; thiết bị biên cấu hình lâu năm.

### 5. Core Weakness
- SNMPv1/v2c **thiếu bảo mật** (community như “shared secret” yếu; payload có thể bị lộ).

### 6. Cost & Risk
- **Chi phí tấn công:** thấp nếu có truy cập mạng; cao hơn nếu phải on‑path/Internet.
- **Rủi ro:** lộ cấu hình mạng, thay đổi cấu hình, gián đoạn.

### 7. Control Surface
- **Thiết bị:** SNMPv3, tắt RW, đổi community, rotate.
- **Network:** quản trị qua VLAN/VRF riêng; chặn SNMP từ Internet.
- **Policy:** baseline cấu hình thiết bị.

### 8. Chain Value
- Vendor thiết bị, NOC/SOC, nhà tích hợp.

### References
- **P1:** RFC 3411 – SNMP architecture: https://www.rfc-editor.org/rfc/rfc3411  
- **P1:** RFC 3414 – SNMPv3 USM security model: https://www.rfc-editor.org/rfc/rfc3414  

---

## 4) FTP Exploits

### 1. Thông tin kỹ thuật
- **Giao thức:** FTP (RFC 959) truyền thống **không mã hoá**, kênh điều khiển + kênh dữ liệu; FTPS (FTP over TLS) theo RFC 4217; (khuyến nghị thay thế) SFTP/SSH.
- **Cơ chế:** đánh cắp credential qua sniffing, lạm dụng cấu hình anonymous/weak auth, tấn công brute‑force vào tài khoản; sai cấu hình firewall/NAT gây mở rộng bề mặt.
- **Công cụ:** Wireshark; log FTP server; hệ thống brute force detection.

### 2. Thuật toán
- **Mã hóa/xác thực:** FTPS dùng TLS (AES/ChaCha20… tuỳ cấu hình); FTP thường không mã hoá.
- **Tấn công:** brute force/dictionary; credential replay nếu lộ.
- **Phòng thủ:** dùng TLS đúng chuẩn, MFA cho quản trị, rate limiting, denylist theo IP.

### 3. Dependencies
- Phần mềm FTP server (vsftpd/IIS FTP…); cấu hình TLS; hệ điều hành.

### 4. Context
- Hệ thống legacy, trao đổi file nội bộ, đối tác B2B.

### 5. Core Weakness
- FTP cổ điển **lộ mật khẩu/phiên** trên mạng; mô hình kênh đôi làm phức tạp firewall.

### 6. Cost & Risk
- **Chi phí tấn công:** thấp nếu sniffing nội bộ; vừa nếu chỉ có Internet.
- **Rủi ro:** lộ dữ liệu, chèn file độc hại, chiếm tài khoản.

### 7. Control Surface
- **Server:** tắt FTP cleartext; bật FTPS/SFTP; harden cipher suites.
- **Client:** không dùng FTP plaintext; kiểm tra chứng chỉ.
- **Network:** segment server, WAF/IDS cho dịch vụ quản trị.
- **Policy:** loại bỏ legacy.

### 8. Chain Value
- Vendor OS/server, doanh nghiệp vận hành, đối tác, người dùng.

### References
- **P1:** RFC 959 – FTP: https://www.rfc-editor.org/rfc/rfc959  
- **P1:** RFC 4217 – Securing FTP with TLS: https://www.rfc-editor.org/rfc/rfc4217  

---

## 5) Pass‑the‑Hash (PtH)

### 1. Thông tin kỹ thuật
- **Giao thức/cơ chế liên quan:** NTLM (challenge‑response), NTLM over SMB/HTTP; Windows credential storage (LSASS).
- **Cơ chế:** kẻ tấn công lấy được **password hash** (ví dụ NTLM hash) và dùng nó như “vật liệu xác thực thay thế” để đăng nhập/lateral movement mà không cần plaintext password.
- **Công cụ quan sát/đánh giá:** Windows event logs, Microsoft Defender/EDR, Sysmon; phân tích đăng nhập NTLM.

### 2. Thuật toán
- **Mã hóa/xác thực:** NTLM challenge‑response dựa trên hash; PtH khai thác việc hash có thể đóng vai “bí mật”.
- **Tấn công:** credential replay/alternate authentication material.
- **Phòng thủ:** giảm/loại NTLM; Credential Guard; hạn chế local admin; tiered admin; phát hiện bất thường (anomaly detection theo logon type, nguồn/đích).

### 3. Dependencies
- Windows/AD; NTLM còn được cho phép; reuse local admin; thiếu LAPS/không phân tầng admin.

### 4. Context
- Doanh nghiệp AD, file share/SMB/RDP nội bộ.

### 5. Core Weakness
- Hash có thể được dùng lại trong một số luồng xác thực; môi trường nhiều tài khoản đặc quyền + reuse.

### 6. Cost & Risk
- **Chi phí tấn công:** vừa (cần lấy hash trước), nhưng sau đó lan rộng nhanh.
- **Chi phí phòng thủ:** vừa→cao (hardening, thay đổi quy trình admin).
- **Rủi ro:** domain compromise, ransomware.

### 7. Control Surface
- **Client/Server:** Credential Guard, LSASS protection, patching.
- **Identity:** giảm NTLM, ưu tiên Kerberos; LAPS/Windows LAPS cho local admin.
- **Network:** segmentation, restrict admin protocols.
- **Policy:** PAM, least privilege.

### 8. Chain Value
- Microsoft, vendor EDR, doanh nghiệp triển khai AD, người dùng/IT admins.

### References
- **P1:** Microsoft PtH whitepaper (PDF): https://download.microsoft.com/download/7/7/A/77ABC5BD-8320-41AF-863C-6ECFB10CB4B9/Mitigating-Pass-the-Hash-Attacks-and-Other-Credential-Theft-Version-2.pdf  
- **P1:** NTLM overview: https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview  
- **P2:** MITRE ATT&CK – Pass the Hash (T1550.002): https://attack.mitre.org/techniques/T1550/002/  

---

## 6) Kerberos & LDAP‑Based Attacks (Active Directory)

### 1. Thông tin kỹ thuật
- **Giao thức:** Kerberos (KDC, TGT/TGS), LDAP cho truy vấn directory; LDAPS/StartTLS khi mã hoá.
- **Cơ chế:** tấn công thường xoay quanh **vật liệu vé (ticket)**, cấu hình cipher yếu (ví dụ RC4 legacy), hoặc cấu hình LDAP không an toàn (simple bind không TLS, thiếu LDAP signing/channel binding, quyền truy vấn quá rộng).
- **Công cụ (phòng thủ/giám sát):** Windows auditing (event 4768/4769…), giám sát DC, Wireshark cho Kerberos/LDAP, SIEM.

### 2. Thuật toán
- **Kerberos:** dùng AES/RC4‑HMAC tuỳ cấu hình; khoá từ mật khẩu tài khoản dịch vụ/máy.
- **LDAP:** xác thực qua SASL hoặc simple bind; bảo vệ qua TLS; integrity/signing ở lớp ứng dụng/transport.
- **Phòng thủ:** migration từ RC4 sang AES; nguyên tắc “secure bind”; anomaly detection trên volume truy vấn/đăng nhập.

### 3. Dependencies
- Phiên bản Windows Server/DC, cấu hình domain, legacy apps cần RC4/LDAP simple bind.

### 4. Context
- Doanh nghiệp; tích hợp SSO, ứng dụng nội bộ, hệ thống IAM.

### 5. Core Weakness
- Trust/misconfig; legacy crypto; quyền truy cập directory “quá rộng”; thiếu ràng buộc kênh (channel binding).

### 6. Cost & Risk
- **Chi phí tấn công:** từ vừa→cao (phụ thuộc vị trí và quyền).
- **Rủi ro:** leo thang đặc quyền, điều khiển domain.

### 7. Control Surface
- **Identity/DC:** harden Kerberos/LDAP, bật logging, giảm RC4, LDAP signing.
- **Apps:** migrate LDAPS/StartTLS; giảm đặc quyền tài khoản dịch vụ.
- **Policy:** quản trị SPN/service account, kiểm soát thay đổi.

### 8. Chain Value
- Microsoft/AD ecosystem, vendor ứng dụng, doanh nghiệp, người dùng.

### References
- **P1:** RFC 4120 – Kerberos V5: https://www.rfc-editor.org/rfc/rfc4120  
- **P1:** RFC 4511 – LDAP protocol: https://www.rfc-editor.org/rfc/rfc4511  
- **P2:** CISA – Detecting & Mitigating Active Directory Compromises: https://www.cisa.gov/resources-tools/resources/detecting-and-mitigating-active-directory-compromises  

---

## 7) Kerberoasting

### 1. Thông tin kỹ thuật
- **Giao thức:** Kerberos (TGS ticket cho service/SPN).
- **Cơ chế:** kẻ tấn công tìm cách có được **service ticket (TGS)** cho tài khoản dịch vụ; nếu ticket được mã hoá bằng khoá suy ra từ mật khẩu yếu/RC4 legacy, có thể bị **brute‑force offline** để suy ra mật khẩu tài khoản dịch vụ.
- **Quan sát/giám sát:** event **4769** trên DC (TGS requested) là tín hiệu cần tương quan ngữ cảnh.

### 2. Thuật toán
- **Crypto liên quan:** RC4‑HMAC (legacy) dễ bị lạm dụng hơn; AES tốt hơn nhưng vẫn phụ thuộc mật khẩu mạnh.
- **Tấn công:** dictionary/brute force offline trên vật liệu ticket.
- **Phòng thủ:** chuyển sang AES, bỏ RC4; mật khẩu dài cho service accounts; gMSA; anomaly detection cho pattern TGS.

### 3. Dependencies
- AD có service accounts/SPN; policy crypto còn RC4; mật khẩu dịch vụ yếu/không rotate.

### 4. Context
- Doanh nghiệp; hệ thống có nhiều dịch vụ (SQL/HTTP/SharePoint…) dùng SPN.

### 5. Core Weakness
- Vé dịch vụ có thể bị lấy bởi principal hợp lệ; sức mạnh bảo mật phụ thuộc vào khoá từ mật khẩu/cipher.

### 6. Cost & Risk
- **Chi phí tấn công:** vừa (cần foothold/quyền trong domain); bẻ offline có thể tốn compute.
- **Chi phí phòng thủ:** vừa→cao (migrate crypto, gMSA, inventory SPN).
- **Rủi ro:** chiếm tài khoản dịch vụ, leo thang.

### 7. Control Surface
- **DC/KDC:** giảm RC4, tăng logging.
- **Identity:** gMSA, mật khẩu dài; giảm SPN không cần thiết.
- **Network/Policy:** phát hiện truy vấn TGS bất thường; quy trình quản lý service accounts.

### 8. Chain Value
- Microsoft + vendor ứng dụng AD‑integrated; doanh nghiệp; attacker.

### References
- **P1:** Microsoft guidance to mitigate Kerberoasting: https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/  
- **P1:** Microsoft blog “Beyond RC4…” (lộ trình tắt RC4): https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication  
- **P1:** Event 4769 (Kerberos service ticket requested): https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769  
- **P2:** MITRE ATT&CK – Kerberoasting (T1558.003): https://attack.mitre.org/techniques/T1558/003/  

---

## 8) On‑Path / Adversary‑in‑the‑Middle (AiTM) Attacks

### 1. Thông tin kỹ thuật
- **Giao thức:** phụ thuộc lớp tấn công: ARP (LAN), DHCP (LAN), DNS (resolver), Wi‑Fi evil twin; mục tiêu là “đứng giữa” để sniff/modify/relay.
- **Cơ chế:** thao túng cơ chế định tuyến/ánh xạ (ARP), cấp phát địa chỉ (DHCP), phân giải tên (DNS/LLMNR), hoặc lừa kết nối Wi‑Fi để trở thành điểm trung gian.
- **Công cụ (phòng thủ):** DAI/DHCP snooping, IDS/IPS, TLS inspection theo chính sách, chứng chỉ/pinning.

### 2. Thuật toán
- **Tấn công:** spoofing + replay + relay.
- **Phòng thủ:** xác thực hai chiều (mTLS/802.1X/EAP‑TLS), integrity checking (DAI), anomaly detection theo thay đổi gateway/DNS.

### 3. Dependencies
- Mạng LAN broadcast; switch/AP không bật DAI/DHCP snooping; thiết bị tin vào gateway/DNS không xác thực.

### 4. Context
- Quán café, mạng doanh nghiệp, IoT subnet.

### 5. Core Weakness
- Nhiều giao thức lớp 2/3 **thiếu xác thực** (ARP/DHCP), và con người dễ bị lừa (Wi‑Fi).

### 6. Cost & Risk
- **Chi phí tấn công:** thấp→vừa (tuỳ vị trí).
- **Rủi ro:** đánh cắp credential/phiên, chỉnh sửa dữ liệu, malware.

### 7. Control Surface
- **Network:** DAI, DHCP snooping, segmentation.
- **App/Client:** TLS/HSTS, VPN, certificate validation.
- **Policy:** ZTNA, đào tạo người dùng.

### 8. Chain Value
- Vendor switch/AP, enterprise SOC, chuẩn TLS/IETF.

### References
- **P2:** MITRE ATT&CK – Adversary‑in‑the‑Middle (T1557): https://attack.mitre.org/techniques/T1557/  
- **P2:** MITRE – ARP Cache Poisoning (T1557.002): https://attack.mitre.org/techniques/T1557/002/  
- **P1:** RFC 826 – ARP: https://www.rfc-editor.org/rfc/rfc826  
- **P4:** Cisco Meraki – Dynamic ARP Inspection (DAI): https://documentation.meraki.com/Switching/MS_-_Switches/Operate_and_Maintain/How-Tos/Dynamic_ARP_Inspection  

---

## 9) Route Manipulation Attacks (BGP/IGP hijack, route leak)

### 1. Thông tin kỹ thuật
- **Giao thức:** BGP (Internet), IGP (OSPF/IS‑IS) trong nội bộ; tuyến đường quyết định đường đi gói tin.
- **Cơ chế:** quảng bá prefix sai/hijack, route leak, thay đổi policy để chuyển hướng lưu lượng qua AS/thiết bị của kẻ tấn công.
- **Công cụ (phòng thủ):** giám sát BGP (ROV/RPKI), route monitoring, alert theo bất thường ASN/prefix.

### 2. Thuật toán
- **Tấn công:** route injection/announcement manipulation; đôi khi kết hợp traffic engineering.
- **Phòng thủ:** **RPKI/ROV**, lọc prefix (prefix‑list), anomaly detection theo thay đổi AS‑path.

### 3. Dependencies
- Nhà mạng/AS vận hành BGP; thiếu RPKI/ROV; cấu hình policy sai.

### 4. Context
- ISP, CDN, enterprise multi‑homing.

### 5. Core Weakness
- BGP truyền thống dựa nhiều vào **trust** giữa các AS; bảo mật phụ thuộc thực hành vận hành.

### 6. Cost & Risk
- **Chi phí tấn công:** cao hơn (cần vị trí/AS hoặc compromise).
- **Rủi ro:** nghe lén, chuyển hướng, gián đoạn diện rộng.

### 7. Control Surface
- **Routing:** ROV, filtering, MANRS.
- **Network:** giám sát NetFlow, DDoS mitigation kết hợp.
- **Policy:** quy trình change management.

### 8. Chain Value
- Nhà mạng, IETF, NIST, doanh nghiệp dùng dịch vụ.

### References
- **P1:** RFC 4271 – BGP‑4: https://www.rfc-editor.org/rfc/rfc4271  
- **P1:** NIST SP 800-189 Rev.1 (IPD) – BGP Security & Resilience: https://csrc.nist.gov/pubs/sp/800/189/r1/ipd  
- **P2:** MANRS documentation: https://docs.manrs.org/  

---

## 10) DoS & DDoS Attacks

### 1. Thông tin kỹ thuật
- **Loại hình:** volumetric (băng thông), protocol (SYN floods, amplification), application (HTTP floods).
- **Cơ chế:** làm cạn kiệt tài nguyên (CPU, conn table, băng thông) hoặc kích hoạt cơ chế retry/backoff.
- **Công cụ (phòng thủ):** rate limiting, WAF, CDN/scrubbing, NetFlow, SIEM.

### 2. Thuật toán
- **Tấn công:** flooding, reflection/amplification (DNS/NTP/SSDP…).
- **Phòng thủ:** anomaly detection (baseline theo thời gian), entropy‑based (IP/UA distribution), automated mitigation (RTBH/flowspec theo chính sách).

### 3. Dependencies
- Bề mặt dịch vụ public; thiếu CDN/WAF; cấu hình anti‑spoofing yếu.

### 4. Context
- Doanh nghiệp public web/API; dịch vụ critical.

### 5. Core Weakness
- Internet “best effort”; khó phân biệt flash crowd vs DoS.

### 6. Cost & Risk
- **Chi phí tấn công:** thấp→rất cao (tùy botnet).
- **Chi phí phòng thủ:** vừa→cao (scrubbing, CDN).
- **Rủi ro:** downtime, thiệt hại doanh thu, SLA.

### 7. Control Surface
- **Edge/CDN/WAF**, **Network** (RTBH/flowspec), **App** (caching, backpressure), **Policy** (IR playbook).

### 8. Chain Value
- ISP/CDN, enterprise, người dùng.

### References
- **P1:** RFC 4732 – Internet DoS considerations: https://www.rfc-editor.org/rfc/rfc4732  
- **P2:** CISA – DDoS Quick Guide: https://www.cisa.gov/resources-tools/resources/understanding-denial-service-attacks  
- **P1/P2:** NIST SP 800-189 Rev.1 (IPD) – routing security + DDoS aspects: https://csrc.nist.gov/pubs/sp/800/189/r1/ipd  

---

## 11) Network Access Control (NAC) Bypass

### 1. Thông tin kỹ thuật
- **Giao thức/công nghệ:** 802.1X (port‑based access control), EAP, RADIUS; NAC thường kết hợp posture (AV/MDM) và dynamic VLAN/ACL.
- **Cơ chế bypass (khái niệm):** khai thác **misconfiguration** (fallback sang MAB/guest), lộ credential, thiết bị trung gian (rogue switch), hoặc thiếu ràng buộc danh tính thiết bị.
- **Công cụ (phòng thủ):** log NAC/RADIUS, Wireshark cho EAPOL, SIEM correlation.

### 2. Thuật toán
- **Xác thực:** EAP‑TLS (mạnh), PEAP/MSCHAPv2 (yếu hơn nếu triển khai sai).
- **Tấn công:** credential replay, session hijack nếu kiểm soát kênh yếu.
- **Phòng thủ:** EAP‑TLS + device cert; continuous posture; anomaly detection theo “MAC move”, “unexpected VLAN”.

### 3. Dependencies
- Firmware switch, supplicant OS/driver; cấu hình fallback; quản lý chứng chỉ/PKI.

### 4. Context
- Campus/enterprise wired + Wi‑Fi.

### 5. Core Weakness
- “Compatibility mode” (guest/MAB) và quy trình onboard thiết bị không chặt.

### 6. Cost & Risk
- **Chi phí tấn công:** vừa (thường cần có mặt trong mạng).
- **Chi phí phòng thủ:** cao (NAC, PKI, vận hành).
- **Rủi ro:** truy cập trái phép vào VLAN nội bộ, lateral movement.

### 7. Control Surface
- **Access layer:** cấu hình 802.1X đúng, giảm fallback.
- **Identity/PKI:** cấp/thu hồi cert, MDM.
- **Network:** dynamic segmentation, monitoring.
- **Policy:** onboarding thiết bị, BYOD.

### 8. Chain Value
- Vendor NAC, switch/AP, PKI/MDM, doanh nghiệp.

### References
- **P1:** RFC 3748 – EAP: https://www.rfc-editor.org/rfc/rfc3748  
- **P1:** RFC 2865 – RADIUS: https://www.rfc-editor.org/rfc/rfc2865  
- **P1/P4:** NIST SP 800-97 – Wireless RSN guidance (nêu 802.1X/EAP trong ngữ cảnh WLAN): https://csrc.nist.gov/pubs/sp/800/97/final  

---

## 12) VLAN Hopping

### 1. Thông tin kỹ thuật
- **Giao thức/công nghệ:** IEEE 802.1Q VLAN tagging; trunk/access port; một số môi trường có cơ chế auto‑trunk (DTP/vendor‑specific).
- **Cơ chế (khái niệm):** lợi dụng cấu hình trunk/native VLAN để “nhảy” VLAN (ví dụ double‑tagging) hoặc switch spoofing khi port bị cấu hình sai.
- **Công cụ phòng thủ:** giám sát switch logs, port security, IDS nội bộ.

### 2. Thuật toán
- **Tấn công:** frame crafting/tagging (khái niệm).
- **Phòng thủ:** disable auto‑trunk, xác định rõ native VLAN, pruning, VLAN ACL.

### 3. Dependencies
- Cấu hình switch (trunk để hở, native VLAN dùng chung), driver NIC hỗ trợ tagging.

### 4. Context
- Doanh nghiệp/campus nhiều VLAN.

### 5. Core Weakness
- Misconfiguration ở access layer (trunk negotiation/thiếu kiểm soát).

### 6. Cost & Risk
- **Chi phí tấn công:** vừa (thường cần cắm dây/foothold).
- **Rủi ro:** phá segmentation, truy cập tài nguyên VLAN khác.

### 7. Control Surface
- **Switch:** port mode cố định, tắt negotiation khi không cần, ACL.
- **Network:** micro‑segmentation, monitoring.
- **Policy:** baseline cấu hình access switch.

### 8. Chain Value
- Vendor switch, enterprise ops.

### References
- **P4:** Juniper – VLAN tagging (802.1Q) concepts: https://www.juniper.net/documentation/us/en/software/junos/vlan-l2/topics/concept/l2-vlan-tagging-understanding.html  
- **P4:** JumpCloud – VLAN hopping overview & mitigations: https://jumpcloud.com/blog/vlan-hopping-attack  

---

## 13) DHCP Starvation & Rogue DHCP Servers

### 1. Thông tin kỹ thuật
- **Giao thức:** DHCP (RFC 2131). Client tin vào DHCP server để nhận IP/gateway/DNS.
- **Cơ chế:** **starvation** làm cạn pool DHCP; hoặc **rogue DHCP** cấp phát cấu hình sai (gateway/DNS) để dẫn hướng/gián đoạn.
- **Công cụ phòng thủ:** DHCP snooping, IP source guard, log DHCP server, IDS.

### 2. Thuật toán
- **Tấn công:** flooding/abuse of state; spoofing DHCP responses.
- **Phòng thủ:** DHCP snooping + binding table; anomaly detection theo số lease request/spike.

### 3. Dependencies
- Switch hỗ trợ snooping; cấu hình trust/untrust; DHCP server logs.

### 4. Context
- LAN doanh nghiệp, Wi‑Fi guest/campus.

### 5. Core Weakness
- DHCP không có xác thực mặc định; dễ bị giả mạo trong broadcast domain.

### 6. Cost & Risk
- **Chi phí tấn công:** thấp nếu ở cùng L2.
- **Rủi ro:** MITM, DNS hijack, mất kết nối diện rộng.

### 7. Control Surface
- **Switch:** DHCP snooping, rate limit.
- **Server:** monitoring lease anomalies.
- **Policy:** phân tách VLAN, cổng “trusted” rõ ràng.

### 8. Chain Value
- Vendor switch, enterprise networking.

### References
- **P1:** RFC 2131 – DHCP: https://www.rfc-editor.org/rfc/rfc2131  
- **P2:** MITRE ATT&CK – DHCP Spoofing (T1557.003): https://attack.mitre.org/techniques/T1557/003/  

---

## 14) Rogue Access Points (Rogue AP)

### 1. Thông tin kỹ thuật
- **Giao thức:** IEEE 802.11 (Wi‑Fi). Rogue AP là AP không được quản trị cho phép nhưng nối vào mạng nội bộ (cắm LAN hoặc mesh).
- **Cơ chế:** mở “cửa hậu” vào mạng; có thể dùng SSID hợp pháp hoặc SSID mới; đôi khi cấu hình bảo mật yếu (open/WEP).
- **Công cụ:** WIDS/WIPS; Kismet; kiểm kê RF; NAC.

### 2. Thuật toán
- **Tấn công:** social + misconfig exploitation.
- **Phòng thủ:** phát hiện dựa trên RF fingerprint, ML anomaly (BSSID lạ, location, channel), whitelist.

### 3. Dependencies
- Chính sách BYOD lỏng; cổng mạng không kiểm soát (802.1X chưa bật); AP consumer dễ mua.

### 4. Context
- Campus/doanh nghiệp; nhân viên tự cắm AP.

### 5. Core Weakness
- Thiếu kiểm soát ở access layer + thiếu giám sát RF.

### 6. Cost & Risk
- **Chi phí tấn công:** thấp.
- **Chi phí phòng thủ:** vừa (WIDS/WIPS, survey định kỳ).
- **Rủi ro:** truy cập trái phép, MITM, rò rỉ dữ liệu.

### 7. Control Surface
- **AP/controller:** rogue detection, WLAN policy.
- **Switch/NAC:** 802.1X, port security.
- **Policy:** cấm AP cá nhân, kiểm tra định kỳ.

### 8. Chain Value
- Vendor Wi‑Fi, SOC/NOC, người dùng.

### References
- **P1:** NIST SP 800-153 – WLAN security lifecycle: https://csrc.nist.gov/pubs/sp/800/153/final  
- **P4:** Kismet docs (WIDS/wardriving): https://www.kismetwireless.net/docs/readme/configuring/  

---

## 15) Evil Twin Attacks

### 1. Thông tin kỹ thuật
- **Giao thức:** 802.11; SSID/BSSID; WPA2/WPA3; captive portal.
- **Cơ chế:** dựng AP giả mạo SSID giống thật để lừa client kết nối; sau khi kết nối có thể theo dõi/điều hướng traffic, hoặc dùng captive portal giả để thu credential.
- **Công cụ phòng thủ:** WIDS/WIPS; xác thực chứng chỉ (HTTPS), VPN, cảnh báo SSID.

### 2. Thuật toán
- **Tấn công:** spoofing (SSID/BSSID), credential harvesting, AiTM.
- **Phòng thủ:** 802.1X/EAP‑TLS cho enterprise; WPA3 + PMF; anomaly detection (BSSID mới, RSSI bất thường, location).

### 3. Dependencies
- Người dùng bật auto‑join; mạng open/captive portal; thiếu certificate hygiene.

### 4. Context
- Quán café/sân bay; hội nghị; campus.

### 5. Core Weakness
- Wi‑Fi truyền thống **không xác thực AP mạnh** với người dùng (đặc biệt mạng open); con người dễ bị lừa.

### 6. Cost & Risk
- **Chi phí tấn công:** thấp→vừa.
- **Rủi ro:** lộ credential, session hijack, malware.

### 7. Control Surface
- **AP:** WPA3/Enterprise; PMF; tắt WPS.
- **Client:** VPN, kiểm tra HTTPS, tắt auto‑join.
- **Network:** WIDS/WIPS.
- **Policy:** đào tạo nhận biết “SSID giả”.

### 8. Chain Value
- Wi‑Fi Alliance, vendor AP, doanh nghiệp, người dùng.

### References
- **P2:** MITRE ATT&CK – Evil Twin (T1557.004): https://attack.mitre.org/techniques/T1557/004/  
- **P1:** NIST SP 800-153 – WLAN guidelines: https://csrc.nist.gov/pubs/sp/800/153/final  

---

## 16) Disassociation / Deauthentication Attacks

### 1. Thông tin kỹ thuật
- **Giao thức:** 802.11 management frames (disassoc/deauth). Nếu không bảo vệ, kẻ tấn công có thể làm client bị rớt khỏi AP (DoS) hoặc ép roam/reconnect.
- **Cơ chế:** lạm dụng việc management frames (một số loại) historically không được bảo vệ; tiêu chuẩn **802.11w / Protected Management Frames (PMF)** bổ sung bảo vệ cho một tập khung quản trị.
- **Công cụ phòng thủ:** bật PMF, giám sát “deauth storm”, WIDS.

### 2. Thuật toán
- **Tấn công:** spoofing management frames.
- **Phòng thủ:** PMF (integrity/replay protection), anomaly detection theo tần suất deauth.

### 3. Dependencies
- Hỗ trợ PMF ở AP/client; cấu hình WPA3 (thường bắt buộc PMF) hoặc WPA2+PMF.

### 4. Context
- Doanh nghiệp (gián đoạn), sự kiện đông người.

### 5. Core Weakness
- Khung quản trị trước khi có PMF dễ bị giả mạo.

### 6. Cost & Risk
- **Chi phí tấn công:** thấp (thiết bị RF phổ biến).
- **Rủi ro:** gián đoạn dịch vụ, tạo điều kiện cho Evil Twin.

### 7. Control Surface
- **AP/controller:** bật PMF; WPA3.
- **Client:** cập nhật driver, chọn WPA3.
- **Network/Policy:** WIDS/WIPS; SOP phản ứng sự cố.

### 8. Chain Value
- Chipset vendors, Wi‑Fi Alliance, doanh nghiệp.

### References
- **P1:** Wi‑Fi Alliance – PMF overview: https://www.wi-fi.org/security  
- **P4:** Aruba – PMF tech docs: https://arubanetworking.hpe.com/techdocs/aos/wifi-design-deploy/security/features/pmf/  
- **P4:** Cisco – 802.11w/PMF deployment guide (PDF): https://www.cisco.com/c/en/us/td/docs/wireless/controller/technotes/5700/software/release/ios_xe_33/11rkw_DeploymentGuide/b_802point11rkw_deployment_guide_cisco_ios_xe_release33/b_802point11rkw_deployment_guide_cisco_ios_xe_release33_chapter_0100.pdf  

---

## 17) Preferred Network List (PNL) Attacks

### 1. Thông tin kỹ thuật
- **Giao thức:** 802.11 scanning/probe requests; client có thể phát probe chứa SSID đã từng kết nối.
- **Cơ chế:** kẻ tấn công nghe probe/PNL và dựng AP với SSID phù hợp để dụ client auto‑connect.
- **Công cụ phòng thủ:** cấu hình client (tắt auto‑join), MAC randomization, WIDS.

### 2. Thuật toán
- **Tấn công:** probe‑based spoofing.
- **Phòng thủ:** ngẫu nhiên hoá MAC/scrambling, giảm phát probe, ML detection theo SSID/BSSID bất thường.

### 3. Dependencies
- OS/driver hành vi scanning; danh sách mạng lưu; auto‑connect.

### 4. Context
- Khu vực công cộng, hội nghị.

### 5. Core Weakness
- Metadata quản lý (probe) thường không mã hoá; hành vi auto‑join.

### 6. Cost & Risk
- **Chi phí tấn công:** thấp.
- **Rủi ro:** MITM, credential harvesting.

### 7. Control Surface
- **Client:** xoá mạng cũ, tắt auto‑join; cập nhật OS.
- **AP/Network:** WPA3‑Enterprise; WIDS/WIPS.
- **Policy:** hướng dẫn người dùng.

### 8. Chain Value
- OS vendors, chipset, enterprise security.

### References
- **P2:** MITRE – Evil Twin (nêu captive portal/credential capture): https://attack.mitre.org/techniques/T1557/004/  
- **P1:** Apple security – privacy features for probe requests: https://support.apple.com/guide/security/privacy-features-connecting-wireless-networks-secb9cb3140c/web  
- **P1:** IETF draft – MAC address randomization: https://www.ietf.org/archive/id/draft-ietf-madinas-mac-address-randomization-08.html  

---

## 18) Wireless Signal Jamming & Interference

### 1. Thông tin kỹ thuật
- **Bản chất:** gây nhiễu/chèn sóng trên băng tần Wi‑Fi (2.4/5/6 GHz) → tăng lỗi, giảm throughput, rớt kết nối.
- **Lưu ý pháp lý:** nhiều quốc gia (ví dụ Mỹ) **cấm** thiết bị gây nhiễu chủ động.
- **Công cụ phòng thủ:** spectrum analyzer, WIDS, khảo sát site, thiết kế kênh.

### 2. Thuật toán
- **Tấn công:** “energy”/noise flooding, interference.
- **Phòng thủ:** phát hiện dựa trên phổ (spectral), ML anomaly theo RSSI/noise floor.

### 3. Dependencies
- Mật độ AP, vật liệu toà nhà, thiết bị RF lân cận (lò vi sóng, BT…).

### 4. Context
- Doanh nghiệp (ảnh hưởng năng suất), sự kiện đông người.

### 5. Core Weakness
- Wi‑Fi hoạt động trên phổ chia sẻ, dễ bị nhiễu.

### 6. Cost & Risk
- **Chi phí tấn công:** từ thấp (gây nhiễu “tình cờ”) đến cao (thiết bị chuyên dụng).
- **Rủi ro:** gián đoạn dịch vụ, ảnh hưởng OT/IoT.

### 7. Control Surface
- **RF design:** channel planning, AP density, 5/6 GHz.
- **Monitoring:** WIDS + spectrum.
- **Policy:** quy trình phản ứng; phối hợp pháp lý khi nghi jamming.

### 8. Chain Value
- Nhà cung cấp RF/Wi‑Fi, doanh nghiệp, cơ quan quản lý tần số.

### References
- **P2/P1:** FCC – Jammer enforcement (mang tính tham khảo pháp lý): https://www.fcc.gov/general/jammer-enforcement  
- **P1:** NIST SP 800-153 – WLAN guidelines: https://csrc.nist.gov/pubs/sp/800/153/final  

---

## 19) War Driving

### 1. Thông tin kỹ thuật
- **Khái niệm:** thu thập thông tin Wi‑Fi (SSID/BSSID, kênh, RSSI, đôi khi vị trí GPS) khi di chuyển.
- **Cơ chế:** chủ yếu “passive scanning”; có thể dẫn tới tìm mạng open/misconfig.
- **Công cụ:** Kismet (sniffer/WIDS/wardriving), phần mềm khảo sát.

### 2. Thuật toán
- **Tấn công:** reconnaissance + clustering (gom nhóm AP theo vị trí/SSID).
- **Phòng thủ:** giảm metadata lộ (ẩn SSID không đủ), mạnh hoá WPA2/3, theo dõi beacon bất thường.

### 3. Dependencies
- AP phát beacon; thiết bị có GPS; chính sách ghi log.

### 4. Context
- Khu dân cư/campus; tấn công giai đoạn recon.

### 5. Core Weakness
- Beacon/probe là metadata công khai; misconfig (open/WEP).

### 6. Cost & Risk
- **Chi phí tấn công:** thấp.
- **Rủi ro:** thông tin phục vụ giai đoạn tấn công tiếp theo.

### 7. Control Surface
- **AP:** WPA2‑AES/WPA3; tắt WPS; segmentation IoT.
- **Monitoring:** WIDS; survey định kỳ.
- **Policy:** không dùng mạng open cho nội bộ.

### 8. Chain Value
- Vendor Wi‑Fi, doanh nghiệp, người dùng.

### References
- **P4:** Kismet – Wardrive Mode: https://www.kismetwireless.net/docs/readme/configuring/wardrive/  
- **P4:** Fortinet – Wardriving definition: https://www.fortinet.com/resources/cyberglossary/wardriving  

---

## 20) Initialization Vector (IV) Attacks & Unsecured Wireless Protocols (WEP/TKIP)

### 1. Thông tin kỹ thuật
- **Giao thức/chuẩn:** WEP dùng RC4 + IV ngắn; TKIP (WPA) là giải pháp chuyển tiếp; WPA2/802.11i dùng AES‑CCMP.
- **Cơ chế:** IV ngắn và/hoặc thiết kế/triển khai yếu dẫn tới thu thập đủ mẫu để phân tích thống kê → suy giảm bí mật khoá (đặc biệt WEP).
- **Công cụ:** phân tích gói (Wireshark); audit toolsets cho WLAN (chỉ dùng khi được phép).

### 2. Thuật toán
- **Crypto bị khai thác:** RC4 KSA weaknesses + IV reuse; WEP integrity yếu.
- **Tấn công:** statistical key recovery, replay.
- **Phòng thủ:** loại bỏ WEP/TKIP; dùng WPA2‑AES/WPA3‑SAE; PMF.

### 3. Dependencies
- AP/IoT legacy chỉ hỗ trợ WEP/TKIP; cấu hình người dùng.

### 4. Context
- Legacy IoT/thiết bị công nghiệp cũ.

### 5. Core Weakness
- Thiết kế WEP yếu (IV ngắn + RC4 KSA issues + integrity).

### 6. Cost & Risk
- **Chi phí tấn công:** thấp→vừa; phụ thuộc lưu lượng.
- **Chi phí phòng thủ:** vừa (thay thiết bị/upgrade).
- **Rủi ro:** giải mã lưu lượng, truy cập trái phép.

### 7. Control Surface
- **AP:** tắt WEP/TKIP; bật WPA2/WPA3.
- **Client:** không kết nối WEP; cảnh báo.
- **Policy:** kế hoạch thay thế thiết bị legacy.

### 8. Chain Value
- Chipset vendors, Wi‑Fi Alliance, doanh nghiệp.

### References
- **P3:** Fluhrer–Mantin–Shamir (RC4 KSA weakness, nền cho WEP break): https://www.cs.umd.edu/~waa/rc4_ksaproc.pdf  
- **P1:** NIST SP 800-97 – RSN/WLAN security: https://csrc.nist.gov/pubs/sp/800/97/final  

---

## 21) Karma Attacks

### 1. Thông tin kỹ thuật
- **Giao thức:** 802.11 probe requests; hành vi client tìm mạng đã biết.
- **Cơ chế:** một dạng “evil twin” khai thác việc client tiết lộ SSID đã lưu/đang tìm; AP giả trả lời để dụ client kết nối.
- **Công cụ phòng thủ:** giảm probe/auto‑join; randomization; WPA3/Enterprise.

### 2. Thuật toán
- **Tấn công:** probe‑response spoofing.
- **Phòng thủ:** giảm metadata, ML detection theo SSID/BSSID + location.

### 3. Dependencies
- OS/driver hành vi probe; auto‑reconnect; mạng open/captive portal.

### 4. Context
- Mạng công cộng, khu vực đông thiết bị.

### 5. Core Weakness
- Thiếu xác thực AP + probe metadata không mã hoá.

### 6. Cost & Risk
- Chi phí thấp; rủi ro cao nếu kết hợp credential harvesting.

### 7. Control Surface
- **Client:** tắt auto‑join; cập nhật OS; xóa mạng cũ.
- **Network/AP:** WPA3 + PMF; enterprise auth.
- **Policy:** hướng dẫn người dùng.

### 8. Chain Value
- OS vendors, Wi‑Fi Alliance, doanh nghiệp.

### References
- **P4:** KARMA attack overview: https://en.wikipedia.org/wiki/KARMA_attack  
- **P1:** Wi‑Fi Alliance security / PMF: https://www.wi-fi.org/security  
- **P1:** Apple probe/privacy randomization: https://support.apple.com/guide/security/privacy-features-connecting-wireless-networks-secb9cb3140c/web  

---

## 22) Fragmentation Attacks (FragAttacks)

### 1. Thông tin kỹ thuật
- **Giao thức/chuẩn:** 802.11 fragmentation & aggregation (A‑MSDU/A‑MPDU).  
- **Cơ chế:** các “design flaws” và “implementation flaws” cho phép kẻ tấn công **forge/inject** frame trong một số điều kiện, ngay cả khi mạng được bảo vệ, dẫn đến exfiltration/attacks nội bộ.
- **Công cụ phòng thủ:** update firmware/driver; theo khuyến nghị vendor; WIDS.

### 2. Thuật toán
- **Tấn công:** frame manipulation, fragmentation/aggregation abuse.
- **Phòng thủ:** patching; cấu hình giảm rủi ro theo hướng dẫn; anomaly detection theo pattern frame.

### 3. Dependencies
- Firmware AP, driver client, chipset; mức độ ảnh hưởng khác nhau theo thiết bị.

### 4. Context
- Doanh nghiệp, IoT, Wi‑Fi gia đình (thiết bị không cập nhật).

### 5. Core Weakness
- Flaw ở chuẩn/triển khai 802.11 liên quan fragmentation/aggregation.

### 6. Cost & Risk
- **Chi phí tấn công:** vừa (cần trong vùng RF).
- **Chi phí phòng thủ:** vừa (patching diện rộng).
- **Rủi ro:** xâm nhập nội bộ, rò dữ liệu.

### 7. Control Surface
- **AP/Client:** cập nhật, kiểm kê thiết bị; tắt tính năng rủi ro nếu vendor khuyến nghị.
- **Network:** segmentation, zero trust.
- **Policy:** quản trị vòng đời thiết bị IoT.

### 8. Chain Value
- Chipset/AP vendors, doanh nghiệp, người dùng.

### References
- **P3:** FragAttacks official site: https://www.fragattacks.com/  
- **P3:** USENIX paper (sec21‑vanhoef): https://www.usenix.org/system/files/sec21-vanhoef.pdf  
- **P3:** Overview PDF: https://papers.mathyvanhoef.com/fragattacks-overview.pdf  

---

## 23) Credential Harvesting

### 1. Thông tin kỹ thuật
- **Bề mặt:** phishing email/web, fake login portal, captive portal Wi‑Fi giả (liên quan Evil Twin).
- **Cơ chế:** lừa người dùng nhập credential hoặc đánh cắp input (keylogging/web portal capture).
- **Công cụ phòng thủ:** MFA (phishing‑resistant), email security, browser isolation, EDR, user training.

### 2. Thuật toán
- **Tấn công:** social engineering + web capture; đôi khi dùng replay.
- **Phòng thủ:** FIDO2/WebAuthn, risk‑based auth, anomaly detection theo địa lý/thiết bị, entropy detection cho login patterns.

### 3. Dependencies
- Thói quen người dùng; thiếu MFA; thiếu DMARC/SPF/DKIM; thiếu giám sát.

### 4. Context
- Mọi môi trường; Wi‑Fi công cộng dễ kết hợp captive portal giả.

### 5. Core Weakness
- Con người + giao diện đăng nhập dễ bị giả mạo; reuse mật khẩu.

### 6. Cost & Risk
- **Chi phí tấn công:** thấp.
- **Chi phí phòng thủ:** vừa (MFA, secure email).
- **Rủi ro:** account takeover, ransomware.

### 7. Control Surface
- **Identity:** MFA chống phishing, conditional access.
- **Network:** DNS filtering, web proxy.
- **Policy:** đào tạo + diễn tập phishing.

### 8. Chain Value
- Nhà cung cấp email/IdP, doanh nghiệp, người dùng, cơ quan hướng dẫn.

### References
- **P2:** CISA/NSA/FBI/MS‑ISAC – Phishing Guidance (PDF): https://www.cisa.gov/sites/default/files/2023-10/Phishing%20Guidance%20-%20Stopping%20the%20Attack%20Cycle%20at%20Phase%20One_508c.pdf  
- **P2:** MITRE ATT&CK – Input Capture (T1056): https://attack.mitre.org/techniques/T1056/  
- **P2:** MITRE – Evil Twin (captive portal credential capture): https://attack.mitre.org/techniques/T1557/004/  

---

## 24) Bluejacking & Bluesnarfing (Bluetooth)

### 1. Thông tin kỹ thuật
- **Giao thức:** Bluetooth BR/EDR, Bluetooth Low Energy (BLE); profile như OBEX (tuỳ trường hợp).
- **Cơ chế:**  
  - **Bluejacking:** gửi tin nhắn/“business card” không mong muốn (spam), thường ít nghiêm trọng hơn.  
  - **Bluesnarfing:** truy cập trái phép dữ liệu/đối tượng Bluetooth (đặc biệt trên thiết bị/stack cũ hoặc cấu hình discoverable/pairing yếu).
- **Công cụ phòng thủ:** tắt discoverable, quản lý pairing, update OS/firmware.

### 2. Thuật toán
- **Bảo mật:** pairing/auth + encryption (tuỳ phiên bản; LE Secure Connections mạnh hơn).
- **Tấn công:** abuse pairing/implementation flaws; brute force nếu cơ chế yếu.
- **Phòng thủ:** LE Secure Connections, policy “non‑discoverable”, anomaly detection cho pairing events.

### 3. Dependencies
- Phiên bản Bluetooth stack; chế độ discoverable; driver/firmware.

### 4. Context
- Văn phòng, nơi công cộng, thiết bị IoT/wearables.

### 5. Core Weakness
- Thiết bị cũ, pairing yếu, người dùng để discoverable.

### 6. Cost & Risk
- **Chi phí tấn công:** thấp (thiết bị BT phổ biến).
- **Rủi ro:** từ phiền nhiễu → lộ dữ liệu.

### 7. Control Surface
- **Client/device:** tắt BT khi không dùng; update; giới hạn profile.
- **Policy:** MDM baseline, quy định pairing.

### 8. Chain Value
- Vendor OS/phone, chipset BT, doanh nghiệp.

### References
- **P1:** NIST SP 800-121 Rev.2 (PDF) – Bluetooth Security: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-121r2-upd1.pdf  
- **P1:** NIST publication page: https://csrc.nist.gov/pubs/sp/800/121/r2/upd1/final  

---

## 25) RFID Attacks (và phần mở rộng)

### 1. Thông tin kỹ thuật
- **Công nghệ:** RFID (passive/active tags), nhiều chuẩn (ISO/IEC 14443, EPC Gen2… tuỳ ứng dụng).
- **Cơ chế:** skimming/eavesdropping, cloning, relay, tracking; nhiều tag giá rẻ có bảo mật hạn chế.
- **Công cụ phòng thủ:** shielding (ví), reader authentication, crypto tags, kiểm soát vùng đọc.

### 2. Thuật toán
- **Crypto:** tuỳ chuẩn (một số tag hỗ trợ challenge‑response, AES…; nhiều tag không).
- **Tấn công:** replay/relay, brute force vào secret yếu.
- **Phòng thủ:** mutual authentication, rolling codes, distance bounding (nếu có), anomaly detection theo thời gian/địa điểm quẹt.

### 3. Dependencies
- Loại tag/reader, firmware, chính sách truy cập vật lý.

### 4. Context
- Kiểm soát ra vào, kho vận, thanh toán không tiếp xúc.

### 5. Core Weakness
- Thiết bị rẻ, phạm vi đọc khó kiểm soát, thiếu xác thực ở một số hệ thống.

### 6. Cost & Risk
- **Chi phí tấn công:** từ thấp→vừa.
- **Chi phí phòng thủ:** vừa→cao (thay tag/reader, quy trình).
- **Rủi ro:** gian lận, xâm nhập vật lý, vi phạm riêng tư.

### 7. Control Surface
- **Reader/Back-end:** auth mạnh, logging, anti‑relay.
- **Physical:** kiểm soát vùng, shield.
- **Policy:** vòng đời thẻ, thu hồi.

### 8. Chain Value
- Nhà sản xuất tag/reader, doanh nghiệp, người dùng, cơ quan tiêu chuẩn.

### References
- **P1:** NIST SP 800-98 – RFID Systems Security: https://csrc.nist.gov/pubs/sp/800/98/final  
- **P1:** NIST publication page: https://www.nist.gov/publications/guidelines-securing-radio-frequency-identification-rfid-systems  

---

## 26) Password Spraying

### 1. Thông tin kỹ thuật
- **Bề mặt:** dịch vụ đăng nhập (VPN, O365/Entra, RDP, webmail, SSO).
- **Cơ chế:** thử **một vài mật khẩu phổ biến** trên **nhiều tài khoản** để tránh lockout của brute force 1 tài khoản.
- **Công cụ phòng thủ:** Identity Protection, SIEM, rate‑limit, MFA, banned passwords.

### 2. Thuật toán
- **Tấn công:** brute force “low‑and‑slow” / dictionary ngắn.
- **Phòng thủ:** throttling, risk‑based auth, ML anomaly (impossible travel, IP reputation), breached password screening.

### 3. Dependencies
- Chính sách lockout quá “dễ né”, thiếu MFA, mật khẩu yếu/reuse.

### 4. Context
- Internet‑facing authentication.

### 5. Core Weakness
- Mật khẩu yếu + không có MFA; bảo vệ rate‑based chưa đủ.

### 6. Cost & Risk
- **Chi phí tấn công:** thấp.
- **Chi phí phòng thủ:** vừa (MFA/conditional access).
- **Rủi ro:** account takeover, initial access.

### 7. Control Surface
- **Identity:** MFA chống phishing; banned passwords; conditional access.
- **Network/App:** rate limiting, WAF.
- **Policy:** password manager, đào tạo.

### 8. Chain Value
- IdP, doanh nghiệp, người dùng.

### References
- **P2:** MITRE ATT&CK – Password Spraying (T1110.003): https://attack.mitre.org/techniques/T1110/003/  
- **P1:** Microsoft Learn – Password spray investigation playbook: https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-password-spray  
- **P2:** CISA alert on password spraying: https://www.cisa.gov/news-events/alerts/2019/08/08/acsc-releases-advisory-password-spraying-attacks  
- **P1:** NIST SP 800-63B (Digital Identity Guidelines – Authentication & lifecycle): https://pages.nist.gov/800-63-3/sp800-63b.html  

---

## Phụ lục: Nguồn công cụ quan sát/phân tích (tham khảo chung)
- Wireshark: https://www.wireshark.org/docs/  
- Kismet docs: https://www.kismetwireless.net/docs/readme/  
- MITRE ATT&CK: https://attack.mitre.org/  
- NIST CSRC Publications: https://csrc.nist.gov/publications  

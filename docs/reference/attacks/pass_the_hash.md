# Pass-the-Hash Attacks (PtH) — Lạm dụng NTLM hash để xác thực & di chuyển ngang

> **Phạm vi:** mô tả kỹ thuật và kiểm soát **phòng thủ** cho tấn công **Pass-the-Hash (PtH)** trong hệ sinh thái Windows/Active Directory: kẻ tấn công dùng **password hash** (đặc biệt NTLM/NT hash) như “vật liệu xác thực thay thế” để đăng nhập/lateral movement mà **không cần mật khẩu dạng rõ**.  
> **Nguyên tắc an toàn:** không cung cấp lệnh/chuỗi thao tác khai thác; chỉ mô tả cơ chế, điều kiện, dấu hiệu và biện pháp giảm thiểu/giám sát.

---

## 1) Thông tin kỹ thuật (Technical Information)

### 1.1 Giao thức liên quan (PtH “thuần” là Windows auth; 802.11/WPA/EAP chỉ là lớp truy cập)
**(A) Hệ cơ chế xác thực Windows**
- **NTLM / NTLMv2** (NT LAN Manager):
  - cơ chế **challenge–response**; “bí mật” là khóa/giá trị dẫn xuất từ mật khẩu (NT hash), được dùng để tạo response.  
  - PtH tận dụng việc “có hash” đôi khi đủ để hoàn tất xác thực NTLM mà không cần mật khẩu.
  - Tài liệu giao thức (Open Specifications): **[MS‑NLMP]** mô tả NTLM chi tiết.
- **Kerberos**:
  - cơ chế ticket‑based (TGT/TGS); thường an toàn hơn NTLM trong nhiều kịch bản AD nhưng vẫn cần hardening.
  - PtH khác với “Pass‑the‑Ticket” (PtT); tuy nhiên thực tế attacker thường phối hợp nhiều kỹ thuật.
- **SMB (TCP/445)**:
  - dịch vụ chia sẻ file/IPC; PtH hay được dùng để truy cập share/ADMIN$ hoặc dịch vụ quản trị liên quan.
  - **SMB signing/encryption** là lớp bảo vệ quan trọng để giảm rủi ro các biến thể relay/tampering và tăng “assurance”.
- **RPC/DCOM, WMI, WinRM (PowerShell Remoting)**:
  - các kênh quản trị từ xa có thể sử dụng NTLM/Kerberos tùy cấu hình; nếu NTLM được phép và attacker có hash, rủi ro di chuyển ngang tăng.
- **LDAP/HTTP** (IWA – Integrated Windows Authentication):
  - nhiều dịch vụ ứng dụng hỗ trợ NTLM; nếu endpoint cho phép NTLM rộng rãi, PtH/AiTM/relay dễ hình thành “chuỗi tấn công”.

**(B) Lớp truy cập mạng (khi PtH xảy ra trong WLAN/LAN)**
- **IEEE 802.11 (Wi‑Fi)**: PtH không “phụ thuộc” 802.11, nhưng Wi‑Fi là bối cảnh phổ biến để attacker **vào được mạng nội bộ** (Initial Access), rồi mới thực hiện PtH.
- **WPA2/WPA3**:
  - bảo vệ liên kết radio (client ↔ AP), không trực tiếp ngăn PtH nếu attacker đã có foothold trong mạng.
- **EAP/802.1X (Enterprise)**:
  - giúp kiểm soát ai/thiết bị nào được vào VLAN nội bộ; giảm xác suất attacker “đứng trong cùng segment” để thực hiện lateral movement.

### 1.2 Cơ chế hoạt động của AP / Client / IoT device (tập trung vào bề mặt PtH)

**(A) AP/Switch (vai trò bề mặt “lateral movement enabler”)**
- PtH phát huy hiệu quả khi:
  - attacker có thể **kết nối tới mục tiêu** qua các port/quản trị (SMB/RPC/WMI/WinRM),
  - có **east‑west connectivity** trong VLAN.
- Các kiểm soát ở access layer (isolation/segmentation/ACL/NAC) có thể làm PtH “khó dùng” dù attacker có hash.

**(B) Windows client/server (nguồn hash & đích xác thực)**
- **Nguồn hash**: attacker cần thu được password hash từ một nơi nào đó (ví dụ:
  - bộ nhớ tiến trình xác thực (LSASS) / credential cache,
  - cơ sở dữ liệu local (SAM) hoặc domain (NTDS.dit) nếu đã có quyền cao,
  - backup/snapshot/EDR artifacts cấu hình sai).
- **Đích PtH**: máy/ dịch vụ chấp nhận NTLM và cho phép sử dụng hash như vật liệu xác thực.
- **Tác động**:
  - nếu hash là của **local admin** và bị reuse giữa nhiều máy → lateral movement nhanh.
  - nếu hash thuộc account có quyền cao (server admin, domain admin) → nguy cơ compromise diện rộng.

**(C) IoT / thiết bị “non‑Windows” nhưng liên quan**
- Nhiều NAS/printer/thiết bị “SMB‑capable” có thể:
  - chấp nhận NTLM/SMB từ Windows client,
  - cấu hình signing/encryption yếu,
  - trở thành pivot hoặc nơi lộ dữ liệu.
- IoT thường khó harden ở tầng identity → cần segmentation & deny‑by‑default.

### 1.3 Công cụ/phần mềm thường dùng (tấn công & phòng thủ) — ở mức khái quát
> Không hướng dẫn sử dụng; chỉ liệt kê để hiểu hệ sinh thái.

**Quan sát/điều tra & phòng thủ**
- **Windows Event Logs** + Advanced Auditing (logon events, NTLM events).
- **EDR** (Microsoft Defender for Endpoint, v.v.) để phát hiện credential dumping và bất thường đăng nhập.
- **Sysmon** (tùy chính sách) để bổ sung telemetry.
- **Wireshark/Zeek/Suricata**: quan sát NTLM/SMB patterns, bất thường đăng nhập từ xa, traffic east‑west.
- **SIEM** (Sentinel/Splunk/Elastic…): tương quan logon + network flow + endpoint alerts.

**Trong đánh giá an ninh được ủy quyền**
- Một số bộ công cụ thường được nhắc tới trong cộng đồng để mô phỏng PtH/PtT/relay (ví dụ công cụ credential dumping/NTLM relay frameworks).  
  *Lưu ý: chỉ nêu khái quát; không cung cấp thao tác.*

**Aircrack‑ng/Kismet**
- Không phải công cụ PtH trực tiếp; nhưng có thể xuất hiện trong chuỗi tấn công khi attacker dùng để **xâm nhập WLAN** trước khi thực hiện PtH.

---

## 2) Thuật toán (Algorithms)

### 2.1 Thuật toán mã hóa/xác thực bị khai thác (hoặc liên quan)
**(A) NT hash & NTLM family**
- **NT hash (NTLM hash)** thường được tính bằng **MD4** trên mật khẩu (Unicode) — mô tả khái niệm nền cho “có hash = có secret”.
- **NTLMv2** sử dụng cấu trúc **HMAC‑MD5** trong quá trình tạo response (khái quát).  
- Ý chính của PtH: attacker không cần phá crypto; họ **tái sử dụng** “vật liệu bí mật” đã bị lộ.

**(B) SMB signing/encryption (liên quan giảm rủi ro lateral/relay)**
- SMB signing dùng các cơ chế dựa trên session key (ví dụ AES‑based signing trong SMB2/3) để đảm bảo integrity.
- SMB encryption dùng AES modes (GCM/CCM tùy phiên bản) để bảo vệ confidentiality/integrity.

**(C) Wi‑Fi crypto (ngữ cảnh truy cập)**
- **WPA2:** AES‑CCMP (chuẩn), **TKIP** (legacy/không khuyến nghị).
- **WPA3:** **SAE** (Personal) + PMF mạnh hơn.
> Đây không phải “thuật toán PtH”, nhưng ảnh hưởng khả năng attacker tiếp cận mạng nội bộ (tức “điều kiện đầu vào” cho PtH).

### 2.2 Thuật toán tấn công (khái niệm)
- **Credential material acquisition**:
  - thu thập hash từ endpoint bị compromise, từ backup/config sai, hoặc từ hệ thống domain nếu đã có quyền.
- **Replay/Use Alternate Authentication Material**:
  - dùng hash như “chìa khóa” để xác thực NTLM tới dịch vụ đích (SMB/RPC/HTTP…).
- **Lateral movement graph**:
  - tìm mục tiêu nơi hash có quyền (admin share, remote management); mở rộng quyền theo đồ thị quan hệ.
- **Dictionary/brute‑force (bổ trợ, không phải PtH cốt lõi)**:
  - nếu attacker thu được vật liệu có thể brute‑force offline (tùy loại artifact) thì dùng để lấy plaintext; nhưng PtH bản chất là “không cần plaintext”.

### 2.3 Thuật toán phòng thủ (entropy-based, ML/DL anomaly detection, và hardening)
- **Entropy‑based detection** (thường dùng trong SIEM/NDR):
  - nguồn đăng nhập “hiếm” (rare source) tới nhiều máy,
  - bùng nổ logon Type 3 (network logon) từ 1 host,
  - tỷ lệ fail/success bất thường theo tài khoản/host,
  - “new admin path” (máy trước đây không bao giờ đăng nhập vào server A, nay xuất hiện).
- **ML/DL anomaly detection**:
  - time‑series cho hành vi đăng nhập (per user/per host),
  - graph anomaly (đường đi mới trong mạng quản trị),
  - kết hợp signal EDR (credential dumping) + network east‑west.
- **Hardening “logic”**:
  - giảm/loại bỏ NTLM, ưu tiên Kerberos,
  - bảo vệ LSASS/secret bằng VBS/Credential Guard,
  - giảm reuse local admin (Windows LAPS),
  - segmentation + block lateral management ports.

---

## 3) Dependencies

### 3.1 Phụ thuộc firmware/driver/hệ điều hành
- **Windows version/edition**: có/không hỗ trợ và mức trưởng thành của:
  - **Credential Guard / VBS**,
  - **NTLM auditing enhancements**,
  - SMB hardening defaults.
- **Driver/firmware** ảnh hưởng gián tiếp:
  - khả năng bật VBS, DMA protection,
  - tương thích với security baselines.

### 3.2 Phụ thuộc cấu hình người dùng/endpoint
- **NTLM được bật rộng rãi** (fallback nhiều).
- **Local admin password reuse** giữa máy.
- Cho phép **remote admin** (SMB/RPC/WMI/WinRM) từ user VLAN.
- Thiếu hardening endpoint:
  - không bật Credential Guard/LSA protection,
  - không có EDR/ASR rules hoặc cấu hình yếu.
- Nếu ở Wi‑Fi: **PSK yếu/WPS bật** làm attacker dễ vào mạng (tạo điều kiện cho PtH sau đó).

### 3.3 Phụ thuộc hạ tầng mạng (AP/router/IoT gateway)
- Thiếu segmentation (user ↔ server ↔ management).
- Thiếu NAC/802.1X cho VLAN nội bộ.
- SMB/remote management ports mở “rộng” east‑west.
- Nhiều thiết bị SMB/IoT legacy không hỗ trợ signing/encryption.

---

## 4) Context

### 4.1 Môi trường triển khai
- **Doanh nghiệp Active Directory** (phổ biến nhất).
- **Campus/corporate Wi‑Fi** (attacker vào mạng qua WLAN rồi pivot).
- **IoT/OT** có SMB shares/NAS/printer trong cùng VLAN user.
- **Hybrid/remote** (VPN split‑tunnel hoặc thiết kế mạng cho phép east‑west rộng).

### 4.2 Kịch bản tấn công (ví dụ)
- **Enterprise lateral movement**:
  - attacker có foothold trên 1 máy trạm → lấy hash → đăng nhập sang file server/ứng dụng nội bộ dùng NTLM.
- **Campus**:
  - máy trong user VLAN dò và đăng nhập sang nhiều máy do local admin reuse.
- **IoT**:
  - NAS/printer dùng SMB + NTLM, cấu hình yếu → bị dùng làm điểm pivot hoặc lộ dữ liệu.

---

## 5) Core Weakness (điểm yếu cốt lõi)

- **“Possession = authentication”** trong một số luồng NTLM: nếu attacker có NT hash, họ có thể dùng nó như vật liệu xác thực (không cần bẻ mật khẩu).
- **Credential caching + đặc quyền admin**:
  - hash xuất hiện trong bộ nhớ/hệ thống nếu có đăng nhập đặc quyền.
- **Legacy & compatibility**:
  - NTLM tồn tại vì tương thích; nhiều ứng dụng/thiết bị vẫn cần NTLM.
- **Human factor**:
  - reuse mật khẩu, chia sẻ tài khoản admin, vận hành thiếu phân tầng.

---

## 6) Cost & Risk

### 6.1 Chi phí triển khai tấn công
- **Trung bình**:
  - PtH thường cần bước trước đó để lấy hash (malware/privilege/backup leak).
  - Khi đã có hash + mạng cho phép lateral, chi phí mở rộng thường **thấp** (diễn ra nhanh).

### 6.2 Chi phí phòng thủ
- **Trung bình → cao**:
  - triển khai Credential Guard/VBS ở quy mô lớn,
  - migrate khỏi NTLM, kiểm thử ứng dụng legacy,
  - áp dụng Windows LAPS và phân tầng quản trị,
  - đầu tư SIEM/NDR/EDR và quy trình IR.

### 6.3 Rủi ro
- **Domain compromise** và ransomware (nếu attacker đạt được đặc quyền cao).
- **Rò rỉ dữ liệu** qua file server/SMB shares.
- **Gián đoạn dịch vụ** do attacker thao tác cấu hình hoặc triển khai phá hoại.
- **Tuân thủ/pháp lý**: ảnh hưởng dữ liệu nhạy cảm/PII, SLA.

---

## 7) Control Surface (các lớp kiểm soát)

### 7.1 Access Point / Access Layer
- **WPA2/WPA3‑Enterprise (802.1X/EAP‑TLS)** cho mạng nội bộ để giảm “kẻ lạ vào mạng”.
- **Guest Wi‑Fi**:
  - bật client isolation,
  - chặn truy cập tới VLAN server/management,
  - không route SMB/WinRM/RPC sang nội bộ.
- **Segmentation**:
  - user VLAN không được phép truy cập admin ports tới workstation/server trừ khi cần và có kiểm soát.

### 7.2 Client (Windows endpoints) & Server
- **Bảo vệ credential/LSASS**:
  - bật **Credential Guard** (VBS) theo baseline phù hợp,
  - bật LSA protection/anti‑credential dumping controls (theo hướng dẫn Microsoft/EDR).
- **Giảm NTLM**:
  - bật auditing, lập kế hoạch loại bỏ NTLM theo lộ trình,
  - ưu tiên Kerberos, cấu hình chặn NTLM nơi có thể (đặc biệt với SMB).
- **Giảm local admin reuse**:
  - triển khai **Windows LAPS** để mỗi máy có mật khẩu local admin khác nhau và rotate.
- **Nguyên tắc đặc quyền**:
  - tiered admin model, PAW (Privileged Access Workstation) cho admin,
  - hạn chế “admin đăng nhập vào workstation người dùng”.

### 7.3 Network Layer
- **Giảm khả năng lateral movement**:
  - hạn chế TCP/445 (SMB), WinRM, WMI/RPC theo zone,
  - áp dụng micro‑segmentation/host firewall.
- **SMB hardening**:
  - yêu cầu SMB signing, cân nhắc SMB encryption,
  - giám sát và giảm “insecure guest”.
- **Detection**:
  - tương quan event log (đăng nhập) + network flow (east‑west) + EDR alerts.

### 7.4 Policy Layer
- **Chính sách mật khẩu**: ưu tiên password dài, blocklist, không reuse (theo NIST 800‑63B).
- **PAM/PIM** (Privileged Access Management / Just‑in‑Time):
  - giảm thời gian tài khoản đặc quyền “luôn bật”.
- **Đào tạo & quy trình**:
  - hướng dẫn admin không đăng nhập domain admin vào máy thường,
  - playbook phản ứng khi nghi credential theft (rotate secrets, isolate host, hunt lateral).

---

## 8) Chain Value (chuỗi giá trị liên quan)

- **Nhà sản xuất phần cứng:** PC, NIC, TPM, AP/switch (ảnh hưởng VBS/secure boot và segmentation).
- **Nhà cung cấp phần mềm:** Windows/AD, SMB stack, EDR, SIEM/NDR, PAM solutions.
- **Doanh nghiệp triển khai:** IT ops, Identity team, SOC, Network team.
- **Người dùng cuối:** thói quen mật khẩu, tuân thủ chính sách thiết bị.
- **Kẻ tấn công:** tận dụng legacy auth + credential reuse + lateral connectivity.
- **Cơ quan/chuẩn/pháp luật:** RFC/IETF (Kerberos), NIST/CISA/MITRE (khung phòng thủ), quy định ATTT & bảo vệ dữ liệu.

---

## References (kèm “Source Preference” và URL)

### P1 — Chuẩn/tiêu chuẩn & tài liệu chính thức (Microsoft Learn/RFC/NIST)
- Microsoft Download — *Mitigating Pass-the-Hash (PtH) Attacks and Other Credential Theft, Version 2* (PDF):  
  https://www.microsoft.com/en-us/download/details.aspx?id=36036  
  (Direct PDF) https://download.microsoft.com/download/7/7/A/77ABC5BD-8320-41AF-863C-6ECFB10CB4B9/Mitigating-Pass-the-Hash-Attacks-and-Other-Credential-Theft-Version-2.pdf
- Microsoft Learn — NTLM overview:  
  https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview
- Microsoft Learn (Open Specifications) — [MS-NLMP] NTLM Protocol:  
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/c50a85f0-5940-42d8-9e82-ed206902e919
- Microsoft Learn — Credential Guard overview:  
  https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/
- Microsoft Learn — Configure Credential Guard:  
  https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure
- Microsoft Support — NTLM auditing enhancements (Windows 11 24H2 / Windows Server 2025):  
  https://support.microsoft.com/en-us/topic/overview-of-ntlm-auditing-enhancements-in-windows-11-version-24h2-and-windows-server-2025-b7ead732-6fc5-46a3-a943-27a4571d9e7b
- Microsoft Learn — SMB signing (overview):  
  https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview  
  (Policy/behavior) https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing
- Microsoft Learn — Block NTLM connections on SMB (Windows Server 2025 / Windows 11 24H2):  
  https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking
- Microsoft Learn — Windows LAPS overview:  
  https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview  
  (Architecture concepts) https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview
- NIST SP 800-63B — Digital Identity Guidelines (password/authenticator guidance):  
  https://pages.nist.gov/800-63-3/sp800-63b.html

### P2 — Khung tri thức/hướng dẫn (MITRE)
- MITRE ATT&CK — T1550.002 Pass the Hash:  
  https://attack.mitre.org/techniques/T1550/002/

### P4 — Vendor/triển khai tham khảo (bổ sung góc nhìn triển khai)
- Windows IT Pro Blog — Roadmap “Disabling NTLM by default” (cập nhật 2026):  
  https://techcommunity.microsoft.com/blog/windows-itpro-blog/advancing-windows-security-disabling-ntlm-by-default/4489526

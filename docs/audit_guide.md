# Hướng dẫn Audit WiFi - Sentinel NetLab

> Tài liệu hướng dẫn sử dụng checklist audit cho Home và SME

---

## Phần A — Hướng dẫn sử dụng Checklist

### Quy trình đánh giá

1. **Thu thập telemetry**: Beacon, Probe Request/Response, Authentication frames
2. **Kiểm tra cấu hình**: Truy cập admin UI của AP (tùy chọn)
3. **Ghi bằng chứng**:
   - Screenshot web UI
   - Radiotap/raw frame excerpt
   - PCAP snippet (5-30s)
   - Timestamps, RSSI values
4. **Gán severity** theo bản đồ rủi ro

### Severity → Numeric Score

| Severity | Score | Timeline |
|----------|-------|----------|
| Critical | 90 | Immediate |
| High | 70 | 24-72h |
| Medium | 40 | 1-4 weeks |
| Low | 10 | Optional |

---

## Phần B — Home Checklist (SOHO)

**Mục tiêu**: Đánh giá nhanh, hành động dễ thực hiện bởi chủ hộ.

### 1. Thông tin cơ bản
- [ ] Model thiết bị, firmware version
- [ ] Vị trí AP và vùng phủ sóng (RSSI snapshot)
- [ ] SSID list discovered

### 2. Authentication & Encryption
- [ ] Kiểm tra encryption: Open/WEP/WPA/WPA2/WPA3
  - **Critical**: WEP → thay thế ngay
  - **High**: WPA2-TKIP → chuyển sang CCMP
- [ ] WPS enabled → **Disable** (High)

### 3. SSID & Network Exposure
- [ ] SSID không chứa PII (tên, SĐT, địa chỉ)
- [ ] Hidden SSID (không phải biện pháp bảo mật thực sự)
- [ ] Guest SSID separation

### 4. Default Credentials
- [ ] Admin password đã đổi? (Critical)
- [ ] Remote management disabled? (High)

### 5. Firmware
- [ ] Firmware cập nhật mới nhất? (High nếu có CVE)

### 6. Channel & Power
- [ ] Channel overlap (2.4GHz: sử dụng 1/6/11)
- [ ] TX power leaks ngoài property

### 7. Segmentation
- [ ] IoT devices trên VLAN riêng?

---

## Phần C — SME Checklist

**Mục tiêu**: Enterprise có RADIUS, VLAN, compliance.

### A. Authentication & EAP
- [ ] WPA2/WPA3 Enterprise với 802.1X
- [ ] RADIUS certificate valid, không expired
- [ ] EAP method: prefer EAP-TLS > PEAP > TTLS

### B. Encryption
- [ ] Disable TKIP, chỉ dùng CCMP/AES

### C. Rogue AP Detection
- [ ] Duplicate SSID detected?
- [ ] Unknown BSSID trong zone?
- [ ] WIDS alerting enabled?

### D. Management Plane
- [ ] Management VLAN separation
- [ ] SSH key-based auth

### E. Logging & SIEM
- [ ] Central log forwarding (Elastic/Splunk)
- [ ] Alerting cho deauth flood, anomalies

### F. Segmentation
- [ ] VLANs: Guest, IoT, Corporate
- [ ] Inter-VLAN firewall rules

### G. Compliance
- [ ] PCI-DSS / HIPAA requirements met?

---

## Phần D — Commands tham khảo

```bash
# Scan SSIDs
iw dev wlan0 scan

# Capture management frames
tcpdump -i wlan0mon -s 256 -w sample.pcap type mgt

# Lower TX power
iw dev wlan0 set txpower fixed 1500  # 15 dBm
```

### hostapd WPA2 config
```ini
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=YourStrongPassphrase12+
```

### Disable WPS
```ini
# hostapd
wps_state=0
```

---

## Phần E — Evidence cần thu thập

- [ ] PCAP snippet (5-30s) với relevant frames
- [ ] Screenshot AP admin UI
- [ ] `iw dev` / `iwlist` output
- [ ] Sensor logs (`journalctl`)
- [ ] Photo vị trí AP (nếu cần)
- [ ] RADIUS cert chain (không credentials)

---

## Phần F — Report Template

Sử dụng lệnh sau để generate báo cáo HTML:

```bash
cd sensor
python audit.py --profile home --format html --output report.html --mock
```

### Cấu trúc báo cáo

1. **Executive Summary** (1 trang)
2. **Findings Table** (ID, Severity, Title, Evidence, Remediation, Status)
3. **Detailed Findings** (mỗi finding: evidence, timeline, commands)
4. **Action Plan** (prioritized tasks, owner, deadline)
5. **Appendix** (raw telemetry, pcaps, screenshots)

---

## Phần G — Chạy Audit

```bash
# Home profile với mock data
python audit.py --sensor-id test --profile home --mock

# SME profile với HTML output
python audit.py --sensor-id pi-01 --profile sme --format html --output audit.html

# Real scan
python audit.py --sensor-id pi-01 --iface wlan0mon --profile home
```

---

*Last Updated: January 28, 2026*

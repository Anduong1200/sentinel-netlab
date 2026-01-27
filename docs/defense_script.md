# Defense Script & Q&A Guide

> Comprehensive preparation for thesis defense / technical interview

---

## A. Tổng quan & Đóng góp

| # | Câu hỏi | Gợi ý trả lời |
|---|---------|---------------|
| 1 | Dự án này giải quyết vấn đề gì cụ thể? | Tự động hoá giám sát Wi-Fi (passive), phát hiện dị thường & cung cấp evidence cho forensic; không phải tấn công. |
| 2 | Đóng góp chính so với Wireshark/Kismet? | Tích hợp sensor→parser→risk scoring→GUI thành pipeline vận hành cho SME & lab. |
| 3 | Phạm vi nghiên cứu bao gồm/không bao gồm? | Bao: monitoring, metadata analysis, risk scoring. Không: payload decryption, active exploitation. |
| 4 | Vì sao chọn VM + USB passthrough? | VM cho driver/kernel tương thích tốt, tái hiện dễ; WSL2 có hạn chế driver. |
| 5 | Mục tiêu đánh giá đặt ra? | Recall ≥ 0.8 so với airodump-ng, latency chấp nhận được, stability 30′ stress test. |

---

## B. Thiết kế & Kiến trúc

| # | Câu hỏi | Gợi ý trả lời |
|---|---------|---------------|
| 6 | Tại sao tách Sensor và Controller? | Separation of concerns — dễ deploy multi-sensor, giảm quyền cho GUI, edge processing. |
| 7 | Giải thích luồng dữ liệu RF → GUI? | RF → USB → driver → pcap → capture engine → parser → risk scorer → API → GUI. |
| 8 | Xử lý duplicate/transient AP thế nào? | Dedupe theo BSSID + TTL window (first_seen/last_seen); threshold cho transient. |
| 9 | Tại sao JSON-over-HTTP thay vì MQTT/Kafka? | Simplicity cho PoC; message brokers là bước tiếp theo khi mở rộng multi-sensor. |
| 10 | Multi-tenant mở rộng thế nào? | Message-broker (MQTT/Kafka), central DB/Elasticsearch, mTLS và RBAC. |

---

## C. Capture Engine & Parser

| # | Câu hỏi | Gợi ý trả lời |
|---|---------|---------------|
| 11 | Tại sao dùng Scapy? Có hiệu năng không? | Scapy nhanh để prototype; môi trường nhiều gói nên chuyển sang tshark backend. |
| 12 | RSSI thu được có đáng tin không? | Tùy driver/adapter; nếu thiếu RSSI thì đánh dấu None, dùng heuristics khác. |
| 13 | Phát hiện encryption bằng gì? | Dò RSN IE / WPA vendor IE / capability flags; cần test với PCAP mẫu. |
| 14 | Phân biệt Evil-Twin vs legit AP? | So beacon timing, capabilities, chipset OUI, HT/VHT, security inconsistencies. |
| 15 | Parser có xử lý hidden SSID không? | Có; hidden SSID trả `<hidden>`; vendor IE parse tag 221, có cache OUI lookup. |

---

## D. Risk Scoring / Thuật toán

| # | Câu hỏi | Gợi ý trả lời |
|---|---------|---------------|
| 16 | Thuật toán risk scoring là gì? | Heuristic weighted scoring (encryption, RSSI, SSID pattern, vendor, channel). |
| 17 | Chứng minh trọng số hợp lý thế nào? | Expert-driven; cần dataset để calibrate hoặc train logistic regression. |
| 18 | Có thể gây false positives? Ví dụ? | Có — guest WPA2 với RSSI mạnh có thể được chấm cao; cần contextual rules. |
| 19 | Đánh giá performance scoring chưa? | "Cam kết chạy benchmark recall/precision vs ground-truth trong Evaluation". |
| 20 | Tại sao không dùng ML ngay? | Thiếu labeled dataset; heuristic cung cấp explainability; ML là bước mở rộng. |

---

## E. Hiệu năng & Benchmarking

| # | Câu hỏi | Gợi ý trả lời |
|---|---------|---------------|
| 21 | Benchmark trên phần cứng nào? | Nêu cấu hình test (CPU, RAM, adapter) hoặc sẽ thực hiện trên laptop/Pi. |
| 22 | Đo recall so với airodump-ng thế nào? | Chạy đồng thời, so sánh BSSID sets bằng `compare_recall.py`. |
| 23 | Packet loss bao nhiêu? Tối ưu thế nào? | BPF filters, dwell adaptive, tshark backend, batch parsing. |
| 24 | Dense environment có scale không? | PoC cần backend tối ưu + multi-sensor aggregation; hiện tại cần cải tiến. |
| 25 | Adapter disconnect thì recover thế nào? | check_driver.py detect, service restart, fallback mock-mode, alert admin. |

---

## F. Bảo mật & Vận hành

| # | Câu hỏi | Gợi ý trả lời |
|---|---------|---------------|
| 26 | API HTTP với API key có an toàn không? | Không đủ; cần TLS/nginx hoặc SSH tunnel; API key đặt env, không hardcode. |
| 27 | Tại sao không cấp capability cho Python? | Không cấp cho interpreter; dùng helper setuid hoặc sudoers cho lệnh hạn chế. |
| 28 | Logs & PCAP chứa PII — quản lý thế nào? | Encrypt at rest, retention policy, role-based access, sanitize before sharing. |
| 29 | Có cơ chế audit không? | Ghi audit logs, lưu event (user/action/timestamp), forward to SIEM. |
| 30 | Xét đến luật/consent khi sniffing chưa? | Luôn cần consent; trong báo cáo có mẫu consent form; mock-mode default. |

---

## G. So sánh với Giải pháp Thương mại

| # | Câu hỏi | Gợi ý trả lời |
|---|---------|---------------|
| 31 | Tại sao SME chọn tool này thay vì WIPS? | Cost-effective, open-source, customizable, no vendor lock-in. |
| 32 | Big enterprise có sử dụng không? | Không trực tiếp; cần HA, SLA, integration — dùng module như PoC internal. |
| 33 | Chi phí triển khai cho SME? | 1–3 sensors (~$30–150 each) + small VM; ops part-time. |
| 34 | ROI làm sao tính? | So cost vs expected avoided incident cost; provide sample scenario. |
| 35 | Điểm khác biệt nào đáng bán? | Transparency, ease of integration for pentest, custom heuristics. |

---

## H. Validation, Tests & Reproducibility

| # | Câu hỏi | Gợi ý trả lời |
|---|---------|---------------|
| 36 | Kịch bản test đã chạy? | Parser unit tests, integration E2E (VM+GUI), stress (30min scan). |
| 37 | Artifact nộp để chứng minh? | poc.json, gt_csv (airodump), recall_report, pcap samples, CPU logs. |
| 38 | Peer reviewer reproduce thế nào? | Clone repo, chạy setup_vm.sh, attach USB adapter or mock-mode, run demo_runbook.md. |
| 39 | Đã dùng CI chưa? | Có GitHub Actions chạy pytest + lint. |
| 40 | Đảm bảo kết quả không "may mắn"? | Lặp test nhiều lần, nhiều vị trí, report mean/std. |

---

## I. Ethics, Legality & Disclosure

| # | Câu hỏi | Gợi ý trả lời |
|---|---------|---------------|
| 41 | "Bạn khuyến khích tấn công mạng?" | Không; project phục vụ defense, research và training; active exploitation disabled default. |
| 42 | Demo thấy dữ liệu user, xử lý sao? | Dừng, sanitize/blur, follow retention & consent policy. |
| 43 | Risk bị misuse? Làm gì để giảm? | Document for ethical use, consent templates, disable active modules default. |
| 44 | Tham khảo policy/pháp lý địa phương chưa? | Tham khảo best practices; khuyến nghị user kiểm tra luật địa phương. |

---

## J. Future Work & Research

| # | Câu hỏi | Gợi ý trả lời |
|---|---------|---------------|
| 45 | 6 tháng nữa thêm tính năng gì? | Multi-sensor aggregation, SIEM/ELK integration, ML anomaly detection, mTLS, RBAC. |
| 46 | ML có thể giúp gì? Thu thập data thế nào? | Reducing FP, clustering rogue APs; thu thập labeled PCAPs + manual labels. |
| 47 | Nâng hệ thống production-ready thế nào? | Gunicorn+Nginx TLS, non-root service, monitoring, HA aggregator, Postgres/ES. |
| 48 | Thương mại hoá rào cản lớn nhất? | Support hardware variety, SLAs, compliance, support model. |

---

## K. Câu hỏi "Ác" Hay Dùng

| # | Câu hỏi | Gợi ý trả lời |
|---|---------|---------------|
| 49 | Ai đã test code ngoài bạn? | Nếu có nêu tên; nếu chưa, thừa nhận và trình kế hoạch peer review. |
| 50 | Nêu 3 hạn chế lớn nhất (thẳng thắn). | Hardware dependency/USB instability; heuristic not data-driven; not production-ready. |
| 51 | Chuyên gia RF chê, phản biện sao? | Thừa nhận giới hạn RF; nhấn mục tiêu operational monitoring, không thay thế chuyên ngành. |
| 52 | Demo live được không? Fail thì sao? | Có demo live + recorded demo as fallback — show checklist pre-demo. |
| 53 | Show worst-case FP example? | Pre-composed: WPA2 guest "Free_WiFi" chấm medium/high; explain thresholds & plan giảm FP. |

---

## L. Phản biện Học thuật (Academic Rigor)

| # | Câu hỏi | Gợi ý trả lời |
|---|---------|---------------|
| 54 | Đây là nghiên cứu hay engineering project? | Applied security engineering. Đóng góp là systematization of practice (SoP) + evaluation có kiểm soát, không phải thuật toán mới. |
| 55 | Có trích dẫn chuẩn công trình liên quan không? | Có cite Kismet, Aircrack-ng docs, và IEEE papers về WIDS. So sánh với Aruba/Cisco ở mức feature-level. |
| 56 | Tiêu chí đánh giá có statistical significance? | Chạy test nhiều lần (5+), report mean/std. Confidence interval là improvement tiếp theo. |
| 57 | Dataset có bias không? | Có; test ở lab ≠ campus ≠ mall. Acknowledge limitation này trong báo cáo. |

---

## M. Phản biện Scope Creep & Overclaim

| # | Câu hỏi | Gợi ý trả lời |
|---|---------|---------------|
| 58 | Tên đề tài có overclaim không? | Chỉ đánh giá exposure & misconfiguration, không phải full security posture. Không decrypt payload. |
| 59 | Đảm bảo user không hiểu nhầm là "phát hiện hacker"? | Document rõ scope; warning trong README; mock-mode default. |
| 60 | Dự án có đang làm quá nhiều thứ? | Acknowledge: Capture, Parse, Risk, GUI, Ops — focus chính là pipeline integration, không sâu từng module. |

---

## N. Phản biện So sánh Công cụ (Killer Questions)

| # | Câu hỏi | Gợi ý trả lời |
|---|---------|---------------|
| 61 | Tại sao không dùng Kismet + Grafana? | Kismet phức tạp cho SME; tool này đơn giản hoá deployment + add risk scoring layer. |
| 62 | Wireshark đã parse mọi thứ, tại sao parser riêng? | Wireshark là GUI tool; cần programmatic parsing cho automation + risk scoring pipeline. |
| 63 | Airodump-ng đã có, tại sao viết lại? | Airodump-ng là CLI output; tool này cung cấp REST API + persistent storage + GUI. |

---

## O. Phản biện Hiệu năng & Phần cứng

| # | Câu hỏi | Gợi ý trả lời |
|---|---------|---------------|
| 64 | USB adapter là bottleneck — xử lý sao? | USB 2.0 + single radio là limitation. Mitigation: adaptive dwell, tshark backend. |
| 65 | RSSI từ driver có đáng tin? | Không hoàn toàn; normalize và dùng relative comparison, không absolute values. |
| 66 | >100 AP environment có scale không? | PoC hiện tại struggle; cần batched parsing + pagination trong API. |
| 67 | Ai xác nhận kết quả "đúng"? | Benchmark với airodump-ng (ground truth); manual verification với Wireshark. |

---

## P. Phản biện Forensics

| # | Câu hỏi | Gợi ý trả lời |
|---|---------|---------------|
| 68 | PCAP có đủ giá trị pháp lý không? | Cần chain of custody, timestamp sync, hash integrity. Hiện chỉ ở mức evidence collection. |
| 69 | Có đảm bảo forensic soundness không? | Passive capture không thay đổi môi trường; active scan contaminate evidence — disabled default. |
| 70 | PCAP bị leak thì sao? | Encrypt at rest, retention policy, access control. Acknowledge risk trong docs. |

---

## Q. Phản biện Vận hành Doanh nghiệp

| # | Câu hỏi | Gợi ý trả lời |
|---|---------|---------------|
| 71 | Ai sẽ vận hành hệ thống? | Target SME IT staff; không cần SOC. Cần basic training. |
| 72 | Alert lên, ai xử lý? | Cần playbook; hiện chỉ là dashboard, chưa có workflow engine. |
| 73 | False positive nhiều thì sao? | Alert fatigue risk; mitigation: tunable thresholds, whitelist feature. |
| 74 | SME hiểu risk score không? | Cần documentation; training cost là limitation. |

---

## R. Phản biện Kinh tế & Đầu tư

| # | Câu hỏi | Gợi ý trả lời |
|---|---------|---------------|
| 75 | TCO 1 năm bao nhiêu? | HW ~$100, Ops ~2h/month, Training ~4h. Total estimate ~$500-1000/year. |
| 76 | ROI đo thế nào? | So với 1 incident cost (~$5k-50k for SME); prevention > response cost. |
| 77 | Có trùng với firewall + IDS không? | Không; firewall = wired, IDS = host-based; tool này = wireless layer visibility. |

---

## S. Phản biện Bảo mật Chính Dự án

| # | Câu hỏi | Gợi ý trả lời |
|---|---------|---------------|
| 78 | Attacker compromise sensor VM thì sao? | Pivot risk; mitigation: isolated network, least privilege, monitoring. |
| 79 | API key bị lộ? | Rate limit, IP whitelist, rotate keys. Acknowledge risk. |
| 80 | Có threat model cho hệ thống chưa? | Basic STRIDE analysis; full threat model là future work. |

---

## T. Phản biện Engineering Discipline

| # | Câu hỏi | Gợi ý trả lời |
|---|---------|---------------|
| 81 | Tại sao không có CI/CD? | Có GitHub Actions với pytest + lint. |
| 82 | Coding style nhất quán không? | PEP8 + flake8 trong CI; có log levels consistent. |
| 83 | Capture crash lúc demo thì sao? | Recorded video fallback + mock-mode option. |

---

## U. Phản biện Đạo đức & Trách nhiệm

| # | Câu hỏi | Gợi ý trả lời |
|---|---------|---------------|
| 84 | Tool bị dùng do thám cá nhân? | Consent requirement trong docs; mock-mode default; ethical use guidelines. |
| 85 | Rủi ro privacy (MAC tracking)? | Acknowledgement: MAC addresses là PII; cần anonymization cho production. |
| 86 | SV dùng scan hàng xóm thì sao? | Disclaimer trong README; legal warning; author không chịu trách nhiệm misuse. |

---

## V. Phản biện Future Work (Bẫy hứa suông)

| # | Câu hỏi | Gợi ý trả lời |
|---|---------|---------------|
| 87 | ML có thật sự khả thi? | Có nếu có labeled dataset; cần ~1000+ samples; label manual hoặc crowdsource. |
| 88 | Multi-sensor có giải quyết root problem? | Giúp coverage; root problem (accuracy) cần ML; multi-sensor là operational improvement. |
| 89 | Làm lại từ đầu, bỏ gì? | GUI complexity; focus pure API + CLI first. |

---

## W. Câu hỏi "Đánh thẳng Tư duy"

| # | Câu hỏi | Gợi ý trả lời |
|---|---------|---------------|
| 90 | Nếu cấm dùng USB adapter ngoài, đề tài còn sống? | Có; dùng PCAP replay mode để demonstrate parsing + risk scoring logic. |
| 91 | Yêu cầu hoàn toàn passive & không PCAP? | Có thể; API chỉ expose metadata, không lưu PCAP. Configurable via settings. |
| 92 | "Đây chỉ là lab exercise" — phản biện sao? | Lab exercise có evaluation rigor, comparison, và reproducibility = valid engineering research. |
| 93 | **Một câu: vì sao đề tài này xứng đáng thông qua?** | Giải quyết pain point thực (Wi-Fi visibility cho SME), có implementation working, có evaluation data, có documentation đầy đủ. |

---

## 📋 Pre-Defense Checklist

### Technical Setup
- [ ] Clone repo mới trên máy demo
- [ ] Run `setup_vm.sh` thành công
- [ ] USB adapter hoạt động (lsusb, iw dev)
- [ ] API server chạy (`/health` OK)
- [ ] GUI kết nối thành công

### Fallback & Evidence
- [ ] Recorded video demo sẵn sàng
- [ ] PCAP samples trong artifacts/
- [ ] Recall report generated
- [ ] Screenshots của GUI

### Documentation
- [ ] Consent form template ready
- [ ] Printed Q&A guide (this doc)
- [ ] Slides loaded

---

## 🔥 Top 10 Câu hỏi Quan trọng Nhất

1. **Đóng góp chính là gì?** → Pipeline integration + evaluation
2. **Tại sao không dùng Kismet?** → Simplicity + risk scoring layer
3. **Recall bao nhiêu?** → ≥80% vs airodump-ng
4. **3 hạn chế lớn nhất?** → USB dependency, heuristic not data-driven, not prod-ready
5. **RSSI có đáng tin?** → Không hoàn toàn, dùng relative comparison
6. **False positive thế nào?** → Có; cần tunable thresholds
7. **Ai test code ngoài bạn?** → CI/CD + self-review; peer review là improvement
8. **Future work khả thi?** → ML + multi-sensor
9. **Ethical use?** → Consent required, mock-mode default
10. **Xứng đáng thông qua?** → Working system + evaluation + documentation

---

*Good luck with your defense! 🛡️*


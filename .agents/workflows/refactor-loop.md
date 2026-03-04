---
description: Quy trình bảo trì và dọn dẹp tự động (The Refactor Loop)
---

# THE REFACTOR LOOP

Khi user ra lệnh "Chạy Loop" hoặc "Dọn dẹp tiếp đi", chạy đúng quy trình 5 bước khép kín:

## BƯỚC 1: KHÁM TỔNG QUÁT (AUDIT)
- Quét toàn bộ codebase hiện tại.
- Xuất ra file `AUDIT_REPORT_CURRENT.md` mới tinh.
- Focus: Dead code, Duplicate Logic, Bloated (phình to/phức tạp).

## BƯỚC 2: BẮT MẠCH KÊ ĐƠN (TRIAGE)
- Đọc báo cáo, LỌC RA ĐÚNG 5 FILE/MODULE NGHIÊM TRỌNG NHẤT.
- Ưu tiên: Low coupling trước để tránh sập app.
- Xuất Artifact (Kế hoạch hành động) liệt kê 5 cái tên và cách sửa, chờ user "Approve".

## BƯỚC 3: XUỐNG ĐAO (EXECUTE)
- Khi user Approve mới được đụng code.
- Sửa từng file một. Sửa xong → cập nhật các file import nó.
- Chỉ dọn dẹp/tối ưu, KHÔNG chế thêm tính năng mới.

## BƯỚC 4: ĐỒNG BỘ SỔ SÁCH (SYNC DOCS)
- Đọc lại file code vừa sửa và `README.md` (hoặc doc tương ứng).
- Sửa Docs khớp 100% với code thực tế.

## BƯỚC 5: BÁO CÁO VÀ LẶP LẠI
- Báo cáo ngắn gọn kết quả.
- Chờ user gõ "OK" → quay lại BƯỚC 1.

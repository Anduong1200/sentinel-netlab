# Bắt Đầu Nhanh: Sentinel NetLab (Dành Cho Lính Mới)

Chào bạn! Đây là hướng dẫn siêu dễ (chuẩn "giải thích cho trẻ lớp 5") để bạn cài đặt và chạy thử Sentinel NetLab — hệ thống "radar" quét tìm wifi bị giả mạo.

Hãy tưởng tượng Sentinel NetLab là một trạm gác. Nó sẽ liên tục "nghe" các sóng wifi xung quanh nhà bạn xem có ai đang giả mạo sóng wifi nhà bạn để lừa bạn nhập mật khẩu không.

## 1. Chuẩn Bị Đồ Nghề

Bạn chỉ cần 2 thứ:
1. **Máy tính** có cài sẵn **Python** (phiên bản 3.11 trở lên).
2. Tải toàn bộ thư mục code này về máy.

## 2. Lắp Ráp Trạm Gác (Cài đặt)

Mở màn hình đen đen (Terminal/Command Prompt) lên, đi vào thư mục vừa tải về và gõ lần lượt 3 dòng bùa chú này:

```bash
# Bùa 1: Tạo một bong bóng cách ly để cài đồ nghề an toàn, không ảnh hưởng tới máy tính của bạn
python -m venv venv

# Bùa 2: Bước vào trong bong bóng đó
# Dùng cho Windows:
venv\Scripts\activate
# Dùng cho Mac/Linux:
source venv/bin/activate

# Bùa 3: Cài đặt tất cả các thiết bị radar (mất khoảng 1-2 phút)
pip install ".[dev,sensor,controller,dashboard]"
```

## 3. Khởi Động Trạm Gác!

Sentinel NetLab có 2 phần chính. Bạn hãy mở **2 cửa sổ Terminal** riêng biệt (và nhớ gõ Bùa số 2 để vào lại bong bóng ở cửa sổ mới nhé).

### Ở Cửa Sổ 1: Mở Phòng Điều Hành (Controller)
Đây là nơi lưu trữ dữ liệu và có màn hình cho bạn xem.
```bash
python controller/api_server.py
```
*(Nếu nó hiện chữ chạy chạy và không báo lỗi màu đỏ nghĩa là phòng điều hành đã mở cửa).*

### Ở Cửa Sổ 2: Bật Cụm Radar (Sensor)
Bây giờ bật thiết bị dò sóng lên để bắt đầu quét wifi xung quanh:
```bash
python sensor/sensor_cli.py
```
*(Sensor này sẽ bắt đầu dò sóng. Dù bạn chưa mua thiết bị bắt wifi chuyên dụng, nó vẫn sẽ tự động tạo ra sóng giả "Mock Data" để bạn xem thử cách nó hoạt động!)*

## 4. Xem Thành Quả

Mở trình duyệt web của bạn lên (Chrome/Cốc Cốc) và vào địa chỉ này:
👉 **[http://localhost:8050](http://localhost:8050)**

Tèn ten! Bạn sẽ thấy một bảng điều khiển xịn sò hiển thị các mạng wifi xung quanh. Nếu có mạng wifi nào nguy hiểm (ví dụ: wifi không có mật khẩu, hoặc wifi giả mạo), radar sẽ báo động bằng màu đỏ!

---
*Chúc chú lính mới thao tác thành công!*

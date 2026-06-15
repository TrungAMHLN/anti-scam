# anti-scam-extension


**AntiScam** là tiện ích mở rộng giúp phát hiện các trang web lừa đảo (phishing) và cảnh báo người dùng khi truy cập. Dự án này được phát triển, cập nhật và nâng cấp sâu rộng dựa trên mã nguồn của **ChongLuaDao**, mang lại khả năng quét toàn diện hơn và tối ưu hóa trải nghiệm người dùng.

Mô hình học máy phân loại được chạy trực tiếp trên trình duyệt, kết hợp cùng cơ chế Heuristic nội bộ giúp phát hiện các hành vi lừa đảo tinh vi một cách tức thời.

Mã nguồn gốc được phát triển dựa trên dự án [Phishing Site Detector Plugin](https://github.com/picopalette/phishing-detection-plugin).

Mã nguồn của browser extension [ChongLuaDao](https://github.com/7zones/chongluadao-extension).

# Những gì bọn mình đã nâng cấp và phát triển thêm

Bọn mình đã tái cấu trúc, tối ưu hóa hiệu năng và mở rộng dự án gốc với các tính năng vượt trội:

## 1. Nâng cấp bộ quét chuyên sâu (Deep Scanner) cho Frontend

- **Phát hiện mã độc ẩn (Obfuscated Script)**: Phát hiện và xử lý các kịch bản JavaScript cố tình bị làm mờ, che giấu mã nguồn nhằm qua mặt bộ quét.
- **Phát hiện khung trang ẩn (iFrames)**: Nhận dạng các iFrame ẩn độc hại (kích thước ≤1px, opacity:0, display:none) dùng để tải ngầm nội dung lừa đảo.
- **Phát hiện Form Hijacking (Chiếm đoạt biểu mẫu)**: Phát hiện các form nhập mật khẩu/OTP gửi dữ liệu chéo sang các domain lạ không thuộc danh sách tin cậy.
- **Nhận diện giả mạo thương hiệu (Brand Impersonation)**: Áp dụng thuật toán Heuristic thông minh để phát hiện các tên miền cố tình bắt chước các thương hiệu lớn ở cả phần hostname và đường dẫn (pathname).
- **Tra cứu tuổi tên miền (Domain Age Lookup)**: Tích hợp gọi API RDAP bất đồng bộ từ background script để lấy thông tin tuổi của tên miền, tự động phạt điểm và cảnh báo đối với các tên miền có tuổi đời cực ngắn (< 30 ngày).
- **Cải tiến giao diện người dùng (Modern UX/UI)**:
  - Thiết kế theo phong cách Neon xanh hiện đại, tối giản, tăng chiều rộng cửa sổ giúp hiển thị rõ ràng hơn.
  - Badge thống kê đặc điểm an toàn có khả năng **mở rộng/thu gọn trực quan** để người dùng dễ dàng theo dõi chi tiết tất cả tiêu chí đánh giá.
  - Tối ưu hóa phông chữ, biểu tượng và hiệu ứng thu gọn "Xem chi tiết" mượt mà.

## 2. Hệ sinh thái Backend Mới

- **Xây dựng API Backend độc lập**: Tiếp nhận, phân tích báo cáo và đánh giá từ cộng đồng người dùng gửi lên.
- **Trang quản trị trực quan (Admin Dashboard)**: Giúp quản trị viên dễ dàng duyệt, phê duyệt báo cáo hoặc quản lý whitelist/blacklist một cách tự động.
- **Đồng bộ hóa thông minh**: Vẫn duy trì cơ chế kết nối với API ChongLuaDao để đồng bộ hóa danh sách đen/trắng thời gian thực, bảo đảm kế thừa tối đa dữ liệu an toàn từ cộng đồng.

---

# Hướng dẫn trải nghiệm phiên bản dành cho nhà phát triển

Bạn có thể cài đặt và sử dụng tiện ích trên Chrome (hoặc các trình duyệt nền tảng Chromium) theo các bước sau:

1. Truy cập địa chỉ `chrome://extensions/`
2. Bật **Developer mode (Chế độ nhà phát triển)** ở góc trên bên phải
3. Chọn **Load unpacked (Tải tiện ích chưa đóng gói)** và trỏ đến thư mục `frontend`
4. Nếu cần, hãy ghim (Pin) tiện ích lên thanh công cụ trình duyệt
5. Có thể sẽ xuất hiện một số lỗi do đây là phiên bản đang phát triển, bạn có thể bỏ qua
6. Bắt đầu sử dụng tiện ích

# Thiết lập môi trường phát triển cục bộ (Local Development)

Cài đặt các thư viện cần thiết:

```bash
npm i
```

Nếu chưa có thư mục `build` hoặc `build-firefox`, hãy tạo chúng:
```bash
mkdir build
mkdir build-firefox
```

## Build cho Chrome
```bash
npm run build
```

## Build cho Firefox
```bash
npm run build-firefox
```
Sau đó, vào thư mục `build-firefox` và xóa thuộc tính `incognito` trong tệp `manifest.json`.
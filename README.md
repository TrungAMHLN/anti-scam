# anti-scam-extension


**AntiScam** là tiện ích mở rộng giúp phát hiện các trang web lừa đảo (phishing) và cảnh báo người dùng khi truy cập. Dự án này được phát triển, cập nhật và nâng cấp sâu rộng dựa trên mã nguồn của **ChongLuaDao**, mang lại khả năng quét toàn diện hơn và tối ưu hóa trải nghiệm người dùng.

Mô hình học máy phân loại được chạy trực tiếp trên trình duyệt, kết hợp cùng cơ chế Heuristic nội bộ giúp phát hiện các hành vi lừa đảo tinh vi một cách tức thời.

Mã nguồn gốc được phát triển dựa trên dự án [Phishing Site Detector Plugin](https://github.com/picopalette/phishing-detection-plugin).

Mã nguồn của browser extension [ChongLuaDao](https://github.com/7zones/chongluadao-extension).

# Những chức năng của extension

AntiScam là browser extension quét URL, nội dung trang và một số hành vi runtime để ước lượng mức độ tin cậy của website. Extension không chỉ dựa vào một dấu hiệu đơn lẻ, mà kết hợp **Trust Context**, **Risk Score**, **Confidence** và các nhóm tín hiệu theo tầng mạnh/yếu để giảm false positive trên các website uy tín như GitHub, Google, Microsoft, Cloudflare, Wikipedia, StackOverflow...

## 1. Trust Engine & Scoring

- **Trust Context Layer**: phân loại website thành `HIGH_TRUST`, `MEDIUM_TRUST`, `LOW_TRUST` trước khi tính điểm.
- **Safe Override cho website uy tín**: whitelist, official domain, HTTPS hợp lệ và domain lâu năm sẽ bảo vệ điểm số khỏi các heuristic yếu.
- **Correlation Engine**: chỉ tăng rủi ro mạnh khi nhiều tín hiệu nguy hiểm xuất hiện cùng lúc, ví dụ domain mới + giả mạo thương hiệu + form mật khẩu/OTP + redirect bất thường.
- **Confidence System**: mỗi tín hiệu có độ tin cậy riêng, ví dụ iframe là tín hiệu yếu, brand impersonation hoặc malware reputation là tín hiệu mạnh.
- **Tiered Weights**:
  - **Tier A**: blacklist, malware/phishing confirmed, cộng đồng báo cáo nhiều lần.
  - **Tier B**: giả mạo thương hiệu, typosquatting, homograph, download file thực thi, form gửi dữ liệu sang domain lạ, keylogger, open redirect.
  - **Tier C**: iframe, CDN, analytics, external image/script, nhiều JavaScript, nhiều subdomain — chỉ là tín hiệu hỗ trợ, không tự kết luận nguy hiểm.

## 2. URL & Domain Scanner

- **Kiểm tra HTTPS**: phát hiện website không dùng HTTPS và phân biệt với trường hợp tên miền cố tình mượn chữ `https`.
- **IP Host Detection**: cảnh báo khi website dùng địa chỉ IP trực tiếp thay vì domain.
- **Long URL / ký tự @ / URL rút gọn**: phát hiện các dấu hiệu URL dễ bị lợi dụng để đánh lừa người dùng.
- **Suspicious TLD**: nhận diện một số đuôi tên miền hay bị lạm dụng, nhưng chỉ xem là tín hiệu yếu.
- **Domain Age Lookup**: tra cứu RDAP để phát hiện domain mới đăng ký, đặc biệt là domain dưới 7 hoặc 30 ngày.
- **Reputation Whitelist**: nhận diện domain chính thức/uy tín để giảm false positive.

## 3. Brand Impersonation Detection

- **Brand-in-domain**: phát hiện tên miền chứa thương hiệu nhưng không thuộc domain chính thức, ví dụ `github-login-security.xyz`.
- **Typosquatting**: dùng Levenshtein và Jaro-Winkler để phát hiện tên miền gần giống thương hiệu.
- **Homograph / Unicode / Punycode**: phát hiện ký tự đánh lừa thị giác như `g00gle`, `m0mo`, punycode `xn--...`.
- **Brand in content**: quét tiêu đề, heading, meta description, logo alt/src/class/id để phát hiện trang mượn thương hiệu nhưng domain không chính thức.
- **Thương hiệu Việt Nam được hỗ trợ**:
  - Ngân hàng: Vietcombank, BIDV, VietinBank, Agribank, MB, ACB, Techcombank, TPBank, VPBank, Sacombank.
  - Ví điện tử: MoMo, ZaloPay, VNPay.
  - Thương mại điện tử: Shopee, Tiki, Lazada.
  - Doanh nghiệp: FPT, Viettel, VinGroup, VinFast, Vinhomes.

## 4. External Resource & Embedded Content Analysis

- **Không còn dùng `hostname !== currentHostname` để kết luận nguồn lạ**.
- **Ecosystem mapping**: nhận diện domain liên quan cùng hệ sinh thái, ví dụ:
  - GitHub: `github.com`, `githubusercontent.com`, `githubassets.com`, `github.io`.
  - Google: `google.com`, `gstatic.com`, `googleusercontent.com`, `googleapis.com`, `youtube.com`.
  - Microsoft: `microsoft.com`, `office.com`, `microsoftonline.com`, `azureedge.net`.
  - Cloudflare: `cloudflare.com`, `cdnjs.cloudflare.com`, `challenges.cloudflare.com`.
  - OpenAI/ChatGPT: `openai.com`, `chatgpt.com`, `oaistatic.com`, `oaiusercontent.com`.
- **Script/link/image scanner**: đếm và phân loại tài nguyên an toàn, chưa xác minh, nguy hiểm.
- **iFrame risk score**: iframe chỉ nguy hiểm khi có dấu hiệu như ẩn bất thường, cross-origin lạ, chứa form/mật khẩu/mã làm rối.

## 5. Link Scanner

- **Quét toàn bộ link bằng `document.querySelectorAll('a[href]')`**.
- **Phân loại link**:
  - Internal: cùng domain.
  - Related: domain cùng hệ sinh thái.
  - Trusted: domain phổ biến/whitelist.
  - Unknown: chưa xác minh.
  - Blacklisted/Dangerous: nằm blacklist hoặc có tín hiệu nguy hiểm.
- **Không coi external link là nguy hiểm**: external link chỉ là tín hiệu yếu nếu không có bằng chứng khác.
- **Dangerous link checks**: kiểm tra blacklist, typosquat, homograph, brand spoof, dangerous download, open redirect và domain age cho link có tín hiệu mạnh.
- **Deceptive link detection**: phát hiện link hiển thị một domain nhưng `href` trỏ sang domain khác.

## 6. Form & Sensitive Information Detection

- **Sensitive form detection**: phát hiện form chứa password, OTP, PIN, CVV, số thẻ, tài khoản ngân hàng, CCCD/CMND, KYC/eKYC.
- **Context-aware scoring**: form mật khẩu trên GitHub/Google/Microsoft/ChatGPT không bị xem là phishing nếu domain chính thức/uy tín.
- **Form hijacking**: cảnh báo khi form nhạy cảm gửi dữ liệu sang domain lạ.
- **Hidden form detection**: phát hiện form nhạy cảm bị ẩn bằng CSS, kích thước 0 hoặc nhiều hidden input.
- **Form destination runtime**: theo dõi fetch/XHR/sendBeacon POST ra domain ngoài để phát hiện endpoint nhận dữ liệu thực tế.

## 7. JavaScript & Malware-like Behaviour Detection

- **Obfuscated Script**: phát hiện `eval`, `new Function`, `atob`, `fromCharCode`, payload base64 dài, entropy cao, hex/unicode encoding.
- **Keylogger signal**: phát hiện script theo dõi `keydown`/`keypress` và gửi dữ liệu đi.
- **Clipboard hijack**: phát hiện đọc/ghi clipboard bất thường.
- **Data exfiltration**: theo dõi fetch/XHR/sendBeacon gửi dữ liệu ra domain lạ.
- **WebSocket signal**: chỉ tăng nhẹ khi đã có rủi ro khác, tránh false positive trên app chat/trading.

## 8. Permission Abuse Detection

- **Runtime hooks trong page context**: theo dõi website gọi các API quyền nhạy cảm.
- **Các quyền/API được theo dõi**:
  - Notification.
  - Camera/Microphone (`getUserMedia`).
  - Geolocation.
  - Clipboard read/write.
  - Fullscreen.
  - MIDI.
  - Payment Request.
  - Sensors / Motion / Orientation.
  - `navigator.permissions.query(...)`.
- **Context-aware scoring**: trên website chính chủ/uy tín, permission query hợp lệ không tự làm tụt điểm mạnh.

## 9. Redirect Chain Analysis

- **Theo dõi redirect main-frame** bằng `chrome.webRequest`.
- **Lưu chuỗi chuyển hướng** dạng A → B → C → D.
- **Đếm số hop và số domain khác nhau**.
- **Open redirect detection**: phát hiện tham số như `url`, `redirect`, `redirect_url`, `next`, `target`, `to`, `destination`, `continue`, `return`, `callback`, `goto`, `r` trỏ sang domain ngoài.
- **Scoring theo mức độ**:
  - 0–1 hop: bình thường.
  - 2–3 hop: nghi ngờ nhẹ.
  - 4+ hop hoặc nhiều domain: nghi ngờ cao.

## 10. Dangerous Download Detection

- **Phát hiện file thực thi/nguy hiểm**:
  - `.exe`, `.msi`, `.scr`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.apk`, `.jar`, `.dll`.
- **Archive detection**:
  - `.zip`, `.rar`, `.7z` được xem là tín hiệu nhẹ hơn, không ngang với file thực thi.
- **Double extension detection**:
  - `invoice.pdf.exe`, `image.jpg.scr`, `document.docx.exe`.
- **MIME analysis**: kiểm tra MIME của download item khi trình duyệt tạo download.
- **Download guard**: nếu file nguy hiểm đến từ ngữ cảnh rủi ro, extension có thể pause download và hỏi người dùng tiếp tục hay hủy.

## 11. Community, Blacklist & Backend Intel

- **Blacklist/Whitelist từ ChongLuaDao API**.
- **OpenPhish public feed**.
- **Backend intelligence endpoint**: tra cứu domain age, malware reputation, DNS/hosting risk, community reports.
- **Threat intelligence backend** có hỗ trợ VirusTotal, URLhaus, ThreatFox, AbuseIPDB nếu cấu hình API key.
- **Community report**: người dùng có thể gửi báo cáo website đáng ngờ.

## 12. Hiển thị tín hiệu trong popup

- **Tín hiệu tích cực**: domain uy tín, HTTPS, domain lâu năm, tài nguyên tin cậy, không phát hiện form đánh cắp.
- **Tín hiệu cảnh báo**: domain mới, link chưa xác minh, permission nhạy cảm trong ngữ cảnh chưa rõ, redirect nhẹ.
- **Tín hiệu nguy hiểm**: blacklist, malware reputation, giả mạo thương hiệu mạnh, keylogger, data exfiltration, dangerous download, form hijacking.
- **Chuẩn hóa thống kê đối tượng**: các nhóm như links/images/scripts/iframes/forms được tách thành chip riêng, ví dụ `Liên kết an toàn ×118`, `Liên kết chưa xác minh ×5`, `Liên kết nguy hiểm ×0`, thay vì gộp khó hiểu.
- **Độ tin cậy**: hiển thị confidence của quá trình phân tích, không phải điểm an toàn.

## 13. Trang cảnh báo nguy hiểm

- **Blocking page có sẵn**: `blocking.html` được dùng khi URL nằm blacklist hoặc khi engine phát hiện rủi ro vượt ngưỡng.
- **Cho phép tiếp tục có kiểm soát**: người dùng có thể chọn vẫn truy cập, extension tạm bỏ qua trong thời gian ngắn để tránh redirect lặp.

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
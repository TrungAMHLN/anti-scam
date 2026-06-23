# AUDIT REPORT — Custom URL Scan — AntiScam Extension
# Kết quả đầu ra theo format yêu cầu

---

## 1. KIẾN TRÚC HIỆN TẠI (trước khi sửa)

Hai pipeline riêng biệt, không đồng bộ:

**Pipeline A — Current Tab Scan:**
```
Tab mở → features.js chạy → ANALYSIS_RESULT → classify()
→ setTabState(tabId) → chrome.storage.session[`tab_${tabId}`]
→ popup.js poll GET_TAB_STATE → renderState()
```

**Pipeline B — Custom URL Scan:**
```
Popup SCAN_URL → background tạo tab ẩn → features.js chạy
→ ANALYSIS_RESULT → classify() → setTabState(scanTabId)
→ background poll → copy sang setUrlScanResult() → chrome.storage.local
→ popup.js poll GET_URL_SCAN_STATE → renderState()
```

**Vấn đề:** UI chỉ có 1 vùng hiển thị, nhưng 2 pipeline viết vào 2 storage khác nhau, và popup poll từ 2 nguồn khác nhau. Không có cơ chế chuyển đổi source.

---

## 2. LUỒNG SCAN THỰC TẾ (truy vết từng bước)

### Bước 1: Popup → startCustomUrlScan()
- **File:** `popup.js`, dòng ~440
- **Chạy:** ✓
- **Hành động:** Đặt `isViewingCustomUrl = true`, gửi `SCAN_URL`

### Bước 2: background.js nhận SCAN_URL
- **File:** `background.js`, dòng ~808
- **Chạy:** ✓
- **Hành động:** `setUrlScanResult()` → `chrome.tabs.create({active:false})` → `addScanPreview()`

### Bước 3: features.js chạy trên tab ẩn
- **File:** `features.js`, hàm `collect()`
- **Chạy:** ✓ (content script tự inject)
- **Dữ liệu:** ~20 ML features + DOM signals

### Bước 4: ANALYSIS_RESULT → classify()
- **File:** `background.js`, dòng ~735
- **Chạy:** ✓
- **Dữ liệu:** `request.result` + `request.dom`

### Bước 5: classify() hoàn tất → setTabState()
- **File:** `background.js`, hàm `classify()`
- **Chạy:** ✓
- **Lưu:** `chrome.storage.session[`tab_${tabId}`]`

### Bước 6: background poll phát hiện → copy sang local
- **File:** `background.js`, hàm `pollForResult()`
- **Chạy:** ✓
- **Lưu:** `chrome.storage.local['antiscam_url_scan_results']`

### Bước 7: popup poll → renderState()
- **File:** `popup.js`, hàm `pollScanResult()`
- **Chạy:** ✓
- **Render:** `renderState(state, domain)` — cập nhật toàn bộ UI

---

## 3. VÌ SAO UI VẪN HIỂN THỊ DỮ LIỆU CỦA TAB CŨ

### NGUYÊN NHÂN GỐC RỞ — BUG #1 (CRITICAL)

**Khi `startCustomUrlScan()` được gọi, UI CHÍNH KHÔNG CHUYỂN TRẠNG THÁI.**

Code cũ (popup.js):
```javascript
const startCustomUrlScan = (rawUrl) => {
  setCustomScanStatus('Đang quét...', 'loading');  // ← CHỈ hiện text nhỏ
  isViewingCustomUrl = true;                        // ← Chặn poll A
  
  chrome.runtime.sendMessage({ type: 'SCAN_URL', url }, (resp) => {
    // ... pollScanResult() chỉ gọi renderState() khi scan HOÀN TẤT
    // TRONG LÚC ĐANG SCAN: UI VẪN HIỆN DỮ LIỆU CŨ
  });
};
```

**Hệ quả:** Giữa lúc bắt đầu scan và lúc scan hoàn tất (5-60 giây):
- `#domain_url` → vẫn hiện "facebook.com"
- `#site_score` → vẫn hiện điểm của facebook.com
- `#site_msg` → vẫn hiện verdict của facebook.com
- `#features` → vẫn hiện signals của facebook.com
- Chỉ `customUrlScanStatus` hiện "Đang quét..."

---

## 4. VÌ SAO TAB THẬT BỊ MỞ

**File:** `background.js`, dòng ~816
**Code:** `chrome.tabs.create({ url: urlString, active: false })`

**Lý do PHẢI mở tab:** Content script `features.js` cần chạy trong context của trang web thực tế để thu thập:
- Forms, inputs, iframes → phân tích form hijacking
- Scripts → phát hiện obfuscation, keylogger
- Links → phân tích anchor ratio, deceptive links
- Brand surfaces → phát hiện giả mạo thương hiệu
- Network hooks → monitor fetch/XHR/sendBeacon

**Ưu điểm:** Kết quả chính xác như scan tab thật
**Nhược điểm:** Tab thật mở (dù ẩn), bị Cloudflare block, tốn tài nguyên

---

## 5. DANH SÁCH BUG PHÁT HIỆN

| # | Mức | Bug | File | Function |
|---|-----|-----|------|----------|
| 1 | CRITICAL | UI chính không chuyển trạng thái khi bắt đầu custom scan | popup.js | startCustomUrlScan() |
| 2 | CRITICAL | domain_url không cập nhật khi bắt đầu custom scan | popup.js | startCustomUrlScan() |
| 3 | MAJOR | Không hiển thị trạng thái loading chi tiết | popup.js | pollScanResult() |
| 4 | MAJOR | savedMainState chỉ lưu HTML snapshot | popup.js | backToCurrentTab handler |
| 5 | MAJOR | `isViewingCustomUrl` chỉ là boolean, không có state machine | popup.js | global |
| 6 | MODERATE | Background poll và popup poll tách rời, race condition | background.js + popup.js | pollForResult + pollScanResult |
| 7 | MINOR | Không có structured logging | background.js | toàn bộ scan flow |

---

## 6. NGUYÊN NHÂN GỐC RỞ

**Thiết kế có 2 pipeline riêng biệt (A và B) nhưng UI chỉ có 1 vùng hiển thị.** Không có unified state machine để quản lý việc chuyển source. Khi chuyển từ A sang B, UI không được reset/đổi trạng thái → người dùng vẫn thấy dữ liệu cũ trong suốt thời gian scan B.

---

## 7. FILE BỊ LỖI

1. `scripts/ui/popup.js` — toàn bộ state management và rendering
2. `scripts/background/background.js` — thiếu structured logging

---

## 8. FUNCTION BỊ LỖI

1. `startCustomUrlScan()` — không reset UI khi bắt đầu scan mới
2. `renderState()` — không có trạng thái loading
3. `pollScanResult()` — không cập nhật UI trong lúc đang scan
4. Back button handler — khôi phục bằng DOM snapshot thay vì state

---

## 9-10. CODE THAY THẾ HOÀN CHỈNH

Đã ghi đè trực tiếp vào:
- `scripts/ui/popup.js` — Refactor hoàn toàn state management
- `scripts/background/background.js` — Thêm structured logging

### Thay đổi chính trong popup.js:

1. **Thêm `activeScan` state object** — Single source of truth:
```javascript
const activeScan = {
  source: null,            // ScanSource.CURRENT_TAB | CUSTOM_URL
  targetUrl: null,
  targetDomain: null,
  status: null,            // ScanStatus.PENDING/LOADING/.../COMPLETED
  tabId: null,
  scanUrl: null,
  // ...
};
```

2. **Thêm `renderLoadingState()`** — Hiển thị trạng thái loading cho URL mới:
```javascript
const renderLoadingState = (domain, statusText) => {
  // Reset toàn bộ UI → loading
  $('#site_score').text('...');
  $('#site_msg').text(statusText);
  $('#domain_url').text(domain);       // ← NGAY LẬP TỨC cập nhật domain
  featureList.innerHTML = '<li class="feature-empty">Đang thu thập dữ liệu...</li>';
};
```

3. **Trong `startCustomUrlScan()`** — GỌI renderLoadingState() NGAY LẬP TỨC:
```javascript
// BƯỚC 3: NGAY LẬP TỨC chuyển UI sang loading cho URL mới
renderLoadingState(domain, 'Đang gửi yêu cầu quét...');
showBackButton(true);
```

4. **Poll A kiểm tra `activeScan.source`** thay vì `isViewingCustomUrl`:
```javascript
const poll = () => {
  if (activeScan.source !== ScanSource.CURRENT_TAB) return;
  // ...
};
```

5. **Poll B cập nhật UI loading theo giai đoạn**:
```javascript
if (scanAttempts < 3) renderLoadingState(domain, 'Đang tải trang...');
else if (scanAttempts < 8) renderLoadingState(domain, 'Đang thu thập dữ liệu...');
else renderLoadingState(domain, 'Đang phân tích...');
```

6. **Back button khôi phục + poll lại**:
```javascript
// Khôi phục snapshot → rồi poll lại GET_TAB_STATE để lấy data mới nhất
setTimeout(() => {
  chrome.runtime.sendMessage({ type: 'GET_TAB_STATE', tabId }, (state) => {
    if (state) renderState(state, domain);
  });
}, 500);
```

### Thay đổi chính trong background.js:

1. **Structured logging** cho toàn bộ scan lifecycle:
```
[SCAN_JOB_CREATED] url=...
[SCAN_URL] url=...
[TAB_CREATED] tabId=... url=...
[FEATURES_COLLECTED] tabId=...
[CLASSIFYING] tabId=... poll=...
[RESULT_SAVED] url=... score=...
[COMPLETED] url=... score=...
[FAILED] url=...
[TIMEOUT] url=...
[SCAN_BLOCKED] tabId=...
```

---

## 11. KIẾN TRÚC MỚI ĐỀ XUẤT

```
┌─────────────────────────────────────────────────┐
│                   POPUP                          │
│                                                  │
│  ┌────────────────────────────────────────────┐  │
│  │           activeScan (STATE)                │  │
│  │  source: CURRENT_TAB | CUSTOM_URL           │  │
│  │  targetUrl, targetDomain, status, score... │  │
│  └──────────────┬─────────────────────────────┘  │
│                 │                                 │
│     ┌───────────┴───────────┐                    │
│     │                       │                    │
│  Pipeline A            Pipeline B                │
│  GET_TAB_STATE         GET_URL_SCAN_STATE        │
│     │                       │                    │
│     └───────────┬───────────┘                    │
│                 │                                 │
│          renderState()                            │
│          renderLoadingState()                     │
│                                                  │
│  Nguồn duy nhất → activeScan.source              │
│  UI đọc từ → đúng pipeline theo source           │
└─────────────────────────────────────────────────┘
```

**Key principle:** Mỗi lúc chỉ có 1 source active. Khi chuyển source → UI NGAY LẬP TỨC chuyển sang loading state cho URL mới.

---

## 12. CHECKLIST TEST SAU KHI SỬA

### Test 1: Custom URL Scan — UI chuyển trạng thái
- [ ] Mở tab facebook.com
- [ ] Nhập phishing-site.com → bấm Scan
- [ ] NGAY LẬP TỨC: `#domain_url` hiện "phishing-site.com"
- [ ] NGAY LẬP TỨC: `#site_score` hiện "..."
- [ ] NGAY LẬP TỨC: `#site_msg` hiện "Đang gửi yêu cầu quét..."
- [ ] SAU 2-3s: `#site_msg` chuyển thành "Đang tải trang..."
- [ ] SAU 5-8s: `#site_msg` chuyển thành "Đang thu thập dữ liệu..."
- [ ] SAU 10s+: `#site_msg` chuyển thành "Đang phân tích..."
- [ ] KHI XONG: `#site_score` hiện điểm của phishing-site.com
- [ ] KHI XONG: Features/Signals hiện của phishing-site.com
- [ ] Back button hiện → bấm → UI quay về facebook.com

### Test 2: Current Tab Scan — không bị ảnh hưởng
- [ ] Mở tab an toàn (VD: google.com)
- [ ] Score hiện đúng
- [ ] Không có text "Đang quét..."
- [ ] Bấm Scan URL khác → UI chuyển → bấm Back → UI quay về google.com

### Test 3: Scan URL bị Cloudflare block
- [ ] Nhập URL có Cloudflare challenge
- [ ] UI hiện "Đang tải trang..." → "Trang web có bảo vệ chống bot..."

### Test 4: Scan URL không hợp lệ
- [ ] Nhập "abc" → hiện "URL không hợp lệ."

### Test 5: History
- [ ] Scan 1 URL → history thêm 1 item
- [ ] Scan URL khác → history thêm item, max 5
- [ ] Click history item → scan lại URL đó
- [ ] Click trash icon → xoá item

### Test 6: Logging
- [ ] Mở DevTools → Console của Service Worker
- [ ] Scan URL → thấy [SCAN_JOB_CREATED], [SCAN_URL], [TAB_CREATED], [COMPLETED]

### Test 7: Back button + re-scan
- [ ] Scan URL A → xong → bấm Back → hiện tab cũ
- [ ] Scan URL B → UI chuyển hoàn toàn → xong → bấm Back → hiện tab cũ

### Test 8: Nhập URL trong lúc đang scan
- [ ] Đang scan URL A → nhập URL B → bấm Scan
- [ ] UI chuyển sang URL B ngay lập tức
- [ ] Poll cũ bị clearInterval

### Test 9: Đóng popup giữa chừng scan
- [ ] Bắt đầu scan → đóng popup → mở lại
- [ ] Popup hiển thị trạng thái current tab (không bị kẹt ở custom scan)

### Test 10: SW restart giữa chừng scan
- [ ] Bắt đầu scan → kill SW → SW restart
- [ ] Recovery mechanism dọn dẹp orphaned tab
- [ ] Scan result = FAILED (không bị treo mãi)

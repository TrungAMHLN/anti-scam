/*global chrome*/
/*global $*/

// ─────────────────────────────────────────────────────────────────────────────
//  Màu sắc cho các yếu tố phân tích (giữ nguyên)
// ─────────────────────────────────────────────────────────────────────────────
const colors = {
  '-1': '#28a745',  // An toàn — xanh dương
  '0':  '#ffeb3c',  // Nghi ngờ — vàng
  '1':  '#cc0000',  // Nguy hiểm — đỏ
};

// ─────────────────────────────────────────────────────────────────────────────
//  Cấu hình polling
// ─────────────────────────────────────────────────────────────────────────────
const POLL_INTERVAL_MS  = 800;   // Kiểm tra mỗi 800ms
const POLL_MAX_ATTEMPTS = 19;    // Tối đa ~15 giây

// ─────────────────────────────────────────────────────────────────────────────
//  Collapsible "Xem chi tiết" (giữ nguyên logic gốc)
// ─────────────────────────────────────────────────────────────────────────────
[...document.getElementsByClassName('collapsible')].forEach((el) => {
  el.addEventListener('click', function () {
    this.classList.toggle('active');
    const content = this.nextElementSibling;
    if (content.style.maxHeight) {
      content.style.maxHeight = null;
    } else {
      content.style.maxHeight = `${content.scrollHeight}px`;
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
//  Bảng dịch thuật ngữ kỹ thuật → tiếng Việt dễ hiểu
// ─────────────────────────────────────────────────────────────────────────────
const featureTranslations = {
  'IP Address':                  'Địa chỉ IP',
  'URL Length':                  'Độ dài đường dẫn',
  'Tiny URL':                    'URL rút gọn',
  '@ Symbol':                    'Chứa ký tự @',
  'Redirecting using //':        'Chuyển hướng ẩn (//)',
  '(-) Prefix/Suffix in domain': 'Có dấu (-) trong tên miền',
  'No. of Sub Domains':          'Nhiều tên miền phụ',
  'HTTPS':                       'Bảo mật HTTPS',
  'Favicon':                     'Biểu tượng trang (Favicon)',
  'Port':                        'Cổng mạng (Port)',
  "HTTPS in URL's domain part":  'HTTPS giả mạo',
  'Request URL':                 'Tài nguyên từ trang khác',
  'Anchor':                      'Liên kết ngoài',
  'Script & Link':               'Mã nhúng từ trang khác',
  'SFH':                         'Xử lý dữ liệu (Form) ẩn',
  'mailto':                      'Gửi dữ liệu qua email',
  'iFrames':                     'Khung trang ẩn (iFrame)',
  'Sensitive Form':              'Yêu cầu nhập Mật khẩu/OTP',
  'Form Hijacking':              'Chiếm đoạt dữ liệu Form (Cross-Domain)',
  'Obfuscated Script':           'Mã độc ẩn (Obfuscated)',
  'Domain Age':                  'Tuổi đời tên miền ngắn',
};

// ─────────────────────────────────────────────────────────────────────────────
//  Render kết quả phân tích vào UI (không thay đổi cấu trúc HTML/CSS)
// ─────────────────────────────────────────────────────────────────────────────
const renderState = (state, domain) => {
  const { isWhiteList, isBlocked, isPhish, legitimatePercent, result, status } = state;

  // Trường hợp 1: URL nằm trong whitelist — an toàn tuyệt đối
  if (isWhiteList) {
    $('#pluginBody').hide();
    $('#isSafe').show();
    $('#isSafe .site-url').text(domain);
    return;
  }

  // Trường hợp 2: URL đã bị chặn — trang nguy hiểm
  if (isBlocked) {
    $('#pluginBody').hide();
    $('#isPhishing').show();
    $('#isPhishing .site-url').text(isBlocked);
    return;
  }

  // Trường hợp 3: Kết quả phân tích ML
  const featureList = document.getElementById('features');
  featureList.innerHTML = ''; // Xóa items cũ trước khi render

  if (result && typeof result === 'object') {
    const safeItems = [];
    const warnItems = [];

    for (const key in result) {
      if (key === 'tab') continue;
      const val = result[key];
      if (val === '-1') {
        safeItems.push(featureTranslations[key] || key);
      } else {
        // Hển thị badge đỏ/vàng (nguy hiểm / ngũ ngờ)
        const li = document.createElement('li');
        li.textContent = featureTranslations[key] || key;
        li.style.backgroundColor = colors[val];
        if (val === '0') li.style.color = '#000';
        warnItems.push(li);
      }
    }

    // Hiển thị các badge cảnh báo trước
    warnItems.forEach(li => featureList.appendChild(li));

    // Nếu có tính năng an toàn, hiển thị dưới dạng badge tổng hợp có thể bấm để xem/thu gọn
    if (safeItems.length > 0) {
      const safeLi = document.createElement('li');
      safeLi.textContent = `✓ ${safeItems.length} đặc điểm an toàn (Xem)`;
      safeLi.style.backgroundColor = '#1a3a2a';
      safeLi.style.color = '#00ff66';
      safeLi.style.border = '1px solid #00ff6644';
      safeLi.style.fontSize = '1.1rem';
      safeLi.style.opacity = '0.85';
      safeLi.style.cursor = 'pointer';
      safeLi.style.textAlign = 'center';
      safeLi.style.transition = 'all 0.2s ease';
      
      safeLi.addEventListener('mouseenter', () => {
        safeLi.style.opacity = '1';
        safeLi.style.backgroundColor = '#1e4630';
      });
      safeLi.addEventListener('mouseleave', () => {
        safeLi.style.opacity = '0.85';
        safeLi.style.backgroundColor = '#1a3a2a';
      });

      let expanded = false;
      const renderedElements = [];

      const toggleExpand = () => {
        const parentContent = safeLi.closest('.feature-content');
        if (!expanded) {
          // Expand
          safeLi.textContent = `✓ ${safeItems.length} đặc điểm an toàn`;
          
          safeItems.forEach(text => {
            const itemLi = document.createElement('li');
            itemLi.textContent = text;
            itemLi.style.backgroundColor = '#28a745';
            itemLi.style.color = '#fff';
            itemLi.style.opacity = '0.85';
            itemLi.style.fontSize = '1.0rem';
            itemLi.style.border = '1px solid #28a74544';
            featureList.appendChild(itemLi);
            renderedElements.push(itemLi);
          });
          
          // Append the collapse button
          const collapseLi = document.createElement('li');
          collapseLi.textContent = `Thu gọn`;
          collapseLi.style.backgroundColor = '#374151';
          collapseLi.style.color = '#e5e7eb';
          collapseLi.style.border = '1px solid #4b5563';
          collapseLi.style.fontSize = '1.1rem';
          collapseLi.style.cursor = 'pointer';
          collapseLi.style.textAlign = 'center';
          collapseLi.style.opacity = '0.85';
          
          collapseLi.addEventListener('mouseenter', () => {
            collapseLi.style.opacity = '1';
            collapseLi.style.backgroundColor = '#4b5563';
          });
          collapseLi.addEventListener('mouseleave', () => {
            collapseLi.style.opacity = '0.85';
            collapseLi.style.backgroundColor = '#374151';
          });
          
          collapseLi.addEventListener('click', (e) => {
            e.stopPropagation();
            toggleExpand();
          });
          
          featureList.appendChild(collapseLi);
          renderedElements.push(collapseLi);
          
          expanded = true;
        } else {
          // Collapse
          renderedElements.forEach(el => {
            if (el.parentNode) {
              el.parentNode.removeChild(el);
            }
          });
          renderedElements.length = 0;
          safeLi.textContent = `✓ ${safeItems.length} đặc điểm an toàn (Xem)`;
          expanded = false;
        }

        // Cập nhật lại chiều cao của panel cha để không bị khuất
        if (parentContent && parentContent.style.maxHeight) {
          parentContent.style.maxHeight = `${parentContent.scrollHeight}px`;
        }
      };

      safeLi.addEventListener('click', toggleExpand);
      featureList.appendChild(safeLi);
    }
  }

  const pct = parseInt(legitimatePercent);
  const isValidPct = !isNaN(pct) && isFinite(pct);

  const site_score     = document.getElementById('site_score');
  const pct_content    = document.getElementById('percentage_content');
  const site_msg       = document.getElementById('site_msg');

  pct_content.classList.add(`p${isValidPct ? pct : 0}`);

  if (isPhish) {
    pct_content.classList.add('orange');
    site_score.classList.add('warning');
    site_msg.classList.add('warning');
  } else {
    site_score.classList.add('safe');
    site_msg.classList.add('safe');
  }

  // Thông báo trạng thái
  let message;
  if (status === 'OFFLINE') {
    message = 'Không thể kết nối máy chủ phân tích.';
  } else if (status === 'FAILED') {
    message = 'Không thể phân tích trang này.';
  } else {
    message = isPhish ? 'Website này có thể không an toàn.' : 'Website này có thể an toàn.';
  }

  $('#site_msg').text(isValidPct ? message : '...');
  $('#site_score').text(isValidPct ? `${pct - 1}%` : '...');
  $('#domain_url').text(domain);
};

// ─────────────────────────────────────────────────────────────────────────────
//  Main — lấy tab hiện tại → polling state từ storage.session
// ─────────────────────────────────────────────────────────────────────────────
chrome.tabs.query({ currentWindow: true, active: true }, ([tab]) => {
  if (!tab) return;

  const tabId = tab.id;
  let url;
  try {
    url = new URL(tab.url);
  } catch {
    return;
  }
  const domain = url.hostname;

  // Không xử lý các trang không phải HTTP/HTTPS (chrome://, file://, v.v.)
  if (!['https:', 'http:'].includes(url.protocol)) {
    $('#pluginBody').hide();
    $('#domain_url').text(domain);
    return;
  }

  // Hiển thị trạng thái mặc định trong khi chờ
  $('#site_msg').text('Đang phân tích...');
  $('#site_score').text('...');
  $('#domain_url').text(domain);

  let attempts = 0;

  const poll = () => {
    chrome.runtime.sendMessage({ type: 'GET_TAB_STATE', tabId }, (state) => {
      // Xử lý lỗi khi service worker đang khởi động lại
      if (chrome.runtime.lastError) {
        if (attempts < POLL_MAX_ATTEMPTS) {
          attempts++;
          setTimeout(poll, POLL_INTERVAL_MS);
        } else {
          $('#site_msg').text('Tiện ích chưa sẵn sàng. Thử tải lại trang.');
          $('#site_score').text('...');
        }
        return;
      }

      // Còn đang phân tích → tiếp tục polling
      const isStillAnalyzing = !state || state.status === 'ANALYZING' || state.status === 'IDLE';
      if (isStillAnalyzing) {
        if (attempts < POLL_MAX_ATTEMPTS) {
          attempts++;
          setTimeout(poll, POLL_INTERVAL_MS);
        } else {
          // Hết thời gian chờ — hiển thị kết quả nếu có, không thì báo lỗi
          if (state && state.result) {
            renderState(state, domain);
          } else {
            $('#site_msg').text('Trang chưa được phân tích. Thử tải lại trang.');
            $('#site_score').text('...');
            $('#domain_url').text(domain);
          }
        }
        return;
      }

      // Có kết quả (SUCCESS / FAILED / OFFLINE) → render UI ngay
      renderState(state, domain);
    });
  };

  poll();
});

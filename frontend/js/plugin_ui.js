/* global chrome */
/* global $ */

// ─────────────────────────────────────────────────────────────────────────────
// Màu sắc badge (giữ nguyên)
// ─────────────────────────────────────────────────────────────────────────────
// Badge values V3: SAFE(-1) NEUTRAL(0) SUSPICIOUS(2) DANGEROUS(1)
// '-1' xanh (an toàn) | '0' vàng (trung tính) | '2' cam (đáng ngờ) | '1' đỏ (nguy hiểm)
const colors = { '-1':'#22c55e', '0':'#facc15', '2':'#fb923c', '1':'#dc2626' };
const reasonColors = { safe:'#22c55e', warning:'#facc15', suspicious:'#fb923c', danger:'#dc2626' };
let currentTabUrl = '';
let currentDomain = '';

const initTheme = () => {
  const saved = localStorage.getItem('antiscam-theme') || 'auto';
  if (saved === 'light') document.documentElement.setAttribute('data-theme', 'light');
  if (saved === 'dark') document.documentElement.setAttribute('data-theme', 'dark');
  const btn = document.getElementById('themeToggle');
  if (btn) btn.textContent = (saved === 'light') ? 'Light' : 'Dark';
};
const toggleTheme = () => {
  const cur = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = cur === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('antiscam-theme', next);
  const btn = document.getElementById('themeToggle'); if (btn) btn.textContent = next === 'light' ? 'Light' : 'Dark';
};
initTheme();
const themeBtn = document.getElementById('themeToggle');
if (themeBtn) themeBtn.addEventListener('click', toggleTheme);

// ─────────────────────────────────────────────────────────────────────────────
// Cấu hình polling — V2: liên tục (dynamic score)
// ─────────────────────────────────────────────────────────────────────────────
const POLL_INTERVAL_MS = 800;       // giai đoạn chờ phân tích đầu
const UPDATE_INTERVAL_MS = 1500;    // sau khi có kết quả → cập nhật realtime
const POLL_MAX_ATTEMPTS = 19;

// ─────────────────────────────────────────────────────────────────────────────
// Collapsible "Xem chi tiết" (giữ nguyên)
// ─────────────────────────────────────────────────────────────────────────────
[...document.getElementsByClassName('collapsible')].forEach((el) => {
  el.addEventListener('click', function () {
    this.classList.toggle('active');
    const content = this.nextElementSibling;
    if (content.style.maxHeight) { content.style.maxHeight = null; }
    else { content.style.maxHeight = `${content.scrollHeight}px`; }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Bảng dịch thuật (giữ key cũ + thêm key V2)
// ─────────────────────────────────────────────────────────────────────────────
const featureTranslations = {
  // gốc
  'IP Address':'Địa chỉ IP','URL Length':'Độ dài đường dẫn','Tiny URL':'URL rút gọn',
  '@ Symbol':'Chứa ký tự @','Redirecting using //':'Chuyển hướng ẩn (//)',
  '(-) Prefix/Suffix in domain':'Có dấu (-) trong tên miền','No. of Sub Domains':'Nhiều tên miền phụ',
  'HTTPS':'Bảo mật HTTPS','Favicon':'Biểu tượng trang (Favicon)','Port':'Cổng mạng (Port)',
  "HTTPS in URL's domain part":'HTTPS giả mạo','Request URL':'Tài nguyên từ trang khác',
  'Anchor':'Liên kết ngoài','Script & Link':'Mã nhúng từ trang khác','SFH':'Biểu mẫu không rõ nơi nhận dữ liệu',
  'mailto':'Gửi dữ liệu qua email','iFrames':'Khung trang ẩn (iFrame)',
  'Sensitive Form':'Yêu cầu nhập mật khẩu/OTP/tài khoản/thẻ','Form Hijacking':'Chiếm đoạt dữ liệu Form',
  'Obfuscated Script':'Mã độc ẩn (Obfuscated)','Domain Age':'Tên miền mới đăng ký',
  // V2 — risk badges
  'Punycode':'Tên miền mã hoá (Punycode)','UnicodeHost':'Ký tự Unicode bất thường',
  'Homograph':'Giả mạo thương hiệu (ký tự giống)','Typosquat':'Tên miền gần giống thương hiệu',
  'BrandInDomain':'Tên miền chứa tên thương hiệu lạ','BrandInPath':'Đường dẫn nhắc thương hiệu',
  'BrandImpersonation':'Giả mạo thương hiệu trong nội dung','VNScamKeyword':'URL chứa từ khoá lừa đảo (VN)',
  'Keylogger':'Theo dõi thao tác gõ phím','ClipboardHijack':'Can thiệp bộ nhớ tạm',
  'DangerousDownload':'Yêu cầu tải file nguy hiểm','SuspiciousExternal':'Tải mã từ nguồn lạ',
  'NoHTTPS':'Không dùng HTTPS','AtSymbol':'URL chứa ký tự @','LongURL':'Đường dẫn quá dài',
  'SuspiciousTLD':'Đuôi tên miền dễ lạm dụng','IPHost':'Truy cập bằng địa chỉ IP',
  'RedirectChain':'Chuỗi chuyển hướng phức tạp',
  'DataExfil':'Gửi dữ liệu ra tên miền lạ',
  'FormDest':'Biểu mẫu gửi dữ liệu đến tên miền lạ',
  'Hidden Form':'Biểu mẫu bị ẩn', 'HiddenForm':'Biểu mẫu bị ẩn',
  'JavaScript Risk':'Mã JavaScript đáng ngờ', 'JavaScriptRisk':'Mã JavaScript đáng ngờ',
  'Scam Content':'Nội dung lừa đảo', 'ScamContent':'Nội dung lừa đảo',
  'NewDomain':'Website mới đăng ký', 'MalwareReputation':'Nguồn cảnh báo nguy hiểm',
  'DNSRisk':'Hạ tầng DNS/hosting rủi ro', 'CommunityReport':'Cộng đồng báo cáo',
  // V2 — trust badges (xanh)
  'EstablishedDomain':'Tên miền lâu đời','ReputationVerified':'Nằm trong danh sách tin cậy',
  'OfficialBrand':'Thương hiệu chính thức','SSL':'Có chứng chỉ HTTPS',
  'TrustedResources':'Tài nguyên từ nguồn phổ biến',
  'CleanScan':'Quét toàn diện: không phát hiện mối đe dọa',
  'NoPhishingForm':'Không phát hiện biểu mẫu đánh cắp thông tin',
};

// ─────────────────────────────────────────────────────────────────────────────
// Theo dõi class động để xoá khi re-render (idempotent — không trùng lớp)
// ─────────────────────────────────────────────────────────────────────────────
let _dynClasses = { pct:[], score:[], msg:[] };
const _cleanDyn = () => {
  const pc = document.getElementById('percentage_content');
  const ss = document.getElementById('site_score');
  const sm = document.getElementById('site_msg');
  _dynClasses.pct.forEach(c => pc && pc.classList.remove(c));
  _dynClasses.score.forEach(c => ss && ss.classList.remove(c));
  _dynClasses.msg.forEach(c => sm && sm.classList.remove(c));
  _dynClasses = { pct:[], score:[], msg:[] };
};

// ─────────────────────────────────────────────────────────────────────────────
// Map key badge → số lượng (lấy từ state.counts)
// Trả về HTML <span class="badge-count"> cho thống nhất
// - Số LƯỢNG tuyệt đối (iframe, form): ×3
// - TỶ LỆ (anchor, script, image): 2/12
// ĐỒNG NHẤT: luôn dùng cú pháp [số] trong tag riêng (badge-count)
// ─────────────────────────────────────────────────────────────────────────────
const _countData = (key, counts) => {
  if (!counts) return null;
  switch (key) {
    case 'iFrames':
      if (counts.hiddenIframes > 0) return { text: counts.hiddenIframes > 1 ? '×' + counts.hiddenIframes : '1' };
      break;
    case 'Anchor':
      if (counts.externalAnchors > 0) return { text: counts.externalAnchors + '/' + counts.totalAnchors };
      break;
    case 'Script & Link':
      if (counts.externalScripts > 0) return { text: counts.externalScripts + '/' + counts.totalScripts };
      break;
    case 'Request URL':
      if (counts.externalImages > 0) return { text: counts.externalImages + '/' + counts.totalImages };
      break;
    case 'Sensitive Form':
      if (counts.sensitiveForms > 1) return { text: '×' + counts.sensitiveForms };
      break;
  }
  return null;
};

// Tạo text + HTML count badge cho một key
const _buildBadge = (key, val, counts) => {
  const label = featureTranslations[key] || key;
  const cd = _countData(key, counts);
  if (!cd) return { text: label, html: label, hasCount: false };
  // text thuần (cho fallback)
  const fullText = label + ' (' + cd.text + ')';
  // HTML có span count style riêng (cho CẢ safe + warn)
  const html = label + ' <span style="display:inline-block;background:rgba(0,0,0,0.3);border-radius:0.6rem;padding:0.05rem 0.5rem;margin-left:0.3rem;font-size:0.85em;font-weight:600;opacity:0.9;">' + cd.text + '</span>';
  return { text: fullText, html: html, hasCount: true };
};


const _stripSentence = (text) => (text || '').toString().replace(/\s+/g, ' ').trim().replace(/[.。]+$/, '');
const _normLabel = (text) => _stripSentence(text).toLowerCase()
  .normalize ? _stripSentence(text).toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '') : _stripSentence(text).toLowerCase();

const semanticKeyMap = {
  'HTTPS':'https', 'SSL':'https', 'NoHTTPS':'https',
  'OfficialBrand':'official-domain',
  'EstablishedDomain':'domain-age-established', 'Domain Age':'domain-age-new', 'NewDomain':'domain-age-new',
  'TrustedResources':'trusted-resources',
  'NoPhishingForm':'no-phishing-form', 'Sensitive Form':'no-phishing-form',
  'Form Hijacking':'form-destination', 'FormDest':'form-destination', 'SFH':'form-unknown-action',
  'Punycode':'unicode-spoof', 'UnicodeHost':'unicode-spoof', 'Homograph':'unicode-spoof',
  'Typosquat':'brand-spoof', 'BrandInDomain':'brand-spoof', 'BrandImpersonation':'brand-spoof',
  'Obfuscated Script':'js-risk', 'JavaScript Risk':'js-risk', 'JavaScriptRisk':'js-risk',
  'Scam Content':'scam-content', 'ScamContent':'scam-content',
  'MalwareReputation':'malware-reputation', 'DNSRisk':'dns-risk', 'CommunityReport':'community-report',
  'DangerousDownload':'download-risk'
};

const _canonicalKey = (key, text) => semanticKeyMap[key] || _normLabel(featureTranslations[key] || text || key);
const _levelFromValue = (val) => val === '-1' ? 'safe' : (val === '1' ? 'danger' : (val === '2' ? 'suspicious' : 'warning'));
const _groupFromLevel = (level) => level === 'safe' ? 'positive' : (level === 'danger' ? 'danger' : 'warning');
const _prefixForLevel = (level) => level === 'safe' ? '✓' : (level === 'danger' ? '✕' : '⚠');

const _labelForSignal = (key, val, fallbackText) => {
  const levelWords = ['safe', 'warning', 'suspicious', 'danger'];
  const level = (typeof val === 'string' && levelWords.includes(val)) ? val : (typeof val === 'string' ? _levelFromValue(val) : (val || 'warning'));
  const safe = level === 'safe';
  switch (key) {
    case 'HTTPS': case 'SSL': return safe ? 'HTTPS hợp lệ' : 'Không dùng HTTPS';
    case 'NoHTTPS': return 'Không dùng HTTPS';
    case 'OfficialBrand': return 'Domain chính thức';
    case 'EstablishedDomain': return 'Domain lâu năm';
    case 'NewDomain': case 'Domain Age': return 'Website mới đăng ký';
    case 'TrustedResources': return 'CDN uy tín';
    case 'Favicon': return safe ? 'Favicon hợp lệ' : 'Favicon bất thường';
    case 'Anchor': return safe ? 'Liên kết ngoài hợp lệ' : 'Liên kết ngoài đáng chú ý';
    case 'Request URL': return safe ? 'Tài nguyên ảnh hợp lệ' : 'Tài nguyên ảnh từ nguồn lạ';
    case 'Script & Link': return safe ? 'Mã nhúng hợp lệ' : 'Mã nhúng từ nguồn lạ';
    case 'Sensitive Form': return safe ? 'Không phát hiện form đánh cắp' : 'Yêu cầu thông tin nhạy cảm';
    case 'NoPhishingForm': return 'Không phát hiện form đánh cắp';
    case 'Form Hijacking': case 'FormDest': return 'Form gửi sang domain lạ';
    case 'SFH': return 'Form chưa rõ nơi nhận';
    case 'Punycode': case 'UnicodeHost': case 'Homograph': return 'Dấu hiệu giả mạo ký tự';
    case 'Typosquat': case 'BrandInDomain': case 'BrandImpersonation': return 'Dấu hiệu giả mạo thương hiệu';
    case 'JavaScript Risk': case 'JavaScriptRisk': case 'Obfuscated Script': return 'JavaScript đáng ngờ';
    case 'Scam Content': case 'ScamContent': return 'Nội dung lừa đảo';
    case 'MalwareReputation': return 'Nguồn cảnh báo nguy hiểm';
    case 'DNSRisk': return 'Hạ tầng DNS rủi ro';
    case 'CommunityReport': return 'Cộng đồng đã báo cáo';
    case 'DangerousDownload': return 'Tải xuống nguy hiểm';
    case 'Tiny URL': return safe ? 'URL không rút gọn' : 'URL rút gọn';
    case 'IP Address': case 'IPHost': return safe ? 'Không dùng IP trực tiếp' : 'Dùng địa chỉ IP trực tiếp';
    case 'LongURL': case 'URL Length': return safe ? 'Độ dài URL hợp lệ' : 'URL quá dài';
    default: return _stripSentence(fallbackText || featureTranslations[key] || key);
  }
};

const _createChip = (item, counts) => {
  const li = document.createElement('li');
  const level = item.level || 'warning';
  li.className = `feature-chip chip-${level}`;
  const icon = document.createElement('span');
  icon.className = 'chip-icon';
  icon.textContent = _prefixForLevel(level);
  const label = document.createElement('span');
  label.className = 'chip-label';
  label.textContent = item.label;
  li.appendChild(icon);
  li.appendChild(label);
  const cd = _countData(item.key, counts);
  if (cd) {
    const count = document.createElement('span');
    count.className = 'chip-count';
    count.textContent = cd.text;
    li.appendChild(count);
  }
  return li;
};

const _appendChipGroup = (featureList, title, items, counts) => {
  if (!items.length) return;
  const heading = document.createElement('li');
  heading.className = 'feature-group-title';
  heading.textContent = title;
  featureList.appendChild(heading);
  items.forEach(item => featureList.appendChild(_createChip(item, counts)));
};

const _collectFeatureChips = (state) => {
  const counts = state.counts || null;
  const chips = [];
  const used = new Map();
  const addChip = (raw) => {
    const key = raw.key || raw.label || raw.text;
    const level = raw.level || _levelFromValue(String(raw.value));
    const label = _labelForSignal(key, raw.value != null ? String(raw.value) : level, raw.text || raw.label);
    const canonical = _canonicalKey(key, label);
    const group = _groupFromLevel(level);
    const priority = { danger:0, suspicious:1, warning:2, safe:3 }[level] ?? 4;
    const chip = { key, label, level, group, priority, canonical };
    const previous = used.get(canonical);
    if (!previous || chip.priority < previous.priority) used.set(canonical, chip);
  };

  const explanations = Array.isArray(state.explanations) ? state.explanations : [];
  explanations.forEach(item => addChip({ key:item.key, level:item.level, text:item.text }));

  const result = state.result || {};
  Object.keys(result).forEach(key => {
    if (key === 'tab') return;
    const value = String(result[key]);
    if (!['-1', '0', '1', '2'].includes(value)) return;
    addChip({ key, value, label:featureTranslations[key] || key });
  });

  used.forEach(v => chips.push(v));
  const order = { positive:0, warning:1, danger:2 };
  chips.sort((a, b) => (order[a.group] - order[b.group]) || (a.priority - b.priority) || a.label.localeCompare(b.label, 'vi'));
  return { chips, counts };
};

// ─────────────────────────────────────────────────────────────────────────────
// Render unified feature chips
// ─────────────────────────────────────────────────────────────────────────────
const renderState = (state, domain) => {
  const { isWhiteList, isBlocked, isPhish, legitimatePercent, status, isUnknown } = state;

  if (isWhiteList) {
    $('#pluginBody').hide(); $('#isSafe').show(); $('#isSafe .site-url').text(domain); return;
  }
  if (isBlocked) {
    $('#pluginBody').hide(); $('#isPhishing').show(); $('#isPhishing .site-url').text(isBlocked); return;
  }

  _cleanDyn();

  const featureList = document.getElementById('features');
  featureList.innerHTML = '';
  const { chips, counts } = _collectFeatureChips(state);
  const positive = chips.filter(c => c.group === 'positive');
  const warning = chips.filter(c => c.group === 'warning');
  const danger = chips.filter(c => c.group === 'danger');

  _appendChipGroup(featureList, 'TÍN HIỆU TÍCH CỰC', positive, counts);
  _appendChipGroup(featureList, 'TÍN HIỆU CẢNH BÁO', warning, counts);
  _appendChipGroup(featureList, 'TÍN HIỆU NGUY HIỂM', danger, counts);

  if (!chips.length) {
    const empty = document.createElement('li');
    empty.className = 'feature-empty';
    empty.textContent = 'Chưa có tín hiệu hiển thị.';
    featureList.appendChild(empty);
  }
  const featureContent = featureList.closest('.feature-content');
  if (featureContent && featureContent.style.maxHeight) featureContent.style.maxHeight = `${featureContent.scrollHeight}px`;

  const pct = parseInt(legitimatePercent);
  const isValidPct = !isNaN(pct) && isFinite(pct);

  const site_score = document.getElementById('site_score');
  const pct_content = document.getElementById('percentage_content');
  const site_msg = document.getElementById('site_msg');

  // Class động cho vòng tròn % + trạng thái
  const pctCls = `p${isValidPct ? pct : 0}`;
  pct_content.classList.add(pctCls); _dynClasses.pct.push(pctCls);
  if (isPhish) { pct_content.classList.add('orange'); _dynClasses.pct.push('orange'); }

  if (isPhish) {
    site_score.classList.add('warning'); _dynClasses.score.push('warning');
    site_msg.classList.add('warning'); _dynClasses.msg.push('warning');
  } else {
    site_score.classList.add('safe'); _dynClasses.score.push('safe');
    site_msg.classList.add('safe'); _dynClasses.msg.push('safe');
  }

  // Thông báo tổng quan không lặp lại nội dung từng chip.
  let message;
  if (status === 'OFFLINE') message = 'Không thể kết nối máy chủ phân tích.';
  else if (status === 'FAILED') message = 'Không thể phân tích trang này.';
  else if (isUnknown) message = 'Chưa đủ dữ liệu để đánh giá độ tin cậy.';
  else message = isPhish ? 'Website có nguy cơ cao. Xem các tín hiệu bên dưới.' : 'Website đã được phân tích. Xem các tín hiệu bên dưới.';

  // Vòng tròn chỉ hiển thị % gọn gàng — KHÔNG nhồi confidence vào
  $('#site_score').text(isValidPct ? `${pct}%` : '...');

  if (isValidPct) {
    const noteLine = isUnknown
      ? `<div class="sub-note">Chưa đủ dữ liệu — không nhập thông tin nhạy cảm nếu chưa chắc chắn.</div>`
      : `<div class="sub-note">Mỗi lý do bên dưới là một tín hiệu đánh giá độc lập.</div>`;
    $('#site_msg').html(message + noteLine);
  } else {
    $('#site_msg').text('...');
  }
  $('#domain_url').text(domain);
};

// ─────────────────────────────────────────────────────────────────────────────
// Main — polling LIÊN TỤC (dynamic score — Vấn đề 8, 9)
// ─────────────────────────────────────────────────────────────────────────────
chrome.tabs.query({ currentWindow: true, active: true }, ([tab]) => {
  if (!tab) return;
  const tabId = tab.id;
  let url; try { url = new URL(tab.url); } catch { return; }
  const domain = url.hostname;
  currentTabUrl = tab.url; currentDomain = domain;

  if (!['https:', 'http:'].includes(url.protocol)) {
    $('#pluginBody').hide(); $('#domain_url').text(domain); return;
  }

  $('#site_msg').text('Đang phân tích...'); $('#site_score').text('...'); $('#domain_url').text(domain);

  let attempts = 0;
  let hasResult = false;
  let lastUpdatedAt = 0;

  const poll = () => {
    chrome.runtime.sendMessage({ type: 'GET_TAB_STATE', tabId }, (state) => {
      if (chrome.runtime.lastError) {
        if (attempts < POLL_MAX_ATTEMPTS) { attempts++; setTimeout(poll, POLL_INTERVAL_MS); }
        else { $('#site_msg').text('Tiện ích chưa sẵn sàng. Thử tải lại trang.'); $('#site_score').text('...'); }
        return;
      }

      const stillAnalyzing = !state || state.status === 'ANALYZING' || state.status === 'IDLE';
      if (stillAnalyzing) {
        if (attempts < POLL_MAX_ATTEMPTS) { attempts++; setTimeout(poll, POLL_INTERVAL_MS); }
        else if (state && state.result) { renderState(state, domain); hasResult = true; }
        else { $('#site_msg').text('Trang chưa được phân tích. Thử tải lại trang.'); $('#site_score').text('...'); $('#domain_url').text(domain); }
        return;
      }

      // Có kết quả → render + TIẾP TỤC polling để cập nhật realtime
      const updatedNow = state && state.updatedAt && state.updatedAt !== lastUpdatedAt;
      if (updatedNow || !hasResult) {
        renderState(state, domain);
        lastUpdatedAt = state ? state.updatedAt : 0;
        hasResult = true;
      }
      // Poll tiếp với nhịp chậm hơn để bắt ANALYSIS_UPDATE
      setTimeout(poll, UPDATE_INTERVAL_MS);
    });
  };

  poll();
});


// Community report UI
const reportToggle = document.getElementById('reportToggle');
const reportForm = document.getElementById('reportForm');
const sendReport = document.getElementById('sendReport');
const reportCancel = document.getElementById('reportCancel');
const closeReportPanel = () => {
  if (!reportForm) return;
  reportForm.hidden = true;
  reportToggle && reportToggle.setAttribute('aria-expanded', 'false');
  const statusEl = document.getElementById('reportStatus');
  if (statusEl) statusEl.textContent = '';
};
if (reportToggle && reportForm) {
  reportToggle.setAttribute('aria-expanded', 'false');
  reportToggle.addEventListener('click', () => {
    reportForm.hidden = !reportForm.hidden;
    reportToggle.setAttribute('aria-expanded', String(!reportForm.hidden));
  });
}
if (reportCancel) {
  reportCancel.addEventListener('click', () => {
    const reasonEl = document.getElementById('reportReason');
    if (reasonEl) reasonEl.value = '';
    closeReportPanel();
  });
}
if (sendReport) {
  sendReport.addEventListener('click', () => {
    const reasonEl = document.getElementById('reportReason');
    const statusEl = document.getElementById('reportStatus');
    const reason = (reasonEl && reasonEl.value || '').trim();
    if (!reason) { if (statusEl) statusEl.textContent = 'Vui lòng nhập lý do.'; return; }
    if (statusEl) statusEl.textContent = 'Đang gửi...';
    chrome.runtime.sendMessage({ type:'COMMUNITY_REPORT', payload:{ url: currentTabUrl, domain: currentDomain, reason } }, (resp) => {
      if (chrome.runtime.lastError || !resp || !resp.ok) {
        if (statusEl) statusEl.textContent = 'Không gửi được báo cáo.';
        return;
      }
      if (statusEl) statusEl.textContent = 'Đã gửi báo cáo. Cảm ơn bạn!';
      if (reasonEl) reasonEl.value = '';
      setTimeout(closeReportPanel, 900);
    });
  });
}

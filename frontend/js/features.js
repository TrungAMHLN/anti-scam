/* global chrome */
// ═══════════════════════════════════════════════════════════════════════════
// features.js  —  CONTENT SCRIPT V2  (Continuous Scan Mode)
//
// Kiến trúc:
//   • collect()         — thu thập toàn bộ tín hiệu DOM (1 lần)
//   • MutationObserver  — theo dõi iframe/form/script/hidden element mới
//   • URL detection     — popstate / hashchange / polling location.href
//   • Network monitor   — hook fetch/XHR/sendBeacon/WebSocket (MAIN world)
//   • Brand surfaces    — title/h1/h2/meta/favicon/logo → brand impersonation
//
// Gửi: ANALYSIS_RESULT (lần đầu) + ANALYSIS_UPDATE (real-time khi thay đổi)
// ═══════════════════════════════════════════════════════════════════════════

const url = window.location.href;
const urlDomain = window.location.hostname;
const onlyDomain = urlDomain.replace(/^www\./, '');
const ipRe = /^(\d{1,3}\.){3}\d{1,3}$/;

// ── Trusted CDN (fallback nội bộ — features.js không import heuristic.js) ──
const _TRUSTED = ['googleapis.com','google.com','gstatic.com','google-analytics.com','googletagmanager.com',
  'youtube.com','ytimg.com','doubleclick.net','cloudflare.com','cdnjs.cloudflare.com','cdn.jsdelivr.net',
  'jsdelivr.net','unpkg.com','bootstrapcdn.com','maxcdn.bootstrapcdn.com','netdna.bootstrapcdn.com',
  'stackpath.bootstrapcdn.com','fontawesome.com','use.fontawesome.com','kit.fontawesome.com',
  'ajax.aspnetcdn.com','msecnd.net','code.jquery.com','facebook.net','fbcdn.net','twitter.com','twimg.com',
  'cloudfront.net','akamai.net','akamaized.net','fastly.net','stripe.com','js.stripe.com',
  'tailwindcss.com','polyfill.io','githubassets.com','googlevideo.com'];
const _isTrustedHost = (host) => {
  if (!host) return false;
  const h = host.toLowerCase().replace(/^www\./, '');
  if (_TRUSTED.includes(h)) return true;
  return _TRUSTED.some(t => h.endsWith('.' + t));
};
const _hostOf = (raw) => {
  if (!raw || typeof raw !== 'string') return null;
  const s = raw.trim();
  if (s.startsWith('//')) { try { return new URL('https:' + s).hostname; } catch (_) { return null; } }
  if (s.startsWith('http://') || s.startsWith('https://')) { try { return new URL(s).hostname; } catch (_) { return null; } }
  if (s.startsWith('/') || s === '') return onlyDomain;
  if (s.startsWith('data:') || s.startsWith('blob:') || s.startsWith('javascript:')) return null;
  return null;
};
const _hostEndsWith = (a, b) => !(!a || !b) && (a === b || a.endsWith('.' + b) || b.endsWith('.' + a));

const _normalizeText = (str) => {
  try {
    return (str || '').toString().normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
  } catch (_) { return (str || '').toString().toLowerCase(); }
};
const VN_SCAM_CONTENT_PATTERNS = [
  { re: /loi\s*nhuan\s*\d+\s*%|\d+\s*%\s*(moi\s*ngay|\/\s*ngay|ngay)/, label: 'lợi nhuận cao bất thường' },
  { re: /dau\s*tu|tien\s*dien\s*tu|crypto|coin|forex|quyen\s*chon\s*nhi\s*phan/, label: 'đầu tư/tiền điện tử rủi ro' },
  { re: /da\s*cap|he\s*thong\s*tuyen\s*duoi|mo\s*hinh\s*kim\s*tu\s*thap/, label: 'đa cấp' },
  { re: /vay\s*nong|vay\s*nhanh|giai\s*ngan\s*trong\s*ngay|khong\s*can\s*the\s*chap/, label: 'vay nóng' },
  { re: /viec\s*nhe\s*luong\s*cao|kiem\s*tien\s*online|khong\s*can\s*von|lam\s*nhiem\s*vu/, label: 'việc nhẹ lương cao/kiếm tiền online' },
  { re: /nhan\s*thuong|trung\s*thuong|nhan\s*qua|hoa\s*hong\s*khung|nap\s*tien\s*nhan\s*thuong/, label: 'nhận thưởng/hoa hồng bất thường' },
];

// ═══════════════════════════════════════════════════════════════════════════
// BRAND SURFACES — phát hiện giả mạo qua nhiều bề mặt
// ═══════════════════════════════════════════════════════════════════════════
const BRAND_KEYS = [
  ['vietcombank','Vietcombank'],['bidv','BIDV'],['mbbank','MB'],['techcombank','Techcombank'],
  ['tpbank','TPBank'],['agribank','Agribank'],['vietinbank','VietinBank'],['vpbank','VPBank'],
  ['sacombank','Sacombank'],['momo','MoMo'],['zalopay','ZaloPay'],['zalo','Zalo'],
  ['google','Google'],['microsoft','Microsoft'],['facebook','Facebook'],['apple','Apple'],
  ['paypal','PayPal'],['amazon','Amazon'],['netflix','Netflix'],['openai','OpenAI'],['chatgpt','ChatGPT'],
  ['telegram','Telegram'],['github','GitHub'],['shopee','Shopee'],['lazada','Lazada'],
];
const BRAND_OFFICIAL = {
  'vietcombank':['vietcombank.com.vn'],'bidv':['bidv.com.vn'],'mbbank':['mbbank.com.vn'],
  'techcombank':['techcombank.com.vn'],'tpbank':['tpb.vn','tpbank.vn'],'agribank':['agribank.com.vn'],
  'vietinbank':['vietinbank.vn'],'vpbank':['vpbank.vn'],'sacombank':['sacombank.com'],
  'momo':['momo.vn'],'zalopay':['zalopay.vn'],'zalo':['zalo.me'],'google':['google.com'],
  'microsoft':['microsoft.com'],'facebook':['facebook.com'],'apple':['apple.com'],
  'paypal':['paypal.com'],'amazon':['amazon.com'],'netflix':['netflix.com'],
  'openai':['openai.com','chatgpt.com'],'chatgpt':['chatgpt.com','openai.com'],'telegram':['telegram.org'],'github':['github.com'],
  'shopee':['shopee.vn'],'lazada':['lazada.vn'],'mb':['mbbank.com.vn'],
};

const detectBrandSurfaces = () => {
  const title = (document.title || '').toLowerCase();
  let h1 = '', h2 = '';
  try {
    const h1el = document.querySelector('h1'); if (h1el) h1 = (h1el.textContent || '').toLowerCase();
    const h2els = document.querySelectorAll('h2'); if (h2els.length) h2 = Array.from(h2els).map(e => e.textContent || '').join(' ').toLowerCase().slice(0, 2000);
  } catch (_) {}
  let meta = '';
  try {
    const m = document.querySelector('meta[name="description"], meta[property="og:title"], meta[property="og:description"]');
    if (m) meta = (m.getAttribute('content') || '').toLowerCase();
  } catch (_) {}
  // favicon origin
  let faviconHost = null;
  try {
    const fl = document.querySelector('link[rel~="icon"], link[rel="shortcut icon"]');
    if (fl) faviconHost = _hostOf(fl.getAttribute('href'));
  } catch (_) {}

  const surfaces = { title, h1, h2, meta };
  const brandHits = {}; // key -> count of surfaces

  for (const [key, name] of BRAND_KEYS) {
    if (key.length < 4) continue;
    const official = BRAND_OFFICIAL[key] || [];
    const isOfficial = official.some(d => onlyDomain === d || onlyDomain.endsWith('.' + d));
    if (isOfficial) continue;
    let count = 0;
    for (const surf of Object.values(surfaces)) {
      if (surf && surf.includes(key)) count++;
    }
    // favicon từ domain lạ nhưng file trùng brand (hiếm, bỏ qua nếu CDN)
    if (count > 0) brandHits[key] = { name, count };
  }
  const entries = Object.values(brandHits);
  if (entries.length === 0) return { brandInContent: false, brandSurfaces: 0, matchedBrand: null };
  const best = entries.sort((a, b) => b.count - a.count)[0];
  return { brandInContent: true, brandSurfaces: best.count, matchedBrand: best.name };
};

// ═══════════════════════════════════════════════════════════════════════════
// COLLECT — thu thập toàn bộ tín hiệu (gọi mỗi lần quét)
// ═══════════════════════════════════════════════════════════════════════════
const collect = () => {
  const result = {}; // ML features (giữ key gốc cho model)
  const dom = { scanned: true };

  // ── ML features (cho model phụ) ──
  result['IP Address'] = ipRe.test(onlyDomain) ? '1' : '-1';
  result['URL Length'] = (url.length > 100) ? '0' : '-1';
  result['Tiny URL'] = (onlyDomain.length < 5 && !ipRe.test(onlyDomain)) ? '0' : '-1';
  result['@ Symbol'] = url.includes('@') ? '0' : '-1';
  result['Redirecting using //'] = (url.lastIndexOf('//') > 7 && /\/\/[^/]+@/.test(url)) ? '0' : '-1';
  result['(-) Prefix/Suffix in domain'] = ((onlyDomain.match(/-/g) || []).length >= 3) ? '0' : '-1';
  result['No. of Sub Domains'] = ((onlyDomain.match(/\./g) || []).length >= 4) ? '0' : '-1';
  result['HTTPS'] = (window.location.protocol === 'https:') ? '-1' : '0';
  result['HTTPS in URL\'s domain part'] = (/https/i.test(onlyDomain)) ? '0' : '-1';
  result['Favicon'] = '-1';
  result['Port'] = '-1';
  const port = window.location.port;
  if (port && !['80','443','8080','8000','8008','3000','3001','4200','5000','5173','5500','8081','8443','9000','9001','1234','2020','4000'].includes(port)) result['Port'] = '0';

  // ── external resource ratios (cho ML + deep) ──
  const sTags = document.getElementsByTagName('script');
  const lTags = document.getElementsByTagName('link');
  const imgTags = document.getElementsByTagName('img');
  const aTags = document.getElementsByTagName('a');
  const forms = document.getElementsByTagName('form');
  const iframes = document.getElementsByTagName('iframe');

  let extCount = 0, totalCount = 0;
  const externalScriptHosts = [];
  const countExternal = (getSrc) => {
    for (const el of getSrc) {
      const src = el.getAttribute('src') || el.getAttribute('href');
      if (!src) continue;
      totalCount++;
      const h = _hostOf(src);
      if (h && h !== onlyDomain && !_hostEndsWith(h, onlyDomain) && !_isTrustedHost(h)) { extCount++; externalScriptHosts.push(h); }
    }
  };
  countExternal(Array.from(sTags));
  countExternal(Array.from(lTags));
  let outPct = totalCount === 0 ? 0 : (extCount / totalCount) * 100;
  result['Script & Link'] = (outPct > 80) ? '1' : (outPct > 50 ? '0' : '-1');

  // ── Request URL (tỷ lệ ảnh từ domain lạ) ──
  let imgExt = 0, imgTotal = 0;
  for (const img of imgTags) {
    const src = img.getAttribute('src');
    if (!src) continue;
    imgTotal++;
    const h = _hostOf(src);
    if (h && h !== onlyDomain && !_hostEndsWith(h, onlyDomain) && !_isTrustedHost(h)) imgExt++;
  }
  let imgPct = imgTotal === 0 ? 0 : (imgExt / imgTotal) * 100;
  result['Request URL'] = (imgPct > 60) ? '1' : (imgPct > 30 ? '0' : '-1');

  // ── Anchor (tỷ lệ liên kết ngoài) ──
  let aExt = 0, aTotal = 0;
  for (const a of aTags) {
    const href = a.getAttribute('href');
    if (!href) continue;
    aTotal++;
    const h = _hostOf(href);
    if (h && h !== onlyDomain && !_hostEndsWith(h, onlyDomain) && !_isTrustedHost(h)) aExt++;
  }
  let aPct = aTotal === 0 ? 0 : (aExt / aTotal) * 100;
  result['Anchor'] = (aPct > 75) ? '1' : (aPct > 40 ? '0' : '-1');

  // ── content richness (STICKY — một lần true thì không quay lại false) ──
  if (!_stickyState.contentRich) {
    let bodyTextLen = 0;
    try { bodyTextLen = (document.body && document.body.innerText || '').trim().length; } catch (_) {}
    if (bodyTextLen > 200) _stickyState.contentRich = true;
  }
  dom.contentRich = _stickyState.contentRich;

  // ── Scam content tiếng Việt ──
  let bodyText = '';
  try { bodyText = _normalizeText((document.body && document.body.innerText || '').slice(0, 60000)); } catch (_) {}
  const scamHits = [];
  for (const p of VN_SCAM_CONTENT_PATTERNS) {
    if (p.re.test(bodyText)) scamHits.push(p.label);
  }
  dom.scamContentHits = scamHits;
  dom.scamContentRisk = scamHits.length;
  result['Scam Content'] = scamHits.length >= 2 ? '2' : (scamHits.length === 1 ? '0' : '-1');

  // ── BRAND surfaces ──
  const bs = detectBrandSurfaces();
  dom.brandInContent = bs.brandInContent;
  dom.brandSurfaces = bs.brandSurfaces;
  dom.matchedBrand = bs.matchedBrand;

  // ── SFH / mailto ──
  result['SFH'] = '-1';
  for (const f of forms) {
    const action = f.getAttribute('action');
    if (!action || action === '' || action === '#') result['SFH'] = '0';
    else if (action.startsWith('http')) {
      try {
        const ah = new URL(action).hostname.replace(/^www\./, '');
        if (ah !== onlyDomain && !_hostEndsWith(ah, onlyDomain) && !_isTrustedHost(ah)) result['SFH'] = '1';
      } catch (_) {}
    }
  }
  result['mailto'] = '-1';
  for (const f of forms) { const a = f.getAttribute('action') || ''; if (a.startsWith('mailto')) { result['mailto'] = '0'; break; } }

  // ── IFRAME RISK SCORE (V3) — chấm điểm chi tiết từng iframe ──
  //   +10 ẩn | +15 cross-origin | +20 không trong whitelist | +20 chứa form
  //   +30 chứa password field | +30 chứa script obfuscated
  //   Nếu src từ trusted provider (Google/OpenAI/Stripe...) → 0 điểm (SAFE)
  result['iFrames'] = '-1';
  dom.numIframes = iframes.length;
  dom.hiddenIframe = false;
  let hiddenIframeCount = 0;
  let iframeRiskScore = 0;
  const iframeDetails = [];
  const TRUSTED_IFRAME_HOSTS = ['google.com','recaptcha','gstatic.com','google-analytics.com',
    'googletagmanager.com','doubleclick.net','facebook.com','fbcdn.net','connect.facebook.net',
    'stripe.com','js.stripe.com','cloudflare.com','challenges.cloudflare.com','twitter.com',
    'twimg.com','linkedin.com','bing.com','microsoft.com','paypal.com','amazon.com','apple.com',
    'openai.com','chatgpt.com','youtube.com','googlevideo.com','player.vimeo.com'];
  const _isTrustedIframeHost = (host) => {
    if (!host) return true; // same-origin hoặc không có src → mặc định an toàn
    const h = host.toLowerCase();
    return TRUSTED_IFRAME_HOSTS.some(t => h.includes(t)) || _isTrustedHost(h);
  };
  for (const fr of iframes) {
    const src = fr.getAttribute('src');
    const srcHost = _hostOf(src);
    const w = parseInt(fr.getAttribute('width') || (fr.offsetWidth || 0));
    const h = parseInt(fr.getAttribute('height') || (fr.offsetHeight || 0));
    const st = fr.style || {};
    const isHidden = st.display === 'none' || st.visibility === 'hidden' ||
      parseFloat(st.opacity || '1') === 0 || (w > 0 && w <= 1) || (h > 0 && h <= 1);
    const isCrossOrigin = srcHost && srcHost !== onlyDomain && !_hostEndsWith(srcHost, onlyDomain);
    const isTrusted = _isTrustedIframeHost(srcHost);

    // Trusted iframe (reCAPTCHA, YouTube, OAuth) → 0 điểm, bỏ qua
    if (isTrusted && !isHidden) continue;
    if (isTrusted && isHidden) continue; // reCAPTCHA/Pixel ẩn cũng OK

    let score = 0;
    const reasons = [];

    if (isHidden) { score += 10; reasons.push('ẩn'); hiddenIframeCount++; _stickyState.hiddenIframe = true; }
    if (isCrossOrigin && !isTrusted) { score += 15; reasons.push('cross-origin'); }
    if (isCrossOrigin && !isTrusted && !_isTrustedHost(srcHost)) { score += 20; reasons.push('domain lạ'); }

    // Kiểm tra nội dung iframe (chỉ same-origin mới truy cập được contentDocument)
    let iframeHasForm = false, iframeHasPassword = false, iframeHasObf = false;
    try {
      const idoc = fr.contentDocument || fr.contentWindow?.document;
      if (idoc) {
        if (idoc.querySelector('form')) { iframeHasForm = true; }
        if (idoc.querySelector('input[type="password"]')) { iframeHasPassword = true; }
        const iscripts = idoc.querySelectorAll('script');
        for (const s of iscripts) {
          const c = s.textContent || '';
          if (c.length > 500 && (c.includes('eval(') || c.includes('atob(') || c.includes('fromCharCode'))) {
            iframeHasObf = true; break;
          }
        }
      }
    } catch (_) { /* cross-origin → không truy cập được, bỏ qua */ }

    if (iframeHasForm) { score += 20; reasons.push('chứa form'); }
    if (iframeHasPassword) { score += 30; reasons.push('chứa ô mật khẩu'); }
    if (iframeHasObf) { score += 30; reasons.push('chứa mã độc'); }

    if (score > 0) {
      iframeRiskScore = Math.max(iframeRiskScore, score);
      iframeDetails.push({ score, reasons, host: srcHost });
    }
  }
  dom.hiddenIframe = _stickyState.hiddenIframe;
  dom.iframeRiskScore = iframeRiskScore;
  dom.iframeDetails = iframeDetails;
  // Badge: tổng điểm iframe quyết định mức độ
  if (iframeRiskScore >= 40) result['iFrames'] = '1';       // đỏ
  else if (iframeRiskScore >= 25) result['iFrames'] = '2';   // cam
  else if (iframeRiskScore >= 10) result['iFrames'] = '0';   // vàng
  else result['iFrames'] = '-1';                              // xanh

  // ── FORM nhạy cảm + hijacking ──
  const sensitiveNames = ['password','passcode','passwd','otp','pin','cvv','cvc','cardnumber','card-number',
    'creditcard','credit-card','debitcard','debit-card','cc-number','so-the','sothe','the-ngan-hang',
    'cccd','cmnd','cmt','ekyc','e-kyc','taikhoan','tai-khoan','account','username','user-name',
    'stk','sotk','so-tai-khoan','tai-khoan-ngan-hang','bank-account','ngan-hang','internet-banking',
    'secret','token','private','ngayhethan','ngay-het-han','expiry','expire'];
  const TRUSTED_FORM_HOSTS = ['google.com','facebook.com','apple.com','microsoft.com','github.com'];
  let sensitiveFound = false, hijackFound = false, pwField = false, otpField = false, hiddenFormFound = false, cardField = false, bankAccountField = false;
  let sensitiveFormCount = 0;
  for (const f of forms) {
    const html = (f.innerHTML || '').toLowerCase();
    const style = (f.getAttribute('style') || '').toLowerCase();
    const hiddenByCss = f.hidden || style.includes('display:none') || style.includes('display: none') ||
      style.includes('visibility:hidden') || style.includes('visibility: hidden') || style.includes('opacity:0') ||
      (f.offsetWidth === 0 && f.offsetHeight === 0 && f.querySelector('input'));
    const hiddenInputCount = f.querySelectorAll ? f.querySelectorAll('input[type="hidden"]').length : 0;
    let sensitive = /type\s*=\s*["']password["']/.test(html) ||
      /autocomplete\s*=\s*["']current-password["']/.test(html) ||
      /autocomplete\s*=\s*["']cc-[a-z]+["']/.test(html);
    if (!sensitive) { for (const nm of sensitiveNames) { if (html.includes(nm)) { sensitive = true; break; } } }
    if (sensitive) {
      sensitiveFound = true;
      sensitiveFormCount++;
      if (/type\s*=\s*["']password["']/.test(html)) pwField = true;
      if (html.includes('otp') || html.includes('ma-xac-thuc') || html.includes('maxacthuc') || html.includes('one-time')) otpField = true;
      if (/card|credit|debit|cvv|cvc|so-the|sothe|cc-number/.test(html)) cardField = true;
      if (/stk|sotk|so-tai-khoan|bank-account|ngan-hang|internet-banking/.test(html)) bankAccountField = true;
      if (hiddenByCss || hiddenInputCount >= 3) hiddenFormFound = true;
      const action = f.getAttribute('action') || '';
      if (action.startsWith('http')) {
        try {
          const ah = new URL(action).hostname.replace(/^www\./, '');
          const trusted = TRUSTED_FORM_HOSTS.some(h => ah === h || ah.endsWith('.' + h));
          const same = ah === onlyDomain || _hostEndsWith(ah, onlyDomain);
          if (!trusted && !same && !_isTrustedHost(ah)) hijackFound = true;
        } catch (_) {}
      }
    }
  }
  dom.sensitiveForm = sensitiveFound || _stickyState.sensitiveForm;
  _stickyState.sensitiveForm = dom.sensitiveForm;
  dom.formHijack = hijackFound || _stickyState.formHijack;
  _stickyState.formHijack = dom.formHijack;
  dom.passwordField = pwField;
  dom.otpField = otpField;
  dom.cardField = cardField;
  dom.bankAccountField = bankAccountField;
  dom.hiddenForm = hiddenFormFound;
  // Phản chiếu vào result để hiển thị badge
  result['Sensitive Form'] = sensitiveFound ? (cardField || bankAccountField ? '2' : '0') : '-1';
  result['Form Hijacking'] = hijackFound ? '1' : '-1';
  result['Hidden Form'] = hiddenFormFound ? '2' : '-1';
  // SFH: form không có action là RẤT phổ biến ở SPA (React/Vue/Angular submit bằng JS).
  //      CHỈ hiện vàng khi form đó YÊU CẦU THÔNG TIN NHẠY CẢM (password/OTP).
  //      Không có password → bình thường → hiện xanh (-1), không phạt điểm.
  if (result['SFH'] === '0' && !sensitiveFound) {
    result['SFH'] = '-1';
  }
  // Truyền SFH cho engine
  dom.sfh = result['SFH'];

  // ── Obfuscation + keylogger + clipboard ──
  const TRUSTED_PAT = [/webpack/,/__vite__/,/react\./,/__vue__/,/_nuxt/,/cloudflare/,/gtag\(/,/ga\(/,/dataLayer/,/serviceWorker/,/sentry/,/jquery/];
  const calcEntropy = (str) => {
    if (!str || str.length === 0) return 0;
    const freq = {}; for (const c of str) freq[c] = (freq[c] || 0) + 1;
    let e = 0; const len = str.length;
    for (const k in freq) { const p = freq[k] / len; e -= p * Math.log2(p); } return e;
  };
  let maxConf = 0;
  let hasKeylogger = false, hasClipboard = false, hasObf = false, hasWS = false;
  const jsRiskIndicators = new Set();
  for (const s of sTags) {
    const code = s.innerHTML;
    if (!code || code.length < 80) continue;
    let conf = 0;
    const compactCode = code.replace(/\s+/g, '');
    const hex = (code.match(/\\x[0-9a-fA-F]{2}/g) || []).length;
    const uni = (code.match(/\\u[0-9a-fA-F]{4}/g) || []).length;
    if (hex > 15 || uni > 15) { conf += 30; jsRiskIndicators.add('encoded'); }
    if (/unescape\s*\(/.test(code) || /(?:String\.)?fromCharCode\s*\(/.test(code)) { conf += 25; jsRiskIndicators.add('decoder'); }
    if (/atob\s*\(/.test(code)) { conf += code.length > 2000 ? 15 : 8; jsRiskIndicators.add('atob'); }
    if (/eval\s*\(/.test(code)) { conf += conf > 0 ? 25 : 10; jsRiskIndicators.add('eval'); }
    if (/new\s+Function\s*\(/.test(code)) { conf += 15; jsRiskIndicators.add('new Function'); }
    if (/document\.write\s*\(/.test(code)) { conf += 8; jsRiskIndicators.add('document.write'); }
    if (/["'][A-Za-z0-9+/]{120,}={0,2}["']/.test(compactCode)) { conf += 18; jsRiskIndicators.add('base64 payload'); }
    if (code.length > 1500 && (code.match(/\n/g) || []).length < 4 && calcEntropy(code) > 5.2) { conf += 20; jsRiskIndicators.add('high entropy'); }
    if (TRUSTED_PAT.some(re => re.test(code))) conf = Math.max(0, conf - 20);
    maxConf = Math.max(maxConf, conf);
    if (conf >= 60) hasObf = true;
    if (/addEventListener\s*\(\s*["']keydown["']|addEventListener\s*\(\s*["']keypress["']/.test(code)) {
      if (code.length > 500 && (code.includes('XMLHttpRequest') || code.includes('fetch(') || code.includes('sendBeacon'))) hasKeylogger = true;
    }
    if (/navigator\.clipboard\.writeText|clipboard\.writeText/.test(code)) hasClipboard = true;
    if (/new\s+WebSocket\s*\(|\.io\s*\(|socket\.io/i.test(code)) hasWS = true;
  }
  dom.obfuscatedScript = hasObf || _stickyState.obfuscatedScript;
  _stickyState.obfuscatedScript = dom.obfuscatedScript;
  dom.keylogger = hasKeylogger || _stickyState.keylogger;
  _stickyState.keylogger = dom.keylogger;
  dom.clipboardHijack = hasClipboard || _stickyState.clipboardHijack;
  _stickyState.clipboardHijack = dom.clipboardHijack;
  dom.websocket = hasWS;
  dom.jsRiskScore = maxConf;
  dom.jsRiskIndicators = Array.from(jsRiskIndicators).slice(0, 8);
  result['Obfuscated Script'] = hasObf ? '1' : (maxConf >= 40 ? '0' : '-1');
  result['JavaScript Risk'] = maxConf >= 60 ? '1' : (maxConf >= 35 ? '2' : '-1');

  // ── suspicious external script (IP / domain lạ) ──
  let suspExt = false;
  for (const h of externalScriptHosts) {
    if (ipRe.test(h)) { suspExt = true; break; }
    const label = h.split('.')[0];
    if (label.length > 24 && /[0-9]/.test(label) && /[a-zA-Z]/.test(label)) { suspExt = true; break; }
  }
  dom.suspiciousExternalScript = suspExt || _stickyState.suspiciousExternalScript;
  _stickyState.suspiciousExternalScript = dom.suspiciousExternalScript;

  // ── dangerous download ──
  const DANGEROUS_EXT = ['.exe','.scr','.bat','.cmd','.ps1','.apk','.msi','.dll','.vbs','.jar'];
  dom.downloadFile = false;
  try {
    if (document.querySelector('a[download]') || document.querySelector('meta[http-equiv="refresh"]')) {
      const html = document.documentElement.outerHTML.toLowerCase();
      if (DANGEROUS_EXT.some(e => html.includes(e))) dom.downloadFile = true;
    }
  } catch (_) {}
  if (DANGEROUS_EXT.some(e => window.location.pathname.toLowerCase().endsWith(e))) dom.downloadFile = true;
  dom.downloadFile = dom.downloadFile || _stickyState.downloadFile;
  _stickyState.downloadFile = dom.downloadFile;

  // ── network monitor findings (tích lũy từ injected hook + sticky) ──
  if (netState.uploadToExternal) _stickyState.networkUploadToExternal = true;
  dom.networkUploadToExternal = _stickyState.networkUploadToExternal;
  // FORM DESTINATION ENGINE (V3): theo dõi endpoint thực tế nhận dữ liệu form
  // không chỉ dựa vào form.action mà theo dõi fetch/XHR/sendBeacon cross-domain POST
  dom.formDestinations = netState.externalPostHosts ? Array.from(netState.externalPostHosts) : [];
  dom.hasUntrustedFormDest = dom.formDestinations.some(h => !_isTrustedHost(h));

  // ═══ SỐ LƯỢNG — đếm cho hiển thị badge ═══
  dom.counts = {
    hiddenIframes: hiddenIframeCount,
    totalIframes: iframes.length,
    iframeRiskScore: iframeRiskScore,
    sensitiveForms: sensitiveFormCount,
    totalForms: forms.length,
    externalAnchors: aExt,
    totalAnchors: aTotal,
    externalScripts: extCount,
    totalScripts: totalCount,
    externalImages: imgExt,
    totalImages: imgTotal,
    scamContentHits: scamHits.length,
    jsRiskScore: maxConf,
    hiddenForms: hiddenFormFound ? 1 : 0,
  };

  return { result, dom };
};

// ═══════════════════════════════════════════════════════════════════════════
// NETWORK MONITOR — inject MAIN-world hook
// ═══════════════════════════════════════════════════════════════════════════
const netState = { externalHosts: new Set(), uploadToExternal: false, externalPostHosts: new Set() };

// Lắng nghe CustomEvent từ MAIN-world script
window.addEventListener('__antiscam_net', (e) => {
  try {
    const d = e.detail || {};
    if (d.host && d.host !== onlyDomain && !_hostEndsWith(d.host, onlyDomain) && !_isTrustedHost(d.host)) {
      netState.externalHosts.add(d.host);
      if (d.upload) {
        netState.uploadToExternal = true;
        netState.externalPostHosts.add(d.host);
      }
    }
  } catch (_) {}
});

const injectNetworkHook = () => {
  try {
    if (document.getElementById('__antiscam_net_hook')) return;
    const code = `(function(){
      if (window.__antiscamHooked) return; window.__antiscamHooked = true;
      var host = location.hostname.replace(/^www\\./,'');
      var send = function(host2, upload){
        try { window.dispatchEvent(new CustomEvent('__antiscam_net',{detail:{host:host2,upload:upload}})); } catch(e){}
      };
      // fetch
      var _fetch = window.fetch;
      if (_fetch) window.fetch = function(input, opts){
        try {
          var u = typeof input === 'string' ? input : (input && input.url);
          if (u) {
            var h = new URL(u, location.href).hostname.replace(/^www\\./,'');
            if (h && h !== host) {
              var up = opts && opts.method && /post|put|patch/i.test(opts.method);
              if (opts && opts.body) up = true;
              send(h, !!up);
            }
          }
        } catch(e){}
        return _fetch.apply(this, arguments);
      };
      // XMLHttpRequest
      var _open = XMLHttpRequest.prototype.open;
      var _send = XMLHttpRequest.prototype.send;
      XMLHttpRequest.prototype.open = function(m, u){
        this.__ascm_m = m; this.__ascm_url = u;
        return _open.apply(this, arguments);
      };
      XMLHttpRequest.prototype.send = function(body){
        try {
          if (this.__ascm_url) {
            var h = new URL(this.__ascm_url, location.href).hostname.replace(/^www\\./,'');
            if (h && h !== host) send(h, !!body || /post|put|patch/i.test(this.__ascm_m || ''));
          }
        } catch(e){}
        return _send.apply(this, arguments);
      };
      // sendBeacon
      if (navigator.sendBeacon) {
        var _beacon = navigator.sendBeacon.bind(navigator);
        navigator.sendBeacon = function(url){
          try {
            var h = new URL(url, location.href).hostname.replace(/^www\\./,'');
            if (h && h !== host) send(h, true);
          } catch(e){}
          return _beacon.apply(navigator, arguments);
        };
      }
      // WebSocket
      var _WS = window.WebSocket;
      if (_WS) {
        var OrigWS = _WS;
        window.WebSocket = function(url, protocols){
          try {
            var h = new URL(url, location.href).hostname.replace(/^www\\./,'');
            if (h && h !== host) send(h, false);
          } catch(e){}
          return protocols !== undefined ? new OrigWS(url, protocols) : new OrigWS(url);
        };
        window.WebSocket.prototype = OrigWS.prototype;
        if (OrigWS.CONNECTING != null) window.WebSocket.CONNECTING = OrigWS.CONNECTING;
        if (OrigWS.OPEN != null) window.WebSocket.OPEN = OrigWS.OPEN;
        if (OrigWS.CLOSING != null) window.WebSocket.CLOSING = OrigWS.CLOSING;
        if (OrigWS.CLOSED != null) window.WebSocket.CLOSED = OrigWS.CLOSED;
      }
    })();`;
    const s = document.createElement('script');
    s.id = '__antiscam_net_hook';
    s.textContent = code;
    (document.head || document.documentElement).appendChild(s);
    s.remove();
  } catch (_) { /* CSP chặn inline → bỏ qua gracefully */ }
};

// ═══════════════════════════════════════════════════════════════════════════
// CONTINUOUS SCAN — gửi phân tích + cập nhật realtime
// ═══════════════════════════════════════════════════════════════════════════
let lastSnapshot = '';
let debounceTimer = null;
let currentUrl = window.location.href;
let sentInitial = false;

// Sticky state — tín hiệu phát hiện rồi thì KHÔNG quay lại false (chống nhảy điểm)
const _stickyState = {
  contentRich: false,
  hiddenIframe: false,
  keylogger: false,
  clipboardHijack: false,
  obfuscatedScript: false,
  suspiciousExternalScript: false,
  downloadFile: false,
  networkUploadToExternal: false,
  sensitiveForm: false,
  formHijack: false,
  hiddenForm: false,
};

const snapshotKey = (data) => JSON.stringify(data.dom) + '|' + data.result['Obfuscated Script'] + '|' + data.result['SFH'];

const sendAnalysis = (isUpdate) => {
  const data = collect();
  const key = snapshotKey(data);
  if (!isUpdate && sentInitial) return;
  if (isUpdate && key === lastSnapshot) return; // không đổi → bỏ qua
  lastSnapshot = key;

  const msg = { type: isUpdate ? 'ANALYSIS_UPDATE' : 'ANALYSIS_RESULT', result: data.result, dom: data.dom };
  chrome.runtime.sendMessage(msg, () => {
    if (chrome.runtime.lastError) { /* SW restart — bỏ qua */ }
  });
  if (!isUpdate) sentInitial = true;
};

const scheduleRescan = (delay = 1200) => {
  if (debounceTimer) clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => sendAnalysis(true), delay);
};

// ── 1. MutationObserver ──
const startMutationObserver = () => {
  if (!('MutationObserver' in window) || !document.body) return;
  const obs = new MutationObserver((mutations) => {
    let relevant = false;
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node.nodeType !== 1) continue;
        const tag = node.tagName;
        if (tag === 'IFRAME' || tag === 'FORM' || tag === 'SCRIPT') { relevant = true; break; }
        if (tag === 'DIV' || tag === 'SECTION') {
          if (node.querySelector && node.querySelector('iframe,form,script,input')) { relevant = true; break; }
        }
      }
      if (relevant) break;
    }
    if (relevant) scheduleRescan();
  });
  try { obs.observe(document.documentElement, { childList: true, subtree: true }); } catch (_) {}
};

// ── 2. URL change detection ──
const startUrlWatcher = () => {
  window.addEventListener('popstate', () => { currentUrl = window.location.href; scheduleRescan(300); });
  window.addEventListener('hashchange', () => scheduleRescan(300));
  // Polling cho pushState/replaceState (SPA)
  setInterval(() => {
    if (window.location.href !== currentUrl) {
      currentUrl = window.location.href;
      // URL đổi → reset toàn bộ sticky + gửi lại ANALYSIS_RESULT (fresh)
      sentInitial = false; lastSnapshot = '';
      netState.externalHosts.clear(); netState.uploadToExternal = false; netState.externalPostHosts.clear();
      Object.keys(_stickyState).forEach(k => { _stickyState[k] = false; });
      setTimeout(() => sendAnalysis(false), 400);
    }
  }, 2000);
};

// ═══════════════════════════════════════════════════════════════════════════
// INIT
// ═══════════════════════════════════════════════════════════════════════════
injectNetworkHook();
sendAnalysis(false);              // phân tích ban đầu
startMutationObserver();
startUrlWatcher();
// quét lại sau 2.5s để bắt nội dung load động (SPA/async)
setTimeout(() => sendAnalysis(true), 2500);
setTimeout(() => sendAnalysis(true), 6000);

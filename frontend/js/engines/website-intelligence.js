/**
 * ANTISCAM VIETNAM — Website Intelligence Engine
 * Module 4: Phân tích nội dung và hành vi website
 *
 * Chạy trong content script (sau DOM ready).
 * Export qua window.WebsiteIntelligence.
 *
 * Phát hiện:
 *  1. OTP Harvesting Form
 *  2. Fake Banking/Payment Form
 *  3. Password Harvesting
 *  4. Hidden Input / Hidden Form
 *  5. Data Exfiltration (form action đến domain lạ)
 *  6. Suspicious External Scripts
 *  7. Urgency Language (tiếng Việt)
 *  8. Scam Pattern Keywords (cộng tác viên, việc làm online...)
 *  9. Fake Captcha
 * 10. Iframe Abuse
 */

(function () {
  'use strict';

  // ─────────────────────────────────────────────────────────────────────────────
  // DATABASE: OTP-related field patterns (Vietnamese + English)
  // ─────────────────────────────────────────────────────────────────────────────

  const OTP_PATTERNS = [
    'otp', 'one.time', 'xac.thuc', 'xacthuc', 'ma.xac', 'maxac',
    'verification.code', 'verifycode', 'sms.code', 'smscode',
    'ma 6 so', 'ma xac nhan', 'nhap ma', 'nhập mã', 'mã xác thực',
    'mã otp', '6 chữ số', 'tin nhắn xác minh',
  ];

  // ─────────────────────────────────────────────────────────────────────────────
  // DATABASE: Urgency keywords (tiếng Việt)
  // ─────────────────────────────────────────────────────────────────────────────

  const URGENCY_KEYWORDS = [
    'khẩn cấp', 'khan cap', 'ngay bây giờ', 'ngay bay gio',
    'tài khoản bị khóa', 'tai khoan bi khoa',
    'tài khoản bị tạm khóa', 'tài khoản bị đình chỉ',
    'hết hạn', 'het han', 'sắp hết hạn',
    'liên hệ ngay', 'lien he ngay',
    'xác minh ngay', 'xac minh ngay',
    'cập nhật ngay', 'cap nhat ngay',
    'bảo mật tài khoản', 'bao mat tai khoan',
    'cảnh báo bảo mật', 'canh bao bao mat',
    'đăng nhập ngay', 'dang nhap ngay',
    'trước khi quá muộn', 'truoc khi qua muon',
    'click ngay', 'nhấp ngay', 'nhap ngay',
  ];

  // ─────────────────────────────────────────────────────────────────────────────
  // DATABASE: Scam pattern keywords (các hình thức lừa đảo VN)
  // ─────────────────────────────────────────────────────────────────────────────

  const SCAM_PATTERN_KEYWORDS = [
    // Việc làm giả
    'cộng tác viên', 'cong tac vien', 'ctv shopee', 'ctv lazada',
    'việc làm online', 'viec lam online', 'làm việc tại nhà', 'lam viec tai nha',
    'thu nhập thêm', 'thu nhap them', 'thu nhập thụ động', 'thu nhap thu dong',
    'kiếm tiền online', 'kiem tien online', 'kiếm tiền tại nhà',
    'part time online', 'làm thêm online',
    // Đầu tư lừa đảo
    'đầu tư sinh lời', 'dau tu sinh loi', 'lãi suất cao', 'lai suat cao',
    'lợi nhuận hấp dẫn', 'sinh lời nhanh', 'đầu tư an toàn 100%',
    'hoàn vốn 100%', 'hoan von 100%', 'không rủi ro', 'khong rui ro',
    'nhân đôi tiền', 'nhan doi tien', 'x2 x3 lợi nhuận',
    // Học bổng giả
    'học bổng toàn phần', 'hoc bong toan phan', 'học bổng du học',
    'hoc bong du hoc', 'miễn 100% học phí', 'hỗ trợ học phí',
    // Giải thưởng giả
    'trúng thưởng', 'trung thuong', 'chúc mừng bạn đã trúng',
    'nhận quà ngay', 'nhan qua ngay', 'quà tặng miễn phí',
    'iphone miễn phí', 'iphone mien phi',
    // Nhận hàng / Shipper giả
    'kiện hàng của bạn', 'kien hang cua ban', 'đơn hàng bị giữ',
    'don hang bi giu', 'phí thông quan', 'phi thong quan',
    // Romance Scam
    'kết bạn làm quen', 'ket ban lam quen', 'người nước ngoài',
    'foreign investor', 'muốn đầu tư vào việt nam',
  ];

  // ─────────────────────────────────────────────────────────────────────────────
  // DATABASE: Banking form field patterns
  // ─────────────────────────────────────────────────────────────────────────────

  const BANKING_FIELD_PATTERNS = [
    // Credentials
    'username', 'user.name', 'user.id', 'userid', 'loginid', 'login.id',
    'ten.dang.nhap', 'tendangnhap', 'tai.khoan', 'taikhoan',
    'so.tai.khoan', 'sotaikhoan', 'account.number',
    // PIN/OTP
    'pin', 'mat.khau', 'matkhau', 'password', 'pass', 'passwd',
    'ma.pin', 'mapin', 'ma.giao.dich', 'magiaodich',
    // Card
    'card.number', 'cardnumber', 'so.the', 'sothe',
    'cvv', 'cvc', 'card.cvv', 'exp.date', 'expdate', 'expiry',
    // Identity
    'cccd', 'cmnd', 'so.cmnd', 'socmnd', 'id.number',
    'ho.ten', 'hoten', 'full.name', 'fullname',
  ];

  // ─────────────────────────────────────────────────────────────────────────────
  // HELPERS
  // ─────────────────────────────────────────────────────────────────────────────

  function normalizeText(str) {
    return (str || '').toLowerCase()
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '') // remove diacritics
      .replace(/\s+/g, ' ')
      .trim();
  }

  function getFieldDescriptors(element) {
    return [
      element.getAttribute('name') || '',
      element.getAttribute('id') || '',
      element.getAttribute('placeholder') || '',
      element.getAttribute('class') || '',
      element.getAttribute('autocomplete') || '',
      element.getAttribute('aria-label') || '',
    ].map(normalizeText).join(' ');
  }

  function getAssociatedLabel(input) {
    // Tìm label tương ứng
    const id = input.getAttribute('id');
    if (id) {
      const label = document.querySelector(`label[for="${CSS.escape(id)}"]`);
      if (label) return normalizeText(label.innerText || label.textContent || '');
    }
    // Look for parent label
    const parentLabel = input.closest('label');
    if (parentLabel) return normalizeText(parentLabel.innerText || '');
    // Look for preceding sibling or parent text
    const parent = input.parentElement;
    if (parent) return normalizeText(parent.innerText || '').substring(0, 100);
    return '';
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // DETECTORS
  // ─────────────────────────────────────────────────────────────────────────────

  function detectOTPFields() {
    const inputs = document.querySelectorAll('input');
    const otpInputs = [];

    for (const input of inputs) {
      const descriptor = getFieldDescriptors(input) + ' ' + getAssociatedLabel(input);
      const isOTP = OTP_PATTERNS.some(p => descriptor.includes(p.replace(/\./g, '')));
      // Also check for 6-digit numeric input pattern
      const isNumericShort = (input.getAttribute('maxlength') === '6' ||
        input.getAttribute('maxlength') === '4') &&
        (input.getAttribute('type') === 'number' ||
          input.getAttribute('type') === 'tel' ||
          input.getAttribute('inputmode') === 'numeric');

      if (isOTP || isNumericShort) {
        otpInputs.push({
          name: input.getAttribute('name') || input.getAttribute('id') || 'unknown',
          placeholder: input.getAttribute('placeholder') || '',
        });
      }
    }

    return {
      detected: otpInputs.length > 0,
      count: otpInputs.length,
      fields: otpInputs,
    };
  }

  function detectBankingForm() {
    const inputs = document.querySelectorAll('input, select');
    const matchedFields = [];
    let passwordCount = 0;
    let hasAutoCompleteOff = false;

    for (const input of inputs) {
      const descriptor = getFieldDescriptors(input) + ' ' + getAssociatedLabel(input);

      // Count password fields
      if (input.getAttribute('type') === 'password') {
        passwordCount++;
        if (input.getAttribute('autocomplete') === 'off' ||
          input.getAttribute('autocomplete') === 'new-password') {
          hasAutoCompleteOff = true;
        }
      }

      // Match banking patterns
      const matched = BANKING_FIELD_PATTERNS.find(p => {
        const pattern = p.replace(/\./g, '');
        return descriptor.includes(pattern);
      });

      if (matched) {
        matchedFields.push({
          pattern: matched,
          name: input.getAttribute('name') || input.getAttribute('id') || 'unknown',
        });
      }
    }

    const uniquePatterns = [...new Set(matchedFields.map(f => f.pattern))];

    return {
      detected: uniquePatterns.length >= 2 || (passwordCount >= 1 && uniquePatterns.length >= 1),
      matchedFieldCount: uniquePatterns.length,
      matchedPatterns: uniquePatterns.slice(0, 5),
      passwordCount,
      hasAutoCompleteOff,
    };
  }

  function detectDataExfiltration(currentHostname) {
    const forms = document.querySelectorAll('form');
    const exfiltrationTargets = [];

    for (const form of forms) {
      const action = (form.getAttribute('action') || '').toLowerCase();
      if (!action || action.startsWith('#') || action.startsWith('/') ||
        action.startsWith('javascript')) {
        continue;
      }

      try {
        const actionUrl = new URL(action, window.location.href);
        const actionHost = actionUrl.hostname.replace(/^www\./, '');
        const currentHost = currentHostname.replace(/^www\./, '');

        // If form submits to a different domain
        if (actionHost && actionHost !== currentHost) {
          exfiltrationTargets.push({
            currentDomain: currentHost,
            targetDomain: actionHost,
            formAction: action.substring(0, 100),
          });
        }
      } catch (_e) { /* ignore */ }
    }

    return {
      detected: exfiltrationTargets.length > 0,
      targets: exfiltrationTargets,
    };
  }

  function detectHiddenElements() {
    // Hidden inputs with sensitive names
    const hiddenInputs = document.querySelectorAll('input[type="hidden"]');
    const sensitiveHidden = [];

    for (const input of hiddenInputs) {
      const name = (input.getAttribute('name') || '').toLowerCase();
      if (['token', 'csrf', 'session', 'redirect', 'returnurl', 'callback'].some(p => name.includes(p))) {
        // These are normal
        continue;
      }
      if (BANKING_FIELD_PATTERNS.some(p => name.includes(p.replace(/\./g, '')))) {
        sensitiveHidden.push(name);
      }
    }

    // Forms hidden with CSS
    const forms = document.querySelectorAll('form');
    const hiddenForms = [];
    for (const form of forms) {
      const style = window.getComputedStyle(form);
      if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
        const hasPasswordField = form.querySelector('input[type="password"]');
        if (hasPasswordField) {
          hiddenForms.push('hidden-password-form');
        }
      }
    }

    return {
      hasSensitiveHidden: sensitiveHidden.length > 0,
      sensitiveHiddenFields: sensitiveHidden,
      hasHiddenForms: hiddenForms.length > 0,
    };
  }

  function detectSuspiciousScripts(currentHostname) {
    const scripts = document.querySelectorAll('script[src]');
    const suspicious = [];
    const currentHost = currentHostname.replace(/^www\./, '');

    // Trusted CDNs và services
    const TRUSTED_SCRIPT_HOSTS = new Set([
      'ajax.googleapis.com', 'cdnjs.cloudflare.com', 'code.jquery.com',
      'cdn.jsdelivr.net', 'stackpath.bootstrapcdn.com', 'maxcdn.bootstrapcdn.com',
      'unpkg.com', 'fonts.googleapis.com', 'www.google-analytics.com',
      'connect.facebook.net', 'platform.twitter.com', 'www.googletagmanager.com',
      'recaptcha.net', 'www.gstatic.com', 'apis.google.com',
    ]);

    for (const script of scripts) {
      const src = script.getAttribute('src') || '';
      try {
        const scriptUrl = new URL(src, window.location.href);
        const scriptHost = scriptUrl.hostname.replace(/^www\./, '');

        if (scriptHost !== currentHost && !TRUSTED_SCRIPT_HOSTS.has(scriptHost)) {
          // Check for data exfiltration patterns in script URL
          const srcLower = src.toLowerCase();
          const isSuspicious = ['collect', 'track', 'log', 'steal', 'grab', 'harvest',
            'keylog', 'exfil', 'capture'].some(p => srcLower.includes(p));

          if (isSuspicious) {
            suspicious.push({ src: src.substring(0, 100), host: scriptHost, reason: 'suspicious-name' });
          }
        }
      } catch (_e) { /* ignore invalid URLs */ }
    }

    return {
      detected: suspicious.length > 0,
      scripts: suspicious,
    };
  }

  function detectUrgencyLanguage() {
    const bodyText = normalizeText(document.body ? document.body.innerText : '');
    const found = URGENCY_KEYWORDS.filter(kw => bodyText.includes(normalizeText(kw)));
    return {
      detected: found.length > 0,
      keywords: found.slice(0, 5),
      count: found.length,
    };
  }

  function detectScamPatterns() {
    const bodyText = normalizeText(document.body ? document.body.innerText : '');
    const titleText = normalizeText(document.title);
    const allText = bodyText + ' ' + titleText;

    const found = SCAM_PATTERN_KEYWORDS.filter(kw => allText.includes(normalizeText(kw)));
    return {
      detected: found.length > 0,
      keywords: found.slice(0, 8),
      count: found.length,
    };
  }

  function detectFakeCaptcha() {
    // Real reCAPTCHA uses specific class/attribute patterns
    const hasRealCaptcha = !!document.querySelector(
      '.g-recaptcha, [data-sitekey], iframe[src*="recaptcha"]'
    );

    // Fake captcha: text about captcha but no real widget
    const bodyText = normalizeText(document.body ? document.body.innerText : '');
    const captchaText = ['captcha', 'xac minh ban la nguoi', 'chung minh ban', 'robot'].some(
      k => bodyText.includes(k)
    );

    const isFake = captchaText && !hasRealCaptcha;

    return {
      detected: isFake,
      hasRealCaptcha,
      hasFakeText: captchaText,
    };
  }

  function detectIframeAbuse() {
    const iframes = document.querySelectorAll('iframe');
    const suspicious = [];
    const currentHost = window.location.hostname.replace(/^www\./, '');

    for (const iframe of iframes) {
      const src = iframe.getAttribute('src') || '';
      // Invisible iframes
      const style = window.getComputedStyle(iframe);
      const isHidden = style.display === 'none' ||
        style.visibility === 'hidden' ||
        parseInt(iframe.getAttribute('width')) === 0 ||
        parseInt(iframe.getAttribute('height')) === 0 ||
        style.opacity === '0';

      if (isHidden && src && !src.startsWith('about:')) {
        try {
          const iframeHost = new URL(src, window.location.href).hostname;
          if (iframeHost !== currentHost) {
            suspicious.push({ src: src.substring(0, 100), reason: 'hidden-cross-origin-iframe' });
          }
        } catch (_e) { /* ignore */ }
      }
    }

    return {
      detected: suspicious.length > 0,
      iframes: suspicious,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // SCORING ENGINE
  // ─────────────────────────────────────────────────────────────────────────────

  function calculateWebsiteScore(analysis) {
    let score = 0;

    if (analysis.otpFields.detected) {
      score += 35;
    }
    if (analysis.bankingForm.detected) {
      score += 30;
    }
    if (analysis.exfiltration.detected) {
      score += 40;
    }
    if (analysis.hiddenElements.hasSensitiveHidden) {
      score += 15;
    }
    if (analysis.hiddenElements.hasHiddenForms) {
      score += 25;
    }
    if (analysis.suspiciousScripts.detected) {
      score += 30;
    }
    if (analysis.urgencyLanguage.detected) {
      score += Math.min(analysis.urgencyLanguage.count * 5, 20);
    }
    if (analysis.scamPatterns.detected) {
      score += Math.min(analysis.scamPatterns.count * 8, 30);
    }
    if (analysis.fakeCaptcha.detected) {
      score += 20;
    }
    if (analysis.iframeAbuse.detected) {
      score += 20;
    }

    return Math.min(100, score);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // AI EXPLANATION
  // ─────────────────────────────────────────────────────────────────────────────

  function generateWebsiteExplanation(analysis, score) {
    const sentences = [];

    if (analysis.otpFields.detected) {
      sentences.push(`🚨 Website yêu cầu nhập mã OTP (${analysis.otpFields.count} trường) — có thể đang thu thập mã xác thực của bạn.`);
    }

    if (analysis.bankingForm.detected) {
      const fields = analysis.bankingForm.matchedPatterns.slice(0, 3).join(', ');
      sentences.push(`🏦 Phát hiện form nhập liệu ngân hàng giả: yêu cầu nhập ${fields}.`);
    }

    if (analysis.exfiltration.detected) {
      const target = analysis.exfiltration.targets[0];
      sentences.push(
        `📤 Form gửi dữ liệu đến "${target.targetDomain}" thay vì "${target.currentDomain}" — dấu hiệu đánh cắp thông tin.`
      );
    }

    if (analysis.scamPatterns.detected && analysis.scamPatterns.keywords.length > 0) {
      const kws = analysis.scamPatterns.keywords.slice(0, 2).join('", "');
      sentences.push(`💼 Phát hiện từ khóa lừa đảo: "${kws}".`);
    }

    if (analysis.urgencyLanguage.detected) {
      sentences.push('⏰ Nội dung trang tạo cảm giác khẩn cấp để ép bạn hành động nhanh.');
    }

    if (analysis.hiddenElements.hasHiddenForms) {
      sentences.push('👁️ Phát hiện form ẩn chứa trường mật khẩu — thủ thuật phishing phổ biến.');
    }

    if (analysis.fakeCaptcha.detected) {
      sentences.push('🤖 Phát hiện captcha giả — đây là kỹ thuật đánh lừa người dùng.');
    }

    if (analysis.iframeAbuse.detected) {
      sentences.push('🖼️ Phát hiện iframe ẩn tải nội dung từ domain khác.');
    }

    if (sentences.length === 0) {
      return '✅ Nội dung website không có dấu hiệu đáng ngờ.';
    }

    return sentences.join(' ');
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // MAIN ANALYSIS FUNCTION
  // ─────────────────────────────────────────────────────────────────────────────

  function analyzeWebsite() {
    const currentHostname = window.location.hostname;

    const otpFields = detectOTPFields();
    const bankingForm = detectBankingForm();
    const exfiltration = detectDataExfiltration(currentHostname);
    const hiddenElements = detectHiddenElements();
    const suspiciousScripts = detectSuspiciousScripts(currentHostname);
    const urgencyLanguage = detectUrgencyLanguage();
    const scamPatterns = detectScamPatterns();
    const fakeCaptcha = detectFakeCaptcha();
    const iframeAbuse = detectIframeAbuse();

    const analysis = {
      otpFields,
      bankingForm,
      exfiltration,
      hiddenElements,
      suspiciousScripts,
      urgencyLanguage,
      scamPatterns,
      fakeCaptcha,
      iframeAbuse,
    };

    const score = calculateWebsiteScore(analysis);
    const explanation = generateWebsiteExplanation(analysis, score);
    const riskLevel = score >= 80 ? 'CRITICAL' :
      score >= 60 ? 'HIGH' :
        score >= 40 ? 'MEDIUM' :
          score >= 20 ? 'LOW' : 'SAFE';

    return {
      ...analysis,
      score,
      riskLevel,
      explanation,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // EXPORT
  // ─────────────────────────────────────────────────────────────────────────────

  window.WebsiteIntelligence = { analyzeWebsite };

})();

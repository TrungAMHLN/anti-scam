// scan_platform.js — lightweight unified target detection and scan helpers
// Runs in extension pages and service worker. No external dependencies.

(function (root) {
  const DANGEROUS_FILE_EXTS = ['.exe', '.scr', '.bat', '.cmd', '.apk', '.jar', '.ps1', '.msi', '.dll', '.vbs'];
  const ARCHIVE_EXTS = ['.zip', '.rar', '.7z'];
  const TEMP_EMAIL_DOMAINS = new Set([
    'yopmail.com','guerrillamail.com','guerrillamail.net','guerrillamail.org','mailinator.com','10minutemail.com',
    'temp-mail.org','tempmail.com','throwawaymail.com','trashmail.com','getnada.com','sharklasers.com','grr.la',
    'maildrop.cc','dispostable.com','fakeinbox.com','mintemail.com','moakt.com','emailondeck.com','tempail.com'
  ]);
  const IMAGE_SCAM_PATTERNS = [
    /loi\s*nhuan|lợi\s*nhuận|\d+\s*%\s*(moi\s*ngay|mỗi\s*ngày|\/\s*ngay)/i,
    /dau\s*tu|đầu\s*tư|tien\s*ao|tiền\s*ảo|crypto|coin|forex/i,
    /nhan\s*thuong|nhận\s*thưởng|hoan\s*tien|hoàn\s*tiền/i,
    /viec\s*nhe\s*luong\s*cao|việc\s*nhẹ\s*lương\s*cao|cong\s*tac\s*vien|cộng\s*tác\s*viên/i,
    /lam\s*nhiem\s*vu|làm\s*nhiệm\s*vụ|chuyen\s*khoan\s*truoc|chuyển\s*khoản\s*trước/i,
    /xac\s*minh\s*tai\s*khoan|xác\s*minh\s*tài\s*khoản|otp|ma\s*xac\s*thuc|mã\s*xác\s*thực/i
  ];
  const BRAND_TEXT_PATTERNS = /vietcombank|bidv|mb\s*bank|mbbank|techcombank|momo|shopee|zalopay|zalo\s*pay/i;

  const trimInput = (value) => (value == null ? '' : String(value)).trim();
  const normalizePhone = (s) => trimInput(s).replace(/[\s().-]/g, '');
  const isUrl = (s) => /^https?:\/\//i.test(s) || /^www\.[a-z0-9.-]+\.[a-z]{2,}/i.test(s);
  const isEmail = (s) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(s);
  const isHash = (s) => /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(s);
  const isIp = (s) => /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(s);
  const isPhone = (s) => {
    const p = normalizePhone(s);
    return /^(?:\+?84|0)(?:3|5|7|8|9)\d{8}$/.test(p) || /^\+?[1-9]\d{7,14}$/.test(p);
  };
  const isDomain = (s) => /^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$/i.test(s) && !s.includes('@');
  const extOf = (name) => {
    const raw = trimInput(name).split('?')[0].split('#')[0].toLowerCase();
    const idx = raw.lastIndexOf('.');
    return idx >= 0 ? raw.slice(idx) : '';
  };
  const isArchiveName = (name) => ARCHIVE_EXTS.includes(extOf(name));
  const isDangerousFileName = (name) => DANGEROUS_FILE_EXTS.includes(extOf(name));

  const normalizeUrl = (s) => {
    const v = trimInput(s);
    if (/^https?:\/\//i.test(v)) return v;
    if (/^www\./i.test(v)) return 'https://' + v;
    if (isDomain(v)) return 'https://' + v;
    return v;
  };

  const detectTarget = (input, meta = {}) => {
    const raw = trimInput(input || meta.url || meta.srcUrl || meta.linkUrl || meta.selectionText || meta.text || '');
    const source = meta.source || 'manual';
    if (meta.kind === 'file' || meta.fileName || meta.hash) {
      const fileName = meta.fileName || raw;
      return {
        type: isArchiveName(fileName) ? 'archive' : 'file',
        value: meta.hash || raw,
        displayValue: fileName || meta.hash || raw,
        source,
        meta,
      };
    }
    if (meta.kind === 'image' || (meta.srcUrl && !raw)) {
      return { type: 'image', value: meta.srcUrl || raw, displayValue: meta.srcUrl || raw, source, meta };
    }
    if (isEmail(raw)) return { type: 'email', value: raw.toLowerCase(), displayValue: raw, source, meta };
    if (isHash(raw)) return { type: 'hash', value: raw.toLowerCase(), displayValue: raw, source, meta };
    if (isIp(raw)) return { type: 'ip', value: raw, displayValue: raw, source, meta };
    if (isPhone(raw)) return { type: 'phone', value: normalizePhone(raw), displayValue: raw, source, meta };
    if (isUrl(raw)) return { type: 'url', value: normalizeUrl(raw), displayValue: raw, source, meta };
    if (isDomain(raw)) return { type: 'domain', value: raw.toLowerCase(), displayValue: raw, source, meta };
    // Người dùng thường nhập kèm nhãn: "Email: a@b.com", "SĐT 090...".
    // Trích xuất entity trước khi fallback sang text để tránh chỉ hiện "văn bản đã nhận diện".
    try {
      const ent = extractEntities(raw.replace(/^mailto:/i, '').replace(/^tel:/i, ''));
      if (ent.emails && ent.emails[0]) return { type: 'email', value: ent.emails[0], displayValue: ent.emails[0], source, meta: { ...meta, extractedFromText: raw } };
      if (ent.phones && ent.phones[0]) return { type: 'phone', value: ent.phones[0], displayValue: ent.phones[0], source, meta: { ...meta, extractedFromText: raw } };
      if (ent.urls && ent.urls[0]) return { type: 'url', value: ent.urls[0], displayValue: ent.urls[0], source, meta: { ...meta, extractedFromText: raw } };
    } catch (_) {}
    return { type: 'text', value: raw, displayValue: raw, source, meta };
  };

  const makeResult = ({ target, finalScore = 70, riskScore = 0, summary = '', result = {}, explanations = [], externalIntel = false }) => {
    const outResult = { ...result };
    const outExplanations = explanations.slice();
    if (!externalIntel) {
      outResult.ExternalIntelMissing = '0';
      outExplanations.push({ key: 'ExternalIntelMissing', level: 'warning', text: 'Chưa có dữ liệu từ nguồn uy tín bên ngoài.' });
    }
    return {
      status: 'SUCCESS',
      scanMode: 'manual',
      targetType: target.type,
      targetValue: target.displayValue || target.value,
      isPhish: finalScore <= 30,
      legitimatePercent: Math.max(0, Math.min(100, Math.round(finalScore))),
      riskScore,
      confidence: externalIntel ? 70 : 35,
      externalIntel,
      assessmentLimited: !externalIntel,
      isUnknown: !externalIntel,
      summary,
      result: outResult,
      explanations: outExplanations,
      updatedAt: Date.now(),
    };
  };

  const normalizeText = (text) => {
    try { return trimInput(text).normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase(); }
    catch (_) { return trimInput(text).toLowerCase(); }
  };

  const extractEntities = (text) => {
    const raw = trimInput(text);
    const urls = raw.match(/https?:\/\/[^\s<>'"]+|www\.[^\s<>'"]+/gi) || [];
    const emails = raw.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi) || [];
    const phones = [];
    const phoneRe = /(?:\+?84|0)(?:[\s.-]*\d){9,10}|\+?[1-9](?:[\s.-]*\d){7,14}/g;
    let m;
    while ((m = phoneRe.exec(raw)) !== null) {
      const p = normalizePhone(m[0]);
      if (isPhone(p) && !phones.includes(p)) phones.push(p);
    }
    return { urls:[...new Set(urls.map(normalizeUrl))], emails:[...new Set(emails.map(e => e.toLowerCase()))], phones };
  };

  const analyzeScamText = (text) => {
    const raw = trimInput(text);
    const normalized = normalizeText(raw);
    let hits = 0;
    for (const re of IMAGE_SCAM_PATTERNS) if (re.test(raw) || re.test(normalized)) hits++;
    const brandHit = BRAND_TEXT_PATTERNS.test(raw) || BRAND_TEXT_PATTERNS.test(normalized);
    return { hits, brandHit, entities: extractEntities(raw) };
  };

  const scanImageFile = async (fileOrBlob) => {
    const out = { ocrText: '', qrText: '', entities: { urls: [], emails: [], phones: [] }, scamHits: 0, brandHit: false, ocrAvailable: false, qrAvailable: false };
    try {
      if (typeof BarcodeDetector !== 'undefined') {
        out.qrAvailable = true;
        const detector = new BarcodeDetector({ formats: ['qr_code'] });
        const bitmap = await createImageBitmap(fileOrBlob);
        const codes = await detector.detect(bitmap);
        if (bitmap && bitmap.close) bitmap.close();
        if (codes && codes[0] && codes[0].rawValue) out.qrText = codes[0].rawValue;
      }
    } catch (_) {}
    try {
      const T = root.Tesseract || (root.window && root.window.Tesseract);
      if (T && T.recognize) {
        out.ocrAvailable = true;
        const result = await T.recognize(fileOrBlob, 'vie+eng');
        out.ocrText = result && result.data && result.data.text ? result.data.text : '';
      }
    } catch (_) {}
    const text = [out.ocrText, out.qrText].filter(Boolean).join('\n');
    const analysis = analyzeScamText(text);
    out.entities = analysis.entities;
    out.scamHits = analysis.hits;
    out.brandHit = analysis.brandHit;
    return out;
  };

  const localScanTarget = (target) => {
    const result = {};
    const explanations = [];
    let risk = 0;
    const add = (key, level, text) => {
      result[key] = level === 'safe' ? '-1' : (level === 'danger' ? '1' : (level === 'suspicious' ? '2' : '0'));
      explanations.push({ key, level, text });
    };

    switch (target.type) {
      case 'email': {
        const domain = (target.value.split('@')[1] || '').toLowerCase();
        add('EmailFormat', 'safe', 'Email đúng định dạng.');
        if (TEMP_EMAIL_DOMAINS.has(domain)) { add('TempEmail', 'suspicious', 'Email dùng dịch vụ email tạm thời.'); risk += 22; }
        else if (/\b(gmail\.com|outlook\.com|yahoo\.com|icloud\.com|proton\.me)\b/i.test(domain)) {
          add('EmailProvider', 'safe', 'Nhà cung cấp email phổ biến.');
        } else {
          add('EmailProvider', 'warning', 'Email dùng tên miền riêng hoặc ít phổ biến.'); risk += 8;
        }
        if (/support|security|verify|admin|bank|otp/i.test(target.value)) {
          add('EmailImpersonation', 'warning', 'Email có từ khóa dễ dùng để giả mạo hỗ trợ hoặc bảo mật.'); risk += 12;
        }
        break;
      }
      case 'phone': {
        add('PhoneFormat', 'safe', 'Số điện thoại đúng định dạng.');
        if (/^(?:\+?84|0)(?:3|5|7|8|9)\d{8}$/.test(target.value)) {
          const local = target.value.replace(/^\+?84/, '0');
          const prefix = local.slice(0, 3);
          let carrier = '';
          if (/^(032|033|034|035|036|037|038|039|086|096|097|098)$/.test(prefix)) carrier = 'Viettel';
          else if (/^(070|076|077|078|079|089|090|093)$/.test(prefix)) carrier = 'MobiFone';
          else if (/^(081|082|083|084|085|088|091|094)$/.test(prefix)) carrier = 'VinaPhone';
          else if (/^(052|056|058|092)$/.test(prefix)) carrier = 'Vietnamobile';
          add('PhoneVN', 'safe', carrier ? `Số Việt Nam thuộc nhà mạng ${carrier}.` : 'Số điện thoại Việt Nam hợp lệ.');
        } else { add('PhoneInternational', 'warning', 'Số điện thoại quốc tế cần kiểm tra ngữ cảnh.'); risk += 6; }
        break;
      }

      case 'hash': {
        add('HashFormat', 'safe', 'Hash đúng định dạng.');
        add('HashReputation', 'warning', 'Cần đối chiếu hash với nguồn threat intelligence.'); risk += 10;
        break;
      }
      case 'ip': {
        add('IPFormat', 'safe', 'Địa chỉ IP đúng định dạng.');
        if (/^(10\.|127\.|172\.(1[6-9]|2\d|3[0-1])\.|192\.168\.)/.test(target.value)) add('PrivateIP', 'warning', 'IP thuộc dải nội bộ, không phải website công khai.');
        else { add('PublicIP', 'warning', 'Truy cập trực tiếp bằng IP cần kiểm tra uy tín hạ tầng.'); risk += 10; }
        break;
      }
      case 'file':
      case 'archive': {
        const fileName = target.displayValue || '';
        add('FileHash', target.value ? 'safe' : 'warning', target.value ? 'Đã tạo hash file.' : 'Chưa có hash file.');
        if (isArchiveName(fileName)) { add('ArchiveContainer', 'warning', 'File nén sẽ được xem như container chứa nhiều file.'); risk += 8; }
        if (isDangerousFileName(fileName)) { add('DangerousFileType', 'danger', 'Định dạng file có thể thực thi mã.'); risk += 35; }
        break;
      }
      case 'image': {
        const img = target.meta && target.meta.imageScan ? target.meta.imageScan : {};
        add('ImageInput', 'safe', 'Đã nhận diện ảnh để quét.');
        if (img.qrText) add('QRDetection', 'warning', 'Ảnh chứa QR Code.');
        if (img.ocrText) add('ImageOCR', 'safe', 'Đã trích xuất văn bản trong ảnh.');
        else add('ImageOCR', 'warning', img.ocrAvailable === false ? 'OCR local chưa khả dụng cho ảnh này.' : 'Ảnh cần OCR hoặc kiểm tra QR.');
        if (img.scamHits > 0) { add('ImageScamText', 'suspicious', 'Ảnh chứa nội dung thường gặp trong lừa đảo.'); risk += Math.min(28, 12 + img.scamHits * 5); }
        if (img.brandHit) { add('ImageBrandText', 'warning', 'Có dấu hiệu sử dụng thương hiệu ngân hàng hoặc ví điện tử.'); risk += 10; }
        const ent = img.entities || {};
        if ((ent.urls || []).length) add('ImageExtractedURL', 'warning', 'Ảnh chứa URL cần kiểm tra.');
        if ((ent.emails || []).length) add('ImageExtractedEmail', 'warning', 'Ảnh chứa email cần kiểm tra.');
        if ((ent.phones || []).length) add('ImageExtractedPhone', 'warning', 'Ảnh chứa số điện thoại cần kiểm tra.');
        break;
      }
      case 'text': {
        if (!target.value) { add('EmptyInput', 'warning', 'Không có dữ liệu để quét.'); risk += 5; break; }
        // Nhận diện văn bản chỉ là trạng thái xử lý, không phải tín hiệu an toàn.
        if (/otp|mat khau|mật khẩu|nhan thuong|nhận thưởng|viec nhe luong cao|việc nhẹ lương cao|kiem tien online|kiếm tiền online/i.test(target.value)) {
          add('ScamText', 'warning', 'Văn bản chứa từ khóa thường gặp trong lừa đảo.'); risk += 18;
        } else {
          add('TextInsufficient', 'warning', 'Văn bản chưa đủ dữ liệu để kết luận an toàn.'); risk += 4;
        }
        break;
      }
      default:
        add('GenericInput', 'safe', 'Đã nhận diện đối tượng quét.');
    }

    const finalScore = Math.max(0, 80 - risk);
    return makeResult({
      target,
      finalScore,
      riskScore: risk,
      summary: `${target.displayValue || target.value} đã được quét trong nền tảng AntiScam.`,
      result,
      explanations,
    });
  };

  const sha256ArrayBuffer = async (buffer) => {
    const digest = await crypto.subtle.digest('SHA-256', buffer);
    return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
  };

  root.AntiScamScanPlatform = {
    detectTarget,
    localScanTarget,
    sha256ArrayBuffer,
    isArchiveName,
    isDangerousFileName,
    normalizeUrl,
    extractEntities,
    analyzeScamText,
    scanImageFile,
    TEMP_EMAIL_DOMAINS,
    extOf,
  };
})(typeof self !== 'undefined' ? self : window);

/**
 * ANTISCAM VIETNAM — URL Intelligence Engine
 * Module 1: Phân tích URL chuyên sâu
 *
 * QUAN TRỌNG: File này là content script, KHÔNG dùng import/export (MV3 restriction).
 * Kết quả được gán vào window.antiScamURLIntel để features.js đọc.
 *
 * Các phân tích:
 *  1. Shannon Entropy Analysis
 *  2. Homograph / IDN Spoofing Detection
 *  3. Typosquatting Detection (Levenshtein Distance)
 *  4. Vietnam Brand Similarity
 *  5. Suspicious TLD Detection
 *  6. URL Shortener Detection
 *  7. Subdomain Abuse Detection
 *  8. Redirect Indicator
 *  9. Suspicious Keyword in URL
 * 10. Overall URL Risk Score
 */

(function () {
  'use strict';

  // ─────────────────────────────────────────────────────────────────────────────
  // DATABASE: Vietnam Brand Registry
  // ─────────────────────────────────────────────────────────────────────────────

  const VIETNAM_BRAND_DB = {
    vietcombank: {
      officialDomains: ['vietcombank.com.vn', 'vcb.com.vn', 'digibank.vietcombank.com.vn'],
      keywords: ['vietcombank', 'vcb', 'ngan-hang-ngoai-thuong', 'ngoai-thuong'],
      aliases: ['vietconbank', 'vietcombank', 'viet-com-bank', 'vietcombankk', 'vietcornbank'],
    },
    bidv: {
      officialDomains: ['bidv.com.vn', 'smartbanking.bidv.com.vn'],
      keywords: ['bidv', 'bank-for-investment'],
      aliases: ['biidv', 'bidvv', 'b1dv', 'bidv-vn'],
    },
    vietinbank: {
      officialDomains: ['vietinbank.vn', 'ipay.vietinbank.vn'],
      keywords: ['vietinbank', 'viettinbank', 'cong-thuong'],
      aliases: ['viettinbank', 'viettin-bank', 'vietinbankk'],
    },
    agribank: {
      officialDomains: ['agribank.com.vn', 'iagribank.agribank.com.vn'],
      keywords: ['agribank', 'nong-nghiep'],
      aliases: ['agri-bank', 'agribankk', 'agr1bank'],
    },
    mbbank: {
      officialDomains: ['mbbank.com.vn', 'app.mbbank.com.vn'],
      keywords: ['mbbank', 'mb-bank', 'quan-doi'],
      aliases: ['mb-bankk', 'mbbankk', 'mb_bank'],
    },
    techcombank: {
      officialDomains: ['techcombank.com.vn', 'f@st.techcombank.com.vn'],
      keywords: ['techcombank', 'techcom'],
      aliases: ['tech-com-bank', 'techcornbank', 'techcombank-vn'],
    },
    acb: {
      officialDomains: ['acb.com.vn', 'acbonline.acb.com.vn'],
      keywords: ['acb', 'a-chau'],
      aliases: ['acb-vn', 'acbbank', 'a-c-b'],
    },
    tpbank: {
      officialDomains: ['tpbank.vn', 'ebank.tpbank.vn'],
      keywords: ['tpbank', 'tien-phong'],
      aliases: ['tp-bank', 'tpbankk', 'tp_bank'],
    },
    vpbank: {
      officialDomains: ['vpbank.com.vn', 'online.vpbank.com.vn'],
      keywords: ['vpbank', 'viet-phuong'],
      aliases: ['vp-bank', 'vpbankk', 'vp_bank'],
    },
    sacombank: {
      officialDomains: ['sacombank.com', 'mbanking.sacombank.com'],
      keywords: ['sacombank', 'sai-gon-thuong-tin'],
      aliases: ['sacom-bank', 'sacombankk', 'sacombank-vn'],
    },
    momo: {
      officialDomains: ['momo.vn', 'mservice.com.vn', 'business.momo.vn'],
      keywords: ['momo', 'vi-momo', 'm_service'],
      aliases: ['momovn', 'mo-mo', 'momo-vn', 'momoxacminh', 'momo-xacminh', 'momo-verify'],
    },
    zalopay: {
      officialDomains: ['zalopay.vn', 'zalo.me'],
      keywords: ['zalopay', 'zalo-pay'],
      aliases: ['zalo-pay-vn', 'zalopayxacminh', 'zalopay-verification', 'zalopay-verify'],
    },
    vnpay: {
      officialDomains: ['vnpay.vn', 'sandbox.vnpayment.vn'],
      keywords: ['vnpay', 'vn-pay', 'vnpayment'],
      aliases: ['vn-pay-vn', 'vnpay-vn', 'vnpayy'],
    },
    shopee: {
      officialDomains: ['shopee.vn', 'seller.shopee.vn', 'spayseller.shopee.vn'],
      keywords: ['shopee', 'shopeepay'],
      aliases: ['shopee-vn', 'shopeee', 'sh0pee', 'shopee-congbo', 'shopee-ctvvn'],
    },
    lazada: {
      officialDomains: ['lazada.vn', 'seller.lazada.vn'],
      keywords: ['lazada'],
      aliases: ['lazada-vn', 'lazadaa', 'laz4da'],
    },
    tiki: {
      officialDomains: ['tiki.vn', 'tikivn.com'],
      keywords: ['tiki'],
      aliases: ['tiki-vn', 'tikii', 't1ki'],
    },
    vneid: {
      officialDomains: ['vneid.gov.vn', 'dichvucong.gov.vn'],
      keywords: ['vneid', 'can-cuoc-cong-dan', 'cccd'],
      aliases: ['vne1d', 'vn-eid', 'vneidgov'],
    },
    utt: {
      officialDomains: ['utt.edu.vn'],
      keywords: ['utt', 'dai-hoc-cong-nghe-giao-thong-van-tai'],
      aliases: ['uttvn', 'utt-vn'],
    },
  };

  // ─────────────────────────────────────────────────────────────────────────────
  // DATABASE: Suspicious TLDs
  // ─────────────────────────────────────────────────────────────────────────────

  const SUSPICIOUS_TLDS = new Set([
    '.xyz', '.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click',
    '.link', '.work', '.loan', '.win', '.gq', '.bid', '.trade',
    '.date', '.download', '.review', '.stream', '.faith', '.racing',
    '.science', '.party', '.webcam', '.country', '.kim', '.cricket',
    '.space', '.website', '.site', '.online', '.tech', '.store',
    '.live', '.press', '.fun', '.host', '.rocks', '.club', '.icu',
    '.vip', '.rest', '.network', '.digital',
  ]);

  // ─────────────────────────────────────────────────────────────────────────────
  // DATABASE: URL Shorteners
  // ─────────────────────────────────────────────────────────────────────────────

  const URL_SHORTENERS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly',
    'adf.ly', 'j.mp', 'is.gd', 'cli.gs', 'yfrog.com', 'migre.me',
    'ff.im', 'tiny.cc', 'url4.eu', 'twit.ac', 'su.pr', 'twurl.nl',
    'snipurl.com', 'short.to', 'BudURL.com', 'ping.fm', 'post.ly',
    'Just.as', 'bkite.com', 'snipr.com', 'fic.kr', 'loopt.us',
    'doiop.com', 'short.ie', 'kl.am', 'wp.me', 'rubyurl.com',
    'om.ly', 'to.ly', 'bit.do', 'lnkd.in', 'db.tt', 'qr.ae',
    'cutt.ly', 'rb.gy', 'shorturl.at',
  ]);

  // ─────────────────────────────────────────────────────────────────────────────
  // DATABASE: Scam Keywords in URL path/query
  // ─────────────────────────────────────────────────────────────────────────────

  const SCAM_URL_KEYWORDS = [
    // Banking/Auth
    'login', 'signin', 'secure', 'security', 'verify', 'verification',
    'xacminh', 'xac-minh', 'xacnhan', 'xac-nhan',
    'dangnhap', 'dang-nhap', 'matkhau', 'mat-khau',
    // OTP / 2FA
    'otp', 'otpverify', '2fa', 'twofactor',
    // Account
    'account', 'update-account', 'confirm', 'reactivate',
    'suspend', 'suspended', 'locked', 'unlock',
    'taikhoan', 'tai-khoan', 'khoitai', 'khoi-tai',
    // Financial
    'payment', 'banking', 'wallet', 'transfer',
    'thanhcoan', 'chuyentien', 'napthe',
    // Phishing triggers
    'free', 'lucky', 'winner', 'reward', 'prize', 'bonus',
    'mienthi', 'trungtuong', 'phanthuong',
    // Urgency
    'urgent', 'khancap', 'khan-cap', 'expire', 'hethan',
  ];

  // ─────────────────────────────────────────────────────────────────────────────
  // DATABASE: Homograph / IDN Lookalike character map
  // ─────────────────────────────────────────────────────────────────────────────

  const HOMOGRAPH_MAP = {
    // Cyrillic
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',
    'і': 'i', 'ь': 'b', 'у': 'y', 'В': 'B', 'М': 'M', 'Т': 'T',
    // Greek
    'α': 'a', 'ο': 'o', 'ρ': 'p', 'ν': 'v', 'κ': 'k', 'τ': 't',
    // Latin lookalikes
    'ⅼ': 'l', '｜': 'l', 'ı': 'i', 'ƅ': 'b',
    // Number substitutions in domains
    '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't',
    // Vietnamese similar
    'ạ': 'a', 'ả': 'a', 'ã': 'a', 'ầ': 'a', 'ấ': 'a',
  };

  // ─────────────────────────────────────────────────────────────────────────────
  // ALGORITHM 1: Shannon Entropy
  // Entropy cao → domain chứa nhiều ký tự ngẫu nhiên → suspicious
  // ─────────────────────────────────────────────────────────────────────────────

  function calculateEntropy(str) {
    if (!str || str.length === 0) return 0;
    const freq = {};
    for (const ch of str) {
      freq[ch] = (freq[ch] || 0) + 1;
    }
    let entropy = 0;
    const len = str.length;
    for (const ch in freq) {
      const p = freq[ch] / len;
      entropy -= p * Math.log2(p);
    }
    return Math.round(entropy * 100) / 100;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // ALGORITHM 2: Levenshtein Distance
  // Dùng để phát hiện typosquatting
  // ─────────────────────────────────────────────────────────────────────────────

  function levenshtein(a, b) {
    if (!a) return b.length;
    if (!b) return a.length;
    const m = a.length;
    const n = b.length;
    const dp = Array.from({ length: m + 1 }, (_, i) =>
      Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
    );
    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        if (a[i - 1] === b[j - 1]) {
          dp[i][j] = dp[i - 1][j - 1];
        } else {
          dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
        }
      }
    }
    return dp[m][n];
  }

  function similarityScore(a, b) {
    const maxLen = Math.max(a.length, b.length);
    if (maxLen === 0) return 1.0;
    return 1.0 - levenshtein(a, b) / maxLen;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // ALGORITHM 3: Homograph Normalization
  // Chuyển ký tự giả về ký tự thật để so sánh
  // ─────────────────────────────────────────────────────────────────────────────

  function normalizeHomograph(str) {
    let normalized = '';
    for (const ch of str) {
      normalized += HOMOGRAPH_MAP[ch] || ch;
    }
    return normalized;
  }

  function detectHomograph(domain) {
    // Check if domain contains non-ASCII characters
    const hasNonASCII = /[^\x00-\x7F]/.test(domain);
    // Check if normalization changes the domain (homograph substitution)
    const normalized = normalizeHomograph(domain);
    const hasSubstitution = normalized !== domain && /^[a-z0-9.-]+$/.test(normalized);
    return {
      detected: hasNonASCII || hasSubstitution,
      normalizedDomain: normalized,
      originalDomain: domain,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // ALGORITHM 4: Typosquatting & Brand Similarity
  // ─────────────────────────────────────────────────────────────────────────────

  function detectTyposquatting(hostname) {
    // Remove www and TLD for comparison
    const cleanHost = hostname
      .replace(/^www\./, '')
      .replace(/\.(com\.vn|net\.vn|org\.vn|edu\.vn|gov\.vn|com|net|org|vn|xyz|top|click|link|info|io)$/, '')
      .toLowerCase();

    const normalizedHost = normalizeHomograph(cleanHost);

    let bestMatch = null;
    let bestScore = 0;
    let bestBrand = null;
    let isOfficialDomain = false;

    for (const [brandName, brandData] of Object.entries(VIETNAM_BRAND_DB)) {
      // Kiểm tra official domains trước
      for (const official of brandData.officialDomains) {
        if (hostname === official || hostname.endsWith('.' + official)) {
          isOfficialDomain = true;
          break;
        }
      }
      if (isOfficialDomain) break;

      // Check known aliases (domain giả mạo đã biết)
      for (const alias of (brandData.aliases || [])) {
        if (normalizedHost.includes(alias) || cleanHost.includes(alias)) {
          bestMatch = alias;
          bestScore = 0.95;
          bestBrand = brandName;
          break;
        }
      }

      if (bestScore >= 0.95) break;

      // Levenshtein vs brand name
      const scoreDirect = similarityScore(normalizedHost, brandName);
      if (scoreDirect > bestScore) {
        bestScore = scoreDirect;
        bestBrand = brandName;
        bestMatch = brandName;
      }

      // Check if brand name is embedded in domain (e.g. "vietcombank-login.net")
      if (normalizedHost.includes(brandName) || cleanHost.includes(brandName)) {
        const embedScore = 0.90;
        if (embedScore > bestScore) {
          bestScore = embedScore;
          bestBrand = brandName;
          bestMatch = brandName + ' (embedded)';
        }
      }
    }

    // Threshold: chỉ flag nếu similarity >= 0.70 và KHÔNG phải official domain
    const isTyposquatting = !isOfficialDomain && bestScore >= 0.70;

    return {
      isOfficialDomain,
      isTyposquatting,
      targetBrand: isTyposquatting ? bestBrand : null,
      similarity: Math.round(bestScore * 100) / 100,
      matchedPattern: isTyposquatting ? bestMatch : null,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // ALGORITHM 5: Suspicious TLD Check
  // ─────────────────────────────────────────────────────────────────────────────

  function detectSuspiciousTLD(hostname) {
    // Extract TLD (last part after last dot)
    const parts = hostname.split('.');
    if (parts.length < 2) return { suspicious: false, tld: '' };

    // Handle compound TLDs like .com.vn
    let tld;
    if (parts.length >= 3 && ['com', 'net', 'org', 'edu', 'gov'].includes(parts[parts.length - 2])) {
      tld = '.' + parts[parts.length - 2] + '.' + parts[parts.length - 1];
    } else {
      tld = '.' + parts[parts.length - 1];
    }

    return {
      suspicious: SUSPICIOUS_TLDS.has(tld),
      tld,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // ALGORITHM 6: URL Shortener Detection
  // ─────────────────────────────────────────────────────────────────────────────

  function detectURLShortener(hostname) {
    const cleanHost = hostname.replace(/^www\./, '');
    return {
      isShortened: URL_SHORTENERS.has(cleanHost),
      shortener: URL_SHORTENERS.has(cleanHost) ? cleanHost : null,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // ALGORITHM 7: Subdomain Abuse Detection
  // Pattern: login.vietcombank.evil.com → sử dụng brand làm subdomain
  // ─────────────────────────────────────────────────────────────────────────────

  function detectSubdomainAbuse(hostname) {
    const parts = hostname.split('.');
    if (parts.length <= 2) return { detected: false };

    // Lấy tất cả subdomains (trừ TLD và domain chính)
    const subdomains = parts.slice(0, -2).join('.');
    const rootDomain = parts.slice(-2).join('.');

    // Kiểm tra xem subdomain có chứa brand name không,
    // trong khi root domain không phải official
    const findings = [];
    for (const [brandName, brandData] of Object.entries(VIETNAM_BRAND_DB)) {
      const isOfficialRoot = brandData.officialDomains.some(d => {
        const officialRoot = d.split('.').slice(-2).join('.');
        return rootDomain === officialRoot;
      });

      if (!isOfficialRoot) {
        // Check if brand appears in subdomain
        if (subdomains.includes(brandName) ||
          brandData.keywords.some(kw => subdomains.includes(kw))) {
          findings.push({
            brand: brandName,
            subdomain: subdomains,
            rootDomain,
          });
        }
      }
    }

    return {
      detected: findings.length > 0,
      findings,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // ALGORITHM 8: Suspicious URL Path/Query Keywords
  // ─────────────────────────────────────────────────────────────────────────────

  function detectSuspiciousKeywords(fullUrl) {
    const urlLower = fullUrl.toLowerCase();
    // Chỉ kiểm tra path + query, không kiểm tra domain (để tránh false positive)
    let pathAndQuery = '';
    try {
      const urlObj = new URL(fullUrl);
      pathAndQuery = (urlObj.pathname + urlObj.search).toLowerCase();
    } catch (e) {
      pathAndQuery = urlLower;
    }

    const found = SCAM_URL_KEYWORDS.filter(kw => pathAndQuery.includes(kw));
    return {
      detected: found.length > 0,
      keywords: found,
      count: found.length,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // ALGORITHM 9: Redirect Chain / Multi-slash Redirect
  // ─────────────────────────────────────────────────────────────────────────────

  function detectRedirectIndicators(fullUrl) {
    const indicators = [];

    // Double-slash redirect (http://legit.com//evil.com/...)
    if (fullUrl.replace('://', '').includes('//')) {
      indicators.push('double-slash-redirect');
    }

    // URL in query param (classic open redirect)
    try {
      const urlObj = new URL(fullUrl);
      for (const [key, value] of urlObj.searchParams) {
        if (/^https?:\/\//i.test(value)) {
          indicators.push('url-in-query-param:' + key);
        }
      }
      // Suspicious param names
      const suspiciousParams = ['redirect', 'return', 'url', 'goto', 'next', 'target', 'link'];
      for (const param of suspiciousParams) {
        if (urlObj.searchParams.has(param)) {
          indicators.push('suspicious-param:' + param);
        }
      }
    } catch (e) { /* ignore */ }

    // @ symbol in URL (user@host trick)
    if (fullUrl.includes('@')) {
      indicators.push('at-symbol-in-url');
    }

    return {
      detected: indicators.length > 0,
      indicators,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // SCORING ENGINE
  // Tính URL Risk Score từ 0-100
  // ─────────────────────────────────────────────────────────────────────────────

  function calculateURLScore(analysis) {
    let score = 0;

    // Entropy: cao → suspicious
    if (analysis.entropy > 4.5) score += 20;
    else if (analysis.entropy > 3.8) score += 10;

    // Homograph
    if (analysis.homograph.detected) score += 30;

    // Typosquatting — nặng nhất
    if (analysis.typosquatting.isTyposquatting) {
      score += Math.round(analysis.typosquatting.similarity * 40);
    }

    // Suspicious TLD
    if (analysis.suspiciousTLD.suspicious) score += 20;

    // URL Shortener
    if (analysis.urlShortener.isShortened) score += 15;

    // Subdomain abuse
    if (analysis.subdomainAbuse.detected) score += 25;

    // Suspicious keywords in URL
    score += Math.min(analysis.suspiciousKeywords.count * 5, 20);

    // Redirect indicators
    if (analysis.redirectIndicators.detected) {
      score += analysis.redirectIndicators.indicators.length * 8;
    }

    // Official domain bonus (reduce score)
    if (analysis.typosquatting.isOfficialDomain) {
      score = Math.max(0, score - 50);
    }

    return Math.min(100, score);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // AI EXPLANATION GENERATOR
  // Tạo giải thích bằng tiếng Việt dựa trên kết quả phân tích
  // ─────────────────────────────────────────────────────────────────────────────

  function generateURLExplanation(analysis) {
    const sentences = [];

    if (analysis.typosquatting.isOfficialDomain) {
      sentences.push('✅ Tên miền này là tên miền chính thức đã được xác minh.');
      return sentences.join(' ');
    }

    if (analysis.typosquatting.isTyposquatting) {
      const brand = analysis.typosquatting.targetBrand.toUpperCase();
      const sim = Math.round(analysis.typosquatting.similarity * 100);
      sentences.push(
        `⚠️ Tên miền có độ tương đồng ${sim}% với thương hiệu ${brand}.`
      );
    }

    if (analysis.subdomainAbuse.detected) {
      const finding = analysis.subdomainAbuse.findings[0];
      sentences.push(
        `🚨 Tên miền sử dụng "${finding.brand}" làm subdomain để giả mạo — đây là kỹ thuật phishing phổ biến.`
      );
    }

    if (analysis.homograph.detected) {
      sentences.push('🔤 Tên miền chứa ký tự giả mạo (Unicode lookalike) để đánh lừa người dùng.');
    }

    if (analysis.suspiciousTLD.suspicious) {
      sentences.push(
        `📛 Tên miền sử dụng TLD đáng ngờ "${analysis.suspiciousTLD.tld}" — thường được dùng để tạo trang lừa đảo miễn phí.`
      );
    }

    if (analysis.urlShortener.isShortened) {
      sentences.push(
        `🔗 URL được rút ngắn qua "${analysis.urlShortener.shortener}" — che giấu địa chỉ thực sự.`
      );
    }

    if (analysis.suspiciousKeywords.detected && analysis.suspiciousKeywords.keywords.length > 0) {
      const kws = analysis.suspiciousKeywords.keywords.slice(0, 3).join('", "');
      sentences.push(`🔑 URL chứa từ khóa nhạy cảm: "${kws}".`);
    }

    if (analysis.redirectIndicators.detected) {
      sentences.push('↩️ URL có dấu hiệu chuyển hướng ẩn — có thể đang cố dẫn đến trang độc hại.');
    }

    if (analysis.entropy > 4.5) {
      sentences.push('🎲 Chuỗi tên miền có độ ngẫu nhiên cao — thường thấy ở domain tự động sinh.');
    }

    if (sentences.length === 0) {
      sentences.push('✅ URL không có dấu hiệu đáng ngờ.');
    }

    return sentences.join(' ');
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // MAIN ANALYSIS FUNCTION
  // ─────────────────────────────────────────────────────────────────────────────

  function analyzeURL(fullUrl) {
    let hostname = '';
    try {
      hostname = new URL(fullUrl).hostname.toLowerCase();
    } catch (e) {
      hostname = fullUrl.toLowerCase();
    }

    const entropy = calculateEntropy(hostname);
    const homograph = detectHomograph(hostname);
    const typosquatting = detectTyposquatting(hostname);
    const suspiciousTLD = detectSuspiciousTLD(hostname);
    const urlShortener = detectURLShortener(hostname);
    const subdomainAbuse = detectSubdomainAbuse(hostname);
    const suspiciousKeywords = detectSuspiciousKeywords(fullUrl);
    const redirectIndicators = detectRedirectIndicators(fullUrl);

    const analysis = {
      hostname,
      entropy,
      homograph,
      typosquatting,
      suspiciousTLD,
      urlShortener,
      subdomainAbuse,
      suspiciousKeywords,
      redirectIndicators,
    };

    const score = calculateURLScore(analysis);
    const explanation = generateURLExplanation(analysis);

    return {
      ...analysis,
      score,
      explanation,
      riskLevel: score >= 80 ? 'CRITICAL' :
        score >= 60 ? 'HIGH' :
          score >= 40 ? 'MEDIUM' :
            score >= 20 ? 'LOW' : 'SAFE',
    };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // EXECUTE & EXPORT
  // Chạy ngay khi script được load (content script context)
  // ─────────────────────────────────────────────────────────────────────────────

  const currentUrl = window.location.href;
  const result = analyzeURL(currentUrl);

  // Export sang global để features.js đọc
  window.antiScamURLIntel = result;

  // Console debug (chỉ hiện trong dev mode)
  // eslint-disable-next-line no-console
  console.debug('[AntiScam] URL Intel:', JSON.stringify({
    hostname: result.hostname,
    score: result.score,
    riskLevel: result.riskLevel,
    typosquatting: result.typosquatting.isTyposquatting ? result.typosquatting.targetBrand : false,
    suspiciousTLD: result.suspiciousTLD.suspicious ? result.suspiciousTLD.tld : false,
  }));

})();

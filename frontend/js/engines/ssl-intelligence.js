/**
 * ANTISCAM VIETNAM — SSL Intelligence Engine
 * Module 3: Phân tích chứng chỉ SSL
 *
 * Chạy trong background.js (service worker).
 * Export qua global `self.SSLIntelligence`.
 *
 * Nguồn dữ liệu:
 *  - crt.sh (Certificate Transparency logs): không cần API key
 *  - Header analysis qua fetch
 *
 * Phân tích:
 *  - Giao thức HTTP vs HTTPS
 *  - Tuổi chứng chỉ SSL (cert mới toanh → suspicious)
 *  - Nhiều cert mới được tạo cho domain lạ → phishing
 *  - Issuer phổ biến của free cert (Let's Encrypt) vs EV cert
 *  - Brand mismatch: cert issued cho domain khác
 */

/* global chrome */

(function (global) {
  'use strict';

  // ─────────────────────────────────────────────────────────────────────────────
  // DATABASE: Trusted CA (Certificate Authorities)
  // ─────────────────────────────────────────────────────────────────────────────

  // CA cho EV certs (Extended Validation) → cao cấp, khó giả
  const EV_ISSUERS = new Set([
    'digicert', 'sectigo', 'entrust', 'globalsign', 'comodo',
    'geotrust', 'thawte', 'symantec', 'verizon', 'ssl.com',
  ]);

  // CA cho free/DV certs → dễ dùng cho phishing
  const FREE_ISSUERS = new Set([
    "let's encrypt", 'zerossl', 'buypass', 'google trust services',
    'ssl for free', 'cloudflare', 'cpanel', 'cPanel',
  ]);

  // ─────────────────────────────────────────────────────────────────────────────
  // CACHE
  // ─────────────────────────────────────────────────────────────────────────────

  // ─── FIX: In-memory Map cache (L1) trước chrome.storage (L2)
  const _sslMemCache = new Map();

  const CACHE_KEY = 'antiScamSSLCache';
  const CACHE_TTL_MS = 12 * 60 * 60 * 1000; // 12 giờ

  async function getCachedSSLData(domain) {
    // L1: Check in-memory first (0ms)
    const memEntry = _sslMemCache.get(domain);
    if (memEntry && (Date.now() - memEntry.timestamp) < CACHE_TTL_MS) {
      return memEntry.data;
    }
    // L2: Fallback to chrome.storage
    return new Promise((resolve) => {
      chrome.storage.local.get([CACHE_KEY], (items) => {
        const cache = items[CACHE_KEY] || {};
        const entry = cache[domain];
        if (entry && (Date.now() - entry.timestamp) < CACHE_TTL_MS) {
          _sslMemCache.set(domain, entry); // Backfill L1
          resolve(entry.data);
        } else {
          resolve(null);
        }
      });
    });
  }

  async function setCachedSSLData(domain, data) {
    const entry = { data, timestamp: Date.now() };
    // L1: Write immediately
    _sslMemCache.set(domain, entry);
    if (_sslMemCache.size > 200) {
      _sslMemCache.delete(_sslMemCache.keys().next().value);
    }
    // L2: Persist to chrome.storage
    return new Promise((resolve) => {
      chrome.storage.local.get([CACHE_KEY], (items) => {
        const cache = items[CACHE_KEY] || {};
        cache[domain] = entry;
        const keys = Object.keys(cache);
        if (keys.length > 200) delete cache[keys[0]];
        chrome.storage.local.set({ [CACHE_KEY]: cache }, resolve);
      });
    });
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // crt.sh API: Certificate Transparency Log
  // ─────────────────────────────────────────────────────────────────────────────

  async function fetchWithTimeout(resource, options = {}) {
    const { timeout = 3000 } = options;
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    const response = await fetch(resource, {
      ...options,
      signal: controller.signal
    });
    clearTimeout(id);
    return response;
  }

  async function fetchCertificates(domain) {
    try {
      const url = `https://crt.sh/?q=%25.${domain}&output=json`;
      const response = await fetchWithTimeout(url, {
        timeout: 2500,
        headers: { 'Accept': 'application/json' },
      });
      if (!response.ok) return null;
      const certs = await response.json();
      return Array.isArray(certs) ? certs : null;
    } catch (_e) {
      return null;
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // ANALYZER
  // ─────────────────────────────────────────────────────────────────────────────

  function analyzeCertificates(domain, certs, hasHTTPS) {
    const now = Date.now();
    let score = 0;
    const flags = [];

    // No HTTPS at all
    if (!hasHTTPS) {
      return {
        domain,
        hasSSL: false,
        certCount: 0,
        newestCertAge: null,
        issuer: null,
        isEV: false,
        isFree: false,
        brandMismatch: false,
        riskLevel: 'HIGH',
        score: 50,
        flags: ['NO_HTTPS'],
        explanation: '🔴 Website không sử dụng HTTPS — kết nối không được mã hóa, thông tin bạn nhập có thể bị đánh cắp.',
      };
    }

    if (!certs || certs.length === 0) {
      // HTTPS nhưng không có cert trong CT log → self-signed hoặc mới tạo
      return {
        domain,
        hasSSL: true,
        certCount: 0,
        newestCertAge: null,
        issuer: null,
        isEV: false,
        isFree: false,
        brandMismatch: false,
        riskLevel: 'MEDIUM',
        score: 25,
        flags: ['CERT_NOT_IN_CT_LOG'],
        explanation: '⚠️ Không tìm thấy chứng chỉ SSL trong Certificate Transparency Log — có thể là chứng chỉ tự ký.',
      };
    }

    // Sort by issue date (newest first)
    const sortedCerts = certs
      .filter(c => c.not_before)
      .sort((a, b) => new Date(b.not_before) - new Date(a.not_before));

    const newestCert = sortedCerts[0];
    const newestCertDate = newestCert ? new Date(newestCert.not_before) : null;
    const newestCertAge = newestCertDate
      ? Math.floor((now - newestCertDate.getTime()) / (1000 * 60 * 60 * 24))
      : null;

    // Issuer analysis
    const issuer = newestCert ? (newestCert.issuer_name || newestCert.issuer_ca_id || '') : '';
    const issuerLower = issuer.toString().toLowerCase();
    const isEV = [...EV_ISSUERS].some(ev => issuerLower.includes(ev));
    const isFree = [...FREE_ISSUERS].some(f => issuerLower.includes(f));

    // Cert age risk
    if (newestCertAge !== null) {
      if (newestCertAge < 3) {
        score += 40;
        flags.push('CERT_VERY_NEW');      // < 3 ngày
      } else if (newestCertAge < 14) {
        score += 25;
        flags.push('CERT_NEW');           // < 2 tuần
      } else if (newestCertAge < 30) {
        score += 10;
        flags.push('CERT_RECENT');        // < 30 ngày
      }
    }

    // Many recent certs for same domain → suspicious rotation
    const certsLast30Days = sortedCerts.filter(c => {
      const age = Math.floor((now - new Date(c.not_before).getTime()) / (1000 * 60 * 60 * 24));
      return age < 30;
    });
    if (certsLast30Days.length > 3) {
      score += 20;
      flags.push('CERT_ROTATION_SUSPICIOUS');
    }

    // Free cert alone isn't risky, but combined with other factors
    if (isFree) {
      score += 5;
      flags.push('FREE_CERT');
    }

    // EV cert is positive signal
    if (isEV) {
      score = Math.max(0, score - 20);
      flags.push('EV_CERT');
    }

    // Brand Mismatch: cert common name vs actual domain
    let brandMismatch = false;
    if (newestCert && newestCert.common_name) {
      const certCN = newestCert.common_name.replace('*.', '').toLowerCase();
      const domainRoot = domain.replace(/^www\./, '');
      // If cert CN doesn't match domain root at all
      if (certCN && !domainRoot.includes(certCN) && !certCN.includes(domainRoot)) {
        brandMismatch = true;
        score += 30;
        flags.push('BRAND_MISMATCH');
      }
    }

    score = Math.min(100, score);

    const riskLevel = score >= 80 ? 'CRITICAL' :
      score >= 60 ? 'HIGH' :
        score >= 40 ? 'MEDIUM' :
          score >= 20 ? 'LOW' : 'SAFE';

    return {
      domain,
      hasSSL: true,
      certCount: certs.length,
      newestCertAge,
      issuer: issuer.toString().substring(0, 100),
      isEV,
      isFree,
      brandMismatch,
      riskLevel,
      score,
      flags,
      explanation: generateSSLExplanation(newestCertAge, issuer, isEV, isFree, brandMismatch, flags),
    };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // AI EXPLANATION
  // ─────────────────────────────────────────────────────────────────────────────

  function generateSSLExplanation(certAge, issuer, isEV, isFree, brandMismatch, flags) {
    const sentences = [];

    if (flags.includes('NO_HTTPS')) {
      return '🔴 Website không sử dụng HTTPS — thông tin bạn nhập hoàn toàn không được bảo vệ.';
    }

    if (flags.includes('CERT_NOT_IN_CT_LOG')) {
      return '⚠️ Chứng chỉ SSL không có trong nhật ký minh bạch — có thể là chứng chỉ tự ký hoặc mới tạo chưa được ghi nhận.';
    }

    if (certAge !== null) {
      if (certAge < 3) {
        sentences.push(`🚨 Chứng chỉ SSL chỉ mới được cấp ${certAge} ngày trước — đây là dấu hiệu của trang lừa đảo vừa được tạo.`);
      } else if (certAge < 14) {
        sentences.push(`⚠️ Chứng chỉ SSL được cấp ${certAge} ngày trước — còn rất mới.`);
      } else if (certAge < 30) {
        sentences.push(`ℹ️ Chứng chỉ SSL được cấp ${certAge} ngày trước.`);
      } else {
        sentences.push(`✅ Chứng chỉ SSL đã tồn tại ${certAge} ngày.`);
      }
    }

    if (flags.includes('CERT_ROTATION_SUSPICIOUS')) {
      sentences.push('🔄 Phát hiện nhiều chứng chỉ mới được tạo trong 30 ngày gần đây — có thể đang xoay vòng để tránh bị chặn.');
    }

    if (brandMismatch) {
      sentences.push('🚨 Tên trong chứng chỉ SSL không khớp với tên miền hiện tại — dấu hiệu giả mạo.');
    }

    if (isEV) {
      sentences.push('✅ Chứng chỉ SSL loại Extended Validation (EV) — yêu cầu xác minh danh tính chủ sở hữu nghiêm ngặt.');
    } else if (isFree) {
      sentences.push('ℹ️ Sử dụng chứng chỉ SSL miễn phí — có thể được tạo tự động trong vài phút.');
    }

    if (sentences.length === 0) {
      sentences.push('✅ Chứng chỉ SSL không có dấu hiệu đáng ngờ.');
    }

    return sentences.join(' ');
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // MAIN PUBLIC API
  // ─────────────────────────────────────────────────────────────────────────────

  /**
   * @param {string} domain - tên miền
   * @param {boolean} hasHTTPS - trang có dùng HTTPS không
   * @returns {Promise<object>}
   */
  async function analyzeSSL(domain, hasHTTPS) {
    if (!domain) {
      return { domain, score: 0, riskLevel: 'SAFE', flags: [], explanation: '' };
    }

    const cleanDomain = domain.replace(/^www\./, '');

    // Check cache
    const cacheKey = `${cleanDomain}_${hasHTTPS}`;
    const cached = await getCachedSSLData(cacheKey);
    if (cached) return { ...cached, fromCache: true };

    // Fetch cert data
    const certs = hasHTTPS ? await fetchCertificates(cleanDomain) : null;
    const result = analyzeCertificates(cleanDomain, certs, hasHTTPS);

    await setCachedSSLData(cacheKey, result);
    return result;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // EXPORT
  // ─────────────────────────────────────────────────────────────────────────────

  global.SSLIntelligence = { analyzeSSL };

})(typeof self !== 'undefined' ? self : this);

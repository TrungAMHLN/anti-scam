/**
 * ANTISCAM VIETNAM — Domain Intelligence Engine
 * Module 2: Phân tích thông tin tên miền (Domain Age, Registrar, Risk)
 *
 * QUAN TRỌNG: File này chạy trong background.js (service worker context).
 * Không dùng import/export. Export qua global `self.DomainIntelligence`.
 *
 * Nguồn dữ liệu:
 *  - RDAP (rdap.org): domain age, registrar — CORS-friendly
 *  - Heuristic fallback nếu API fail
 *
 * Đánh giá rủi ro theo domain age:
 *  < 7 ngày   → CRITICAL
 *  < 30 ngày  → HIGH
 *  < 90 ngày  → MEDIUM
 *  < 365 ngày → LOW
 *  ≥ 365 ngày → SAFE
 */

/* global chrome */

(function (global) {
  'use strict';

  // ─────────────────────────────────────────────────────────────────────────────
  // DATABASE: Risky registrars thường dùng cho scam domains
  // ─────────────────────────────────────────────────────────────────────────────

  const RISKY_REGISTRARS = new Set([
    'namecheap', 'godaddy', 'publicdomainregistry', 'resellerclub',
    'hostinger', 'namesiло', '101domain', 'namesilo',
    'internet.bs', 'dynadot', 'epik', 'porkbun',
  ]);

  // Registrars được dùng nhiều bởi legitimate VN businesses
  const TRUSTED_REGISTRARS = new Set([
    'vnpt', 'viettel', 'fpt', 'matbao', 'tenten', 'pa vietnam',
    'mắt bão', 'nhân hòa', 'inet', 'vn-internet', 'pavietnam',
  ]);

  // ─────────────────────────────────────────────────────────────────────────────
  // DATABASE: Suspicious Nameserver patterns
  // ─────────────────────────────────────────────────────────────────────────────

  const BULLETPROOF_HOSTING_NS = [
    'njalla', 'privacyguardian', 'whoisguard',
    'privacyprotect', 'domainsbyproxy',
  ];

  // ─────────────────────────────────────────────────────────────────────────────
  // CACHE: Tránh gọi API liên tục
  // ─────────────────────────────────────────────────────────────────────────────

  // ─── FIX: In-memory Map cache (L1) trước chrome.storage (L2)
  // Mục tiêu: domain đã scan không tốn thêm 1 async round-trip nào
  const _memCache = new Map();

  const CACHE_KEY = 'antiScamDomainCache';
  const CACHE_TTL_MS = 6 * 60 * 60 * 1000; // 6 giờ

  async function getCachedDomainData(domain) {
    // L1: Check in-memory first (sync, 0ms)
    const memEntry = _memCache.get(domain);
    if (memEntry && (Date.now() - memEntry.timestamp) < CACHE_TTL_MS) {
      return memEntry.data;
    }
    // L2: Fallback to chrome.storage
    return new Promise((resolve) => {
      chrome.storage.local.get([CACHE_KEY], (items) => {
        const cache = items[CACHE_KEY] || {};
        const entry = cache[domain];
        if (entry && (Date.now() - entry.timestamp) < CACHE_TTL_MS) {
          // Backfill L1
          _memCache.set(domain, entry);
          resolve(entry.data);
        } else {
          resolve(null);
        }
      });
    });
  }

  async function setCachedDomainData(domain, data) {
    const entry = { data, timestamp: Date.now() };
    // L1: Write to memory immediately
    _memCache.set(domain, entry);
    // Limit memory cache size
    if (_memCache.size > 200) {
      _memCache.delete(_memCache.keys().next().value);
    }
    // L2: Write to chrome.storage asynchronously (non-blocking)
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
  // RDAP API Lookup
  // RDAP là chuẩn ICANN mở, không cần API key, hỗ trợ CORS
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

  async function fetchRDAPData(domain) {
    // Thử nhiều RDAP endpoints
    const endpoints = [
      `https://rdap.org/domain/${domain}`,
      `https://rdap.iana.org/domain/${domain}`,
    ];

    for (const url of endpoints) {
      try {
        const response = await fetchWithTimeout(url, { timeout: 2500 });
        if (response.ok) {
          return await response.json();
        }
      } catch (_e) {
        // Thử endpoint tiếp theo
      }
    }
    return null;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // PARSER: Trích xuất thông tin từ RDAP response
  // ─────────────────────────────────────────────────────────────────────────────

  function parseRDAPResponse(rdapData) {
    if (!rdapData) return null;

    let registrationDate = null;
    let expirationDate = null;
    let lastChangedDate = null;
    let registrar = null;
    let nameservers = [];
    let status = [];

    // Parse events để lấy ngày
    if (rdapData.events && Array.isArray(rdapData.events)) {
      for (const event of rdapData.events) {
        if (event.eventAction === 'registration') {
          registrationDate = new Date(event.eventDate);
        } else if (event.eventAction === 'expiration') {
          expirationDate = new Date(event.eventDate);
        } else if (event.eventAction === 'last changed') {
          lastChangedDate = new Date(event.eventDate);
        }
      }
    }

    // Parse registrar từ entities
    if (rdapData.entities && Array.isArray(rdapData.entities)) {
      for (const entity of rdapData.entities) {
        if (entity.roles && entity.roles.includes('registrar')) {
          if (entity.vcardArray && entity.vcardArray[1]) {
            for (const vcard of entity.vcardArray[1]) {
              if (vcard[0] === 'fn') {
                registrar = vcard[3];
                break;
              }
            }
          }
          if (!registrar && entity.publicIds) {
            for (const pid of entity.publicIds) {
              if (pid.type === 'IANA Registrar ID') {
                registrar = `IANA-${pid.identifier}`;
              }
            }
          }
        }
      }
    }

    // Parse nameservers
    if (rdapData.nameservers && Array.isArray(rdapData.nameservers)) {
      nameservers = rdapData.nameservers.map(ns =>
        (ns.ldhName || ns.unicodeName || '').toLowerCase()
      );
    }

    // Parse status
    if (rdapData.status && Array.isArray(rdapData.status)) {
      status = rdapData.status;
    }

    return { registrationDate, expirationDate, lastChangedDate, registrar, nameservers, status };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // ANALYSIS: Tính toán risk từ domain data
  // ─────────────────────────────────────────────────────────────────────────────

  function analyzeDomainData(domain, parsedData) {
    const now = Date.now();
    let score = 0;
    const flags = [];
    const details = {};

    if (!parsedData) {
      // Không lấy được data → không thể verify → tăng điểm nghi ngờ nhẹ
      return {
        domain,
        ageInDays: null,
        registrar: null,
        registrationDate: null,
        expirationDate: null,
        nameservers: [],
        riskLevel: 'MEDIUM',
        score: 30,
        flags: ['RDAP_UNAVAILABLE'],
        explanation: '⚠️ Không thể xác minh thông tin tên miền từ cơ sở dữ liệu WHOIS/RDAP.',
      };
    }

    // --- Domain Age ---
    let ageInDays = null;
    if (parsedData.registrationDate && !isNaN(parsedData.registrationDate)) {
      ageInDays = Math.floor((now - parsedData.registrationDate.getTime()) / (1000 * 60 * 60 * 24));
      details.ageInDays = ageInDays;

      if (ageInDays < 7) {
        score += 60;
        flags.push('DOMAIN_AGE_CRITICAL');  // < 7 ngày
      } else if (ageInDays < 30) {
        score += 45;
        flags.push('DOMAIN_AGE_HIGH');      // < 30 ngày
      } else if (ageInDays < 90) {
        score += 30;
        flags.push('DOMAIN_AGE_MEDIUM');    // < 90 ngày
      } else if (ageInDays < 365) {
        score += 15;
        flags.push('DOMAIN_AGE_LOW');       // < 1 năm
      }
      // >= 365 ngày: không cộng điểm
    }

    // --- Registrar Risk ---
    if (parsedData.registrar) {
      const registrarLower = parsedData.registrar.toLowerCase();
      const isRisky = [...RISKY_REGISTRARS].some(r => registrarLower.includes(r));
      const isTrusted = [...TRUSTED_REGISTRARS].some(r => registrarLower.includes(r));

      if (isRisky && !isTrusted) {
        score += 10;
        flags.push('RISKY_REGISTRAR');
      }
      if (isTrusted) {
        score = Math.max(0, score - 10);
        flags.push('TRUSTED_REGISTRAR');
      }
    }

    // --- Nameserver Analysis ---
    if (parsedData.nameservers && parsedData.nameservers.length > 0) {
      const nsList = parsedData.nameservers;
      const hasBulletproof = nsList.some(ns =>
        BULLETPROOF_HOSTING_NS.some(bph => ns.includes(bph))
      );
      if (hasBulletproof) {
        score += 20;
        flags.push('BULLETPROOF_HOSTING_NS');
      }
      // Privacy nameservers (che thông tin chủ sở hữu)
      const hasPrivacyNS = nsList.some(ns =>
        ns.includes('privacy') || ns.includes('whoisguard') || ns.includes('protect')
      );
      if (hasPrivacyNS) {
        score += 10;
        flags.push('PRIVACY_NAMESERVER');
      }
    }

    // --- Domain Status ---
    if (parsedData.status) {
      // clientDeleteProhibited + clientTransferProhibited = domain được bảo vệ tốt (legitimate)
      const isProtected = parsedData.status.includes('clientDeleteProhibited') &&
        parsedData.status.includes('clientTransferProhibited');
      if (isProtected) {
        score = Math.max(0, score - 15);
        flags.push('DOMAIN_PROTECTED');
      }
    }

    // --- Expiration Check ---
    if (parsedData.expirationDate && !isNaN(parsedData.expirationDate)) {
      const daysToExpiry = Math.floor(
        (parsedData.expirationDate.getTime() - now) / (1000 * 60 * 60 * 24)
      );
      // Domain sắp hết hạn trong 30 ngày → có thể là scam domain tạm thời
      if (daysToExpiry < 30 && daysToExpiry > 0) {
        score += 10;
        flags.push('EXPIRING_SOON');
      }
    }

    score = Math.min(100, score);

    const riskLevel = score >= 80 ? 'CRITICAL' :
      score >= 60 ? 'HIGH' :
        score >= 40 ? 'MEDIUM' :
          score >= 20 ? 'LOW' : 'SAFE';

    return {
      domain,
      ageInDays,
      registrar: parsedData.registrar || null,
      registrationDate: parsedData.registrationDate
        ? parsedData.registrationDate.toISOString().split('T')[0]
        : null,
      expirationDate: parsedData.expirationDate
        ? parsedData.expirationDate.toISOString().split('T')[0]
        : null,
      nameservers: parsedData.nameservers || [],
      riskLevel,
      score,
      flags,
      explanation: generateDomainExplanation(ageInDays, parsedData.registrar, flags, riskLevel),
    };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // AI EXPLANATION: Tiếng Việt
  // ─────────────────────────────────────────────────────────────────────────────

  function generateDomainExplanation(ageInDays, registrar, flags, riskLevel) {
    const sentences = [];

    if (ageInDays !== null) {
      if (ageInDays < 7) {
        sentences.push(`🚨 Tên miền chỉ mới được đăng ký ${ageInDays} ngày trước — cực kỳ đáng ngờ.`);
      } else if (ageInDays < 30) {
        sentences.push(`⚠️ Tên miền được đăng ký cách đây ${ageInDays} ngày — rất mới, nhiều scam domain có tuổi dưới 30 ngày.`);
      } else if (ageInDays < 90) {
        sentences.push(`⚠️ Tên miền được đăng ký cách đây ${ageInDays} ngày — tuổi đời còn khá mới.`);
      } else if (ageInDays < 365) {
        sentences.push(`ℹ️ Tên miền được đăng ký cách đây ${ageInDays} ngày (dưới 1 năm).`);
      } else {
        const years = Math.floor(ageInDays / 365);
        sentences.push(`✅ Tên miền đã tồn tại ${years} năm — tuổi đời đáng tin cậy.`);
      }
    }

    if (registrar) {
      if (flags.includes('TRUSTED_REGISTRAR')) {
        sentences.push(`✅ Đăng ký qua "${registrar}" — đơn vị đăng ký tên miền uy tín tại Việt Nam.`);
      } else if (flags.includes('RISKY_REGISTRAR')) {
        sentences.push(`⚠️ Đăng ký qua "${registrar}" — thường được dùng để tạo domain scam nhanh.`);
      } else {
        sentences.push(`ℹ️ Đăng ký qua: ${registrar}.`);
      }
    }

    if (flags.includes('BULLETPROOF_HOSTING_NS')) {
      sentences.push('🔴 Nameserver sử dụng dịch vụ hosting ẩn danh — che giấu thông tin chủ sở hữu.');
    }

    if (flags.includes('EXPIRING_SOON')) {
      sentences.push('⏳ Tên miền sắp hết hạn — có thể là domain tạm thời dùng cho scam.');
    }

    if (flags.includes('DOMAIN_PROTECTED')) {
      sentences.push('✅ Tên miền có cấu hình bảo vệ đầy đủ — thường thấy ở domain hợp pháp lâu năm.');
    }

    if (sentences.length === 0) {
      sentences.push('ℹ️ Không có đủ thông tin tên miền để phân tích.');
    }

    return sentences.join(' ');
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // MAIN PUBLIC API
  // ─────────────────────────────────────────────────────────────────────────────

  /**
   * Phân tích domain và trả về kết quả đầy đủ.
   * @param {string} domain - tên miền cần phân tích (ví dụ: "vietcombank.com.vn")
   * @returns {Promise<object>} - kết quả phân tích domain
   */
  async function analyzeDomain(domain) {
    if (!domain) {
      return { domain, score: 0, riskLevel: 'SAFE', flags: [], explanation: '' };
    }

    // Normalize: bỏ www
    const cleanDomain = domain.replace(/^www\./, '');

    // Kiểm tra cache
    const cached = await getCachedDomainData(cleanDomain);
    if (cached) {
      return { ...cached, fromCache: true };
    }

    // Gọi RDAP API
    const rdapData = await fetchRDAPData(cleanDomain);
    const parsedData = parseRDAPResponse(rdapData);
    const result = analyzeDomainData(cleanDomain, parsedData);

    // Lưu cache
    await setCachedDomainData(cleanDomain, result);

    return result;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // EXPORT
  // ─────────────────────────────────────────────────────────────────────────────

  global.DomainIntelligence = { analyzeDomain };

})(typeof self !== 'undefined' ? self : this);

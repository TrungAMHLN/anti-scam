/**
 * ANTISCAM VIETNAM — Threat Intelligence Engine
 * Module 6: Kiểm tra các danh sách đen và CSDL mã độc
 *
 * Chạy trong background.js (service worker).
 * Export qua global `self.ThreatIntelligence`.
 */

(function (global) {
  'use strict';

  // ─────────────────────────────────────────────────────────────────────────────
  // LOCAL DATABASE: Known Malicious IPs (Hardcoded fallback)
  // ─────────────────────────────────────────────────────────────────────────────

  const MALICIOUS_IPS = new Set([
    // Một số IP tĩnh thường xuyên chạy phishing
    '193.169.255.43', '45.144.225.43', '185.244.150.12',
    '185.119.73.23', '45.138.72.100', '194.55.186.2'
  ]);

  // ─────────────────────────────────────────────────────────────────────────────
  // CSDL Nội bộ (từ ChongLuaDao API)
  // ─────────────────────────────────────────────────────────────────────────────

  let cachedBlacklist = [];
  let lastFetchTime = 0;
  const FETCH_INTERVAL = 30 * 60 * 1000; // 30 phút

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

  async function updateBlacklist() {
    if (Date.now() - lastFetchTime < FETCH_INTERVAL && cachedBlacklist.length > 0) {
      return;
    }
    try {
      const response = await fetchWithTimeout('https://api.chongluadao.vn/v1/blacklist', { timeout: 2500 });
      if (response.ok) {
        const data = await response.json();
        cachedBlacklist = data.map(item => item.url);
        lastFetchTime = Date.now();
      }
    } catch (e) {
      // Ignore
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // DETECTION
  // ─────────────────────────────────────────────────────────────────────────────

  async function analyzeThreat(url, ipAddress) {
    await updateBlacklist();

    const result = {
      url,
      ipAddress,
      inBlacklist: false,
      maliciousIP: false,
      score: 0,
      riskLevel: 'SAFE',
      explanation: '✅ Không phát hiện mối đe dọa đã biết.',
    };

    if (ipAddress && MALICIOUS_IPS.has(ipAddress)) {
      result.maliciousIP = true;
      result.score = 100;
      result.riskLevel = 'CRITICAL';
      result.explanation = '🚨 IP của máy chủ nằm trong danh sách đen chứa mã độc / lừa đảo.';
      return result;
    }

    try {
      const currentUrlObj = new URL(url);
      const currentHost = currentUrlObj.host;
      const currentPath = currentUrlObj.pathname.replace(/^\//, '');

      for (const blockedUrl of cachedBlacklist) {
        try {
          const blockedObj = new URL(blockedUrl);
          const blockPrefix = blockedObj.host.split('.')[0];
          
          if (blockPrefix === '%2A') {
            const blockDomain = blockedObj.host.slice(4);
            if (currentHost.endsWith(blockDomain)) {
              result.inBlacklist = true;
              break;
            }
          } else if (blockedObj.pathname === '/*') {
            if (currentHost === blockedObj.host) {
              result.inBlacklist = true;
              break;
            }
          } else {
            if (currentHost === blockedObj.host && currentPath === blockedObj.pathname.replace(/^\//, '')) {
              result.inBlacklist = true;
              break;
            }
          }
        } catch (_e) { continue; }
      }
    } catch (_e) { }

    if (result.inBlacklist) {
      result.score = 100;
      result.riskLevel = 'CRITICAL';
      result.explanation = '🚨 CẢNH BÁO: URL này nằm trong cơ sở dữ liệu lừa đảo của ChongLuaDao / AntiScam Vietnam.';
    }

    return result;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // EXPORT
  // ─────────────────────────────────────────────────────────────────────────────

  global.ThreatIntelligence = { analyzeThreat };

})(typeof self !== 'undefined' ? self : this);

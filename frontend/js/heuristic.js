// js/heuristic.js

const HEURISTIC_BRANDS = [
  'vietcombank', 'vcb', 'vietinbank', 'bidv', 'tpbank', 'mbbank', 'techcombank', 
  'vpbank', 'hdbank', 'ocb', 'momo', 'zalopay', 'shb', 'sacombank', 'acb', 'vib',
  'paypal', 'apple', 'microsoft', 'google', 'facebook', 'amazon', 'netflix', 'steam', 'discord'
];

const HEURISTIC_KEYWORDS = [
  'login', 'verify', 'update', 'secure', 'account', 'auth', 'signin', 'support',
  'recover', 'billing', 'password', 'credential', 'validate', 'confirm', 'service'
];

const SUSPICIOUS_TLDS = [
  '.xyz', '.tk', '.ml', '.ga', '.cf', '.cc', '.pw', '.top', '.club', '.online', '.site', '.click'
];

/**
 * Tính điểm rủi ro cho một URL dựa trên các heuristic rule.
 * Hoạt động hoàn toàn cục bộ, không gọi API.
 * @param {string} urlString - URL cần kiểm tra
 * @returns {object} { score, flags, riskLevel }
 */
const computeHeuristicScore = (urlString) => {
  let score = 0;
  const flags = [];
  
  if (!urlString || !urlString.startsWith('http')) {
    return { score: 0, flags: ['Not HTTP/HTTPS'], riskLevel: 'safe' };
  }

  let url;
  try {
    url = new URL(urlString);
  } catch (e) {
    return { score: 100, flags: ['Invalid URL'], riskLevel: 'dangerous' };
  }

  const hostname = url.hostname.toLowerCase();
  
  // 1. Kiểm tra IP thay vì domain
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  if (ipRegex.test(hostname)) {
    score += 30;
    flags.push('IP Address instead of Domain');
  }

  // 2. Độ dài URL
  if (urlString.length > 75) {
    score += 10;
    flags.push('Long URL');
  }

  // 3. Chứa ký tự @
  if (urlString.includes('@')) {
    score += 20;
    flags.push('Contains @ symbol');
  }

  // 4. Nhiều subdomain (không tính www)
  const domainParts = hostname.replace('www.', '').split('.');
  if (domainParts.length > 3) {
    score += 15;
    flags.push(`Multiple subdomains (${domainParts.length})`);
  }

  // 5. Dash (-) trong domain
  const dashCount = (hostname.match(/-/g) || []).length;
  if (dashCount > 0) {
    const dashScore = Math.min(dashCount * 5, 15);
    score += dashScore;
    flags.push(`${dashCount} dashes in domain`);
  }

  // 6. Brand impersonation (Hostname & Path)
  for (const brand of HEURISTIC_BRANDS) {
    // Nếu brand nằm trong domain nhưng không phải là base domain hợp lệ
    if (hostname.includes(brand)) {
      const baseDomainRegex = new RegExp(`^${brand}\\.[a-z]+$`);
      const isExactBaseDomain = baseDomainRegex.test(hostname.replace('www.', ''));
      
      if (!isExactBaseDomain) {
         score += 25;
         flags.push(`Brand impersonation suspected in domain: ${brand}`);
         break;
      }
    } else if (url.pathname.toLowerCase().includes(brand)) {
      // Nếu thương hiệu bị nhét vào phần path (ví dụ: login.com/vietcombank)
      score += 30;
      flags.push(`Brand impersonation suspected in path: ${brand}`);
      break;
    }
  }

  // 7. Suspicious keywords
  let keywordMatchCount = 0;
  for (const keyword of HEURISTIC_KEYWORDS) {
    if (urlString.toLowerCase().includes(keyword)) {
      keywordMatchCount++;
    }
  }
  if (keywordMatchCount > 0) {
    const kwScore = Math.min(keywordMatchCount * 10, 30);
    score += kwScore;
    flags.push(`${keywordMatchCount} suspicious keywords`);
  }

  // 8. TLD nguy hiểm
  for (const tld of SUSPICIOUS_TLDS) {
    if (hostname.endsWith(tld)) {
      score += 15;
      flags.push(`Suspicious TLD: ${tld}`);
      break;
    }
  }

  // 9. Không HTTPS
  if (url.protocol !== 'https:') {
    score += 20;
    flags.push('No HTTPS');
  }

  // 10. Unicode look-alike (Punycode)
  if (hostname.startsWith('xn--')) {
    score += 25;
    flags.push('Punycode domain (possible homograph attack)');
  }

  // Cap score at 100
  score = Math.min(score, 100);

  let riskLevel = 'safe';
  if (score >= 60) riskLevel = 'dangerous';
  else if (score >= 30) riskLevel = 'suspicious';

  return { score, flags, riskLevel };
};

// Export cho môi trường global của Service Worker
if (typeof window !== 'undefined') {
  window.computeHeuristicScore = computeHeuristicScore;
} else if (typeof self !== 'undefined') {
  self.computeHeuristicScore = computeHeuristicScore;
}

/* global chrome */
/* global psl */

// Engine V2 (computeScore) — sourced from packages/shared/heuristic.js
importScripts('../shared/heuristic.js');

// ─────────────────────────────────────────────────────────────────────────────
// Logger
// ─────────────────────────────────────────────────────────────────────────────
const IS_DEV = !('update_url' in chrome.runtime.getManifest());
const logger = {
  info: (...a) => IS_DEV && console.info('[AntiScam]', ...a),
  warn: (...a) => IS_DEV && console.warn('[AntiScam]', ...a),
  error: (...a) => { try { console.error('[AntiScam]', ...a); } catch(_) {} },
};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────
const ANALYSIS_STATUS = Object.freeze({ IDLE:'IDLE', ANALYZING:'ANALYZING', SUCCESS:'SUCCESS', FAILED:'FAILED', OFFLINE:'OFFLINE' });
const BLACKLIST_TTL_MS = 60*60*1000, OPENPHISH_TTL_MS = 15*60*1000, CLASSIFIER_TTL_MS = 5*60*1000;
// Cache TTLs riêng biệt cho từng loại dữ liệu
const RESULT_CACHE_TTL_MS = 10*60*1000;     // Live Scan result: 10 phút
const QUICK_CACHE_TTL_MS  = 30*60*1000;     // Quick Scan result: 30 phút
const STATIC_CACHE_TTL_MS = 6*60*60*1000;   // Blacklist/Reputation: 6 giờ
const DOMAIN_AGE_TTL_MS   = 24*60*60*1000;  // Domain Age (RDAP): 24 giờ
const INTEL_CACHE_TTL_MS = 30*60*1000, FETCH_TIMEOUT_MS = 10_000, MAX_RETRIES = 3;
const RESULT_CACHE_SCHEMA = 2;
const API_BASE = 'https://anti-scam-6iix.onrender.com';
const BACKEND_BASE = API_BASE;
const OPENPHISH_URL = 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt';
const PORT_REDIRECT = 'REDIRECT_PORT_NAME', PORT_CLOSE_TAB = 'CLOSE_TAB_PORT_NAME';
const RISK_BLOCK_THRESHOLD = 55;
const RISK_BLOCK_ALLOW_MS = 5 * 60 * 1000;
const riskBlockAllowUntil = new Map();
// deepScanTabs: Map<tabId, { url, dwellTimer, hardTimeout }>
const deepScanTabs = new Map();
const ipRe = /^(\d{1,3}\.){3}\d{1,3}$/;

// ─────────────────────────────────────────────────────────────────────────────
// Circuit Breaker V2 — Half-Open + Exponential Backoff + Auto Recovery
// ─────────────────────────────────────────────────────────────────────────────
const circuitBreaker = {
  antiScamApi:  { failures:0, openUntil:0, lastFailure:0 },
  openPhish:    { failures:0, openUntil:0, lastFailure:0 },
  backendIntel: { failures:0, openUntil:0, lastFailure:0 },
};
const CB_THRESHOLD = 3;

/**
 * Half-Open Circuit Breaker:
 * - Khi timeout het, tu dong reset failures => cho phep 1 probe request
 * - Exponential backoff: moi lan trip, timeout gap doi (max 2 phut)
 * - recOK reset hoan toan => circuit khoe lai ngay khi backend online
 */
const checkCB = (service) => {
  const cb = circuitBreaker[service];
  if (!cb) return true;
  const now = Date.now();
  if (cb.openUntil > 0 && now >= cb.openUntil) {
    logger.warn("[CB_HALF_OPEN] " + service + " — reset failures, allowing probe");
    cb.failures = 0;
    cb.openUntil = 0;
    return true;
  }
  if (now < cb.openUntil) {
    logger.warn("[CB_OPEN] " + service + " — blocked for " + ((cb.openUntil-now)/1000).toFixed(0) + "s");
    return false;
  }
  return true;
};

const recFail = (service) => {
  const cb = circuitBreaker[service];
  if (!cb) return;
  cb.failures++;
  cb.lastFailure = Date.now();
  if (cb.failures >= CB_THRESHOLD) {
    const tripCount = Math.floor(cb.failures / CB_THRESHOLD);
    const timeout = Math.min(10_000 * Math.pow(2, tripCount), 120_000);
    cb.openUntil = Date.now() + timeout;
    logger.error("[CB_TRIPPED] " + service + " — opened for " + (timeout/1000) + "s (failures=" + cb.failures + ")");
  } else {
    logger.warn("[CB_FAIL] " + service + " — " + cb.failures + "/" + CB_THRESHOLD);
  }
};

const recOK = (service) => {
  const cb = circuitBreaker[service];
  if (!cb) return;
  if (cb.failures > 0) {
    logger.info("[CB_RECOVERED] " + service + " — reset after " + cb.failures + " failures");
  }
  cb.failures = 0;
  cb.openUntil = 0;
};

const fetchWithRetry = async (url, service, isJson = true, retries = 3) => {
  if (!checkCB(service)) return null;
  const maxRetries = Math.max(1, retries);
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
      const response = await fetch(url, { signal: controller.signal });
      clearTimeout(timeoutId);
      if (!response.ok) throw new Error("HTTP " + response.status);
      const data = isJson ? await response.json() : await response.text();
      recOK(service);
      return data;
    } catch (err) {
      const errMsg = err.name === "AbortError" ? "timeout" : err.message;
      logger.warn("[FETCH_FAIL] " + service + " — attempt " + (attempt+1) + "/" + maxRetries + ": " + errMsg);
      if (attempt < maxRetries - 1) {
        await new Promise(r => setTimeout(r, 1000 * Math.pow(2, attempt)));
      }
    }
  }
  recFail(service);
  return null;
};

// ─────────────────────────────────────────────────────────────────────────────
// Storage helpers
// ─────────────────────────────────────────────────────────────────────────────
const getTabState = async (tabId) => { try { const d = await chrome.storage.session.get(`tab_${tabId}`); return d[`tab_${tabId}`] || null; } catch(e){ return null; } };
const setTabState = async (tabId, state) => { try { await chrome.storage.session.set({ [`tab_${tabId}`]: { ...state, updatedAt: Date.now() } }); } catch(e){ logger.error('setTabState', e); } };
const removeTabState = async (tabId) => { try { await chrome.storage.session.remove(`tab_${tabId}`); } catch(e){} };

const getUrlCache = async (url, requiredStage = 'LIVE') => {
  try {
    let h=0; for (let i=0;i<url.length;i++){ h=((h<<5)-h)+url.charCodeAt(i); h|=0; }
    const d = await chrome.storage.session.get(`cache_${h}`);
    const it = d[`cache_${h}`];
    if (!it) return null;
    if (it.schemaVersion !== RESULT_CACHE_SCHEMA) return null;
    // Không dùng QUICK cache cho LIVE scan — tín hiệu không đầy đủ
    if (requiredStage === 'LIVE' && it.stage === 'QUICK') return null;
    const ttl = (it.stage === 'QUICK') ? QUICK_CACHE_TTL_MS : RESULT_CACHE_TTL_MS;
    if (Date.now() - it.timestamp >= ttl) return null;
    return it;
  } catch(e){}
  return null;
};
const setUrlCache = async (url, data, stage = 'LIVE') => {
  try {
    let h=0; for (let i=0;i<url.length;i++){ h=((h<<5)-h)+url.charCodeAt(i); h|=0; }
    await chrome.storage.session.set({ [`cache_${h}`]: { ...data, stage, schemaVersion: RESULT_CACHE_SCHEMA, timestamp: Date.now() } });
  } catch(e){}
};

// ─────────────────────────────────────────────────────────────────────────────
// RDAP Domain Age
// ─────────────────────────────────────────────────────────────────────────────
const _pickRdapDate = (events, names) => {
  if (!Array.isArray(events)) return null;
  const wanted = names.map(n => String(n).toLowerCase());
  const ev = events.find(e => wanted.includes(String(e.eventAction || '').toLowerCase()));
  return ev && ev.eventDate ? ev.eventDate : null;
};

const fetchDomainAge = async (domain) => {
  try {
    let base = domain;
    try { if (typeof psl !== 'undefined') base = psl.parse(domain).domain || domain; } catch(e){}
    const key = `age_${base}`;
    const cached = await chrome.storage.session.get(key);
    if (cached && cached[key] !== undefined) {
      const c = cached[key];
      // Domain Age cache TTL: 24 giờ (ít thay đổi)
      if (c._cachedAt && Date.now() - c._cachedAt < DOMAIN_AGE_TTL_MS) {
        if (typeof c === 'number') return { ageDays: c, source: 'rdap-cache' };
        return c;
      } else if (!c._cachedAt) {
        // Dữ liệu cũ không có _cachedAt → vẫn dùng
        if (typeof c === 'number') return { ageDays: c, source: 'rdap-cache' };
        return c;
      }
    }
    const ctrl = new AbortController(); const t = setTimeout(()=>ctrl.abort(), 3500);
    const res = await fetch(`https://rdap.org/domain/${base}`, { signal: ctrl.signal }); clearTimeout(t);
    if (!res.ok) return { ageDays: -1, source: 'rdap', status: 'nodata' };
    const data = await res.json();
    const registrationDate = _pickRdapDate(data && data.events, ['registration']);
    const expirationDate = _pickRdapDate(data && data.events, ['expiration', 'expiry']);
    const ageDays = registrationDate ? (Date.now() - new Date(registrationDate).getTime())/(1000*60*60*24) : -1;
    const info = { ageDays, registrationDate, expirationDate, source: 'rdap', _cachedAt: Date.now() };
    await chrome.storage.session.set({ [key]: info }); return info;
  } catch (err) { logger.warn(`fetchDomainAge ${domain}:`, err.message); }
  return { ageDays: -1, source: 'rdap', status: 'error' };
};

const fetchBackendIntel = async (urlString, domain) => {
  try {
    let base = domain;
    try { if (typeof psl !== 'undefined') base = psl.parse(domain).domain || domain; } catch(e){}
    const key = `intel_${base}`;
    const cached = await chrome.storage.session.get(key);
    if (cached && cached[key] && Date.now() - cached[key].timestamp < INTEL_CACHE_TTL_MS) return cached[key].data;
    const payload = encodeURIComponent(urlString || domain || '');
    const data = await fetchWithRetry(`${BACKEND_BASE}/v1/intel?url=${payload}`, 'backendIntel', true, 2);
    if (data && data.status !== 'error') {
      await chrome.storage.session.set({ [key]: { data, timestamp: Date.now() } }); return data;
    }
  } catch (err) { logger.warn(`fetchBackendIntel ${domain}:`, err.message); }
  return null;
};

const mergeDomainAge = (rdapAge, backendAge) => {
  if (backendAge && backendAge.ageDays != null && backendAge.ageDays >= 0) return backendAge;
  if (rdapAge && rdapAge.ageDays != null) return rdapAge;
  if (typeof rdapAge === 'number') return { ageDays: rdapAge };
  return { ageDays: -1 };
};

// ─────────────────────────────────────────────────────────────────────────────
// Classifier ML
// ─────────────────────────────────────────────────────────────────────────────
const fetchCLF = async () => {
  try {
    const { classifierCache, classifierCacheTime } = await chrome.storage.local.get(['classifierCache','classifierCacheTime']);
    if (classifierCache && classifierCacheTime && Date.now()-classifierCacheTime < CLASSIFIER_TTL_MS) return classifierCache;
    const data = await fetchWithRetry(`${API_BASE}/classifier.json`, 'antiScamApi', true);
    if (data) { await chrome.storage.local.set({ classifierCache:data, classifierCacheTime:Date.now() }); return data; }
    if (classifierCache) return classifierCache;
  } catch(e){ logger.error('fetchCLF', e); }
  return null;
};
const decisionTree = (root) => { const p1=(x)=>{ let n=root; while(n.type==='split'){ const th=n.threshold.split(' <= '); n = x[th[0]]<=th[1] ? n.left : n.right; } return n.value[0]; }; return { predict:(X)=>X.map(p1) }; };
const randomForest = (clf) => {
  const predict = (X) => {
    let pred = [clf.estimators.map(r=>decisionTree(r).predict(X))];
    pred = pred[0].map((c,i)=>pred.map(r=>r[i]));
    const res = [];
    for (const p in pred) { let pos=0,neg=0; for (const i in pred[p]){ pos+=pred[p][i][1]; neg+=pred[p][i][0]; } res.push([pos>=neg, Math.max(pos,neg)]); }
    return res;
  };
  return { predict };
};

// ─────────────────────────────────────────────────────────────────────────────
// Blacklist / Whitelist
// ─────────────────────────────────────────────────────────────────────────────
let blackListing = [], blackListingSet = new Set(), whiteListingSet = new Set(), inputBlockLenient = false;

const loadListsFromCache = async () => {
  try {
    const { blacklist, blacklistTime, whitelist, whitelistTime, openPhishList, openPhishTime } = await chrome.storage.local.get([
      'blacklist','blacklistTime','whitelist','whitelistTime','openPhishList','openPhishTime']);
    blackListing = []; blackListingSet.clear(); whiteListingSet.clear();
    if (blacklist && blacklistTime && Date.now()-blacklistTime < BLACKLIST_TTL_MS) blacklist.forEach(u=>blackListing.push(u));
    if (openPhishList && openPhishTime && Date.now()-openPhishTime < OPENPHISH_TTL_MS) openPhishList.forEach(u=>blackListingSet.add(u));
    if (whitelist && whitelistTime && Date.now()-whitelistTime < BLACKLIST_TTL_MS) whitelist.forEach(u=>whiteListingSet.add(u));
  } catch(e){ logger.error('loadListsFromCache', e); }
};

let startupInProgress = false;
const startup = async () => {
  if (startupInProgress) return; startupInProgress = true;
  try {
    await loadListsFromCache();
    const { blacklistTime } = await chrome.storage.local.get('blacklistTime');
    if (!blacklistTime || Date.now()-blacklistTime >= BLACKLIST_TTL_MS) {
      const data = await fetchWithRetry(`${API_BASE}/v1/blacklist`, 'antiScamApi', true);
      if (data && Array.isArray(data)) { const list = data.map(i=>i.url).filter(Boolean); await chrome.storage.local.set({ blacklist:list, blacklistTime:Date.now() }); blackListing = list; }
    }
    const { openPhishTime } = await chrome.storage.local.get('openPhishTime');
    if (!openPhishTime || Date.now()-openPhishTime >= OPENPHISH_TTL_MS) {
      const text = await fetchWithRetry(OPENPHISH_URL, 'openPhish', false);
      if (text) { const list = text.split('\n').map(l=>l.trim()).filter(l=>l.length>0); await chrome.storage.local.set({ openPhishList:list, openPhishTime:Date.now() }); list.forEach(u=>blackListingSet.add(u)); }
    }
    const { whitelistTime } = await chrome.storage.local.get('whitelistTime');
    if (!whitelistTime || Date.now()-whitelistTime >= BLACKLIST_TTL_MS) {
      const data = await fetchWithRetry(`${API_BASE}/v1/whitelist`, 'antiScamApi', true);
      if (data && Array.isArray(data)) { const list = data.map(i=>i.url).filter(Boolean); await chrome.storage.local.set({ whitelist:list, whitelistTime:Date.now() }); whiteListingSet.clear(); list.forEach(u=>whiteListingSet.add(u)); }
    }
  } catch(e){ logger.error('startup', e); }
  finally { startupInProgress = false; }
};

// ═══════════════════════════════════════════════════════════════════════════
// REDIRECT CHAIN TRACKING
// ═══════════════════════════════════════════════════════════════════════════
const redirectChains = new Map();
const getRedirectChain = (tabId) => redirectChains.get(tabId) || [];

// ═══════════════════════════════════════════════════════════════════════════
// REPUTATION ENGINE
// ═══════════════════════════════════════════════════════════════════════════

const _isKnownBadUrl = (urlString) => {
  if (!urlString) return false;
  const cur = createUrlObject(String(urlString));
  const normalized = String(urlString).replace(/\/$/, '');
  if (blackListingSet.has(normalized) || blackListingSet.has(String(urlString))) return true;
  if (!cur || !blackListing || !blackListing.length) return false;
  const curHost = cur.hostname.replace(/^www\./, '').toLowerCase();
  const curHref = cur.href.replace(/\/$/, '');
  let curReg = curHost;
  try { curReg = getRegistrable(curHost); } catch (_) {}
  for (const raw of blackListing) {
    const item = String(raw || '').trim();
    if (!item) continue;
    const bs = createUrlObject(item);
    if (!bs) {
      const plain = item.replace(/^\*\./, '').replace(/\/$/, '').toLowerCase();
      if (plain && (curHost === plain || curReg === plain || curHost.endsWith('.' + plain))) return true;
      continue;
    }
    const bHost = bs.hostname.replace(/^www\./, '').toLowerCase();
    const bHref = bs.href.replace(/\/$/, '');
    if (curHref === bHref) return true;
    if (bs.pathname === '/' || bs.pathname === '/*') {
      if (curHost === bHost || curHost.endsWith('.' + bHost)) return true;
    }
  }
  return false;
};

const _analyzePageLinks = async (links, pageDomain) => {
  const out = []; const seen = new Set();
  if (!Array.isArray(links)) return out;
  for (const raw of links.slice(0, 160)) {
    if (!raw || seen.has(raw)) continue; seen.add(raw);
    let host = ''; try { host = new URL(raw).hostname; } catch (_) {}
    const knownBad = _isKnownBadUrl(raw);
    let linkReg = ''; try { linkReg = getRegistrable(host); } catch (_) {}
    const pageReg = getRegistrable(pageDomain || '');
    const benignHost = host && (linkReg === pageReg || (typeof isTrustedHost !== 'undefined' && isTrustedHost(host)) || (typeof REPUTATION_WHITELIST !== 'undefined' && REPUTATION_WHITELIST.has(linkReg)) || (typeof isOfficialBrandDomain !== 'undefined' && !!isOfficialBrandDomain(host)));
    const local = (!knownBad && benignHost) ? { findings: [] } : (typeof analyzeUrl !== 'undefined' ? analyzeUrl(raw) : { findings: [] });
    const suspicious = (local.findings || []).filter(f =>
      ['DangerousDownload','Typosquat','Homograph','BrandInDomain','BrandInPath','Punycode','UnicodeHost','VNScamKeyword','IPHost','OpenRedirect'].includes(f.key)
    );
    let keys = suspicious.map(f => f.key).slice(0, 5);
    let points = (knownBad ? 45 : 0) + suspicious.reduce((sum, f) => sum + Math.min(f.points || 0, 18), 0);
    if (!knownBad && suspicious.some(f => ['DangerousDownload','Typosquat','Homograph','BrandInDomain','BrandInPath','OpenRedirect'].includes(f.key)) && host && !benignHost && out.length < 3) {
      try { const age = await fetchDomainAge(host); if (age && age.ageDays >= 0 && age.ageDays < 14) { keys.push('LinkNewDomain'); points += 10; } } catch (_) {}
    }
    if (knownBad || keys.length) { out.push({ url: raw, host, knownBad, keys: keys.slice(0, 6), points }); }
    if (out.length >= 12) break;
  }
  return out;
};

const resolveReputation = (domain, registrable, urlString, backendIntel = null) => {
  const whitelist = typeof self !== 'undefined' && self.REPUTATION_WHITELIST ? self.REPUTATION_WHITELIST : (typeof REPUTATION_WHITELIST !== 'undefined' ? REPUTATION_WHITELIST : new Set());
  const inBuiltWhitelist = whitelist.has(registrable);
  let inCldWhitelist = false;
  for (const w of whiteListingSet) { if (w.includes(domain) || w.includes(registrable)) { inCldWhitelist = true; break; } }
  let inBlacklist = blackListingSet.has(urlString) || blackListingSet.has(urlString.replace(/\/$/,''));
  if (!inBlacklist && blackListing.length) { for (const b of blackListing) { if (urlString.includes(b.replace(/\/$/,''))) { inBlacklist = true; break; } } }
  const checkBrand = typeof self !== 'undefined' && self.isOfficialBrandDomain ? self.isOfficialBrandDomain : (typeof isOfficialBrandDomain !== 'undefined' ? isOfficialBrandDomain : null);
  const officialBrand = checkBrand ? checkBrand(domain) : null;
  const intel = backendIntel || {};
  return {
    inWhitelist: inBuiltWhitelist || inCldWhitelist,
    inBlacklist: inBlacklist || !!(intel.malware && intel.malware.dangerous),
    isOfficialBrand: !!officialBrand,
    malware: intel.malware || {}, dns: intel.dns || {},
    community: intel.community || null,
    communityReports: intel.community && intel.community.reportCount ? intel.community.reportCount : 0,
    checked: true,
  };
};

// ─────────────────────────────────────────────────────────────────────────────
// Utility
// ─────────────────────────────────────────────────────────────────────────────
const getDomain = (url) => { try { return new URL(url).hostname; } catch (_) { const m = url.match(/^https?:\/\/([^/?#]+)(?:[/?#]|$)/i); return (m && m[1].split(':')[0]) || ''; } };
const createUrlObject = (url) => { try { return new URL(url); } catch { return null; } };
const getRegistrable = (domain) => {
  if (typeof self !== 'undefined' && self.getRegistrableDomain) return self.getRegistrableDomain(domain);
  let h = (domain||'').toLowerCase().replace(/^www\./,''); return h.split('.').slice(-2).join('.');
};

const updateBadge = (isPhishing, finalScore, tabId) => {
  const title = isPhishing ? `AntiScam: ⚠ Cảnh báo (${finalScore}% an toàn)` : `AntiScam: ✓ An toàn (${finalScore}%)`;
  chrome.action.setTitle({ title, tabId }).catch(()=>{});
  chrome.action.setIcon({ path: 'assets/antiScamLogo.png', tabId }).catch(()=>{});
};

const isRiskBlockAllowed = (tabId) => { const until = riskBlockAllowUntil.get(tabId) || 0; if (Date.now() < until) return true; riskBlockAllowUntil.delete(tabId); return false; };

const shouldAutoBlock = (assessment, reputation) => {
  if (!assessment || !reputation) return false;
  if (reputation.inWhitelist || reputation.isOfficialBrand) return false;
  const finalScore = assessment.finalScore || 0;
  if (finalScore >= 50) return false;
  const criticalSignals = ['MalwareReputation','FormHijack','FormDest','DataExfil','Keylogger','DangerousDownload','RedirectBadHop','BrandImpersonation','Homograph','Typosquat'];
  const findings = assessment.findings || [];
  const hasCritical = findings.some(f => criticalSignals.includes(f.key));
  const highRisk = findings.filter(f => f.points >= 15).length;
  return assessment.confidence >= 45 && (hasCritical || highRisk >= 2 || (assessment.riskScore || 0) >= 60);
};

// ═══════════════════════════════════════════════════════════════════════════
// CUSTOM URL SCAN STORAGE
// ═══════════════════════════════════════════════════════════════════════════
const SCAN_STORAGE_KEY = 'antiscam_url_scan_results';

const getUrlScanResult = async (urlString) => {
  try { const data = await chrome.storage.local.get(SCAN_STORAGE_KEY); return (data[SCAN_STORAGE_KEY] || {})[urlString] || null; } catch { return null; }
};
const setUrlScanResult = async (urlString, state) => {
  try {
    const data = await chrome.storage.local.get(SCAN_STORAGE_KEY);
    const all = data[SCAN_STORAGE_KEY] || {};
    all[urlString] = { ...state, updatedAt: Date.now() };
    await chrome.storage.local.set({ [SCAN_STORAGE_KEY]: all });
  } catch (e) { logger.error('[SCAN] setUrlScanResult failed', e); }
};
const removeUrlScanResult = async (urlString) => {
  try { const data = await chrome.storage.local.get(SCAN_STORAGE_KEY); const all = data[SCAN_STORAGE_KEY] || {}; delete all[urlString]; await chrome.storage.local.set({ [SCAN_STORAGE_KEY]: all }); } catch {}
};

// ═══════════════════════════════════════════════════════════════════════════
// CLASSIFY — cho tab hiện tại (Pipeline A)
// ═══════════════════════════════════════════════════════════════════════════
const classify = async (tabId, featuresResult, urlString, domInput = {}, isUpdate = false) => {
  let reputation = null;
  try {
    const domain = getDomain(urlString);
    const registrable = getRegistrable(domain);

    let inCldWhitelist = false;
    for (const w of whiteListingSet) { if (w.includes(domain) || w.includes(registrable)) { inCldWhitelist = true; break; } }
    if (inCldWhitelist) {
      await setTabState(tabId, { status: ANALYSIS_STATUS.SUCCESS, isWhiteList: domain, isPhish: false, legitimatePercent: 100, confidence: 95, listType: 'whitelist', result: {}, summary: 'Trang nằm trong danh sách tin cậy.', url: urlString });
      updateBadge(false, 100, tabId); return;
    }

    if (!isUpdate) {
      // LIVE scan chỉ dùng cache LIVE — không dùng QUICK cache
      const cached = await getUrlCache(urlString, 'LIVE');
      if (cached) {
        await setTabState(tabId, { status: ANALYSIS_STATUS.SUCCESS, isPhish: cached.isPhish, legitimatePercent: cached.legitimatePercent, confidence: cached.confidence,
          riskScore: cached.riskScore || 0, trustScore: cached.trustScore || 0, trustContext: cached.trustContext || null,
          result: cached.result || {}, summary: cached.summary || '', explanations: cached.explanations || [], isUnknown: cached.isUnknown, url: urlString });
        updateBadge(cached.isPhish, cached.legitimatePercent, tabId); return;
      }
    }

    const prev = await getTabState(tabId);
    const rdapAge = await fetchDomainAge(domain);
    const backendIntel = await fetchBackendIntel(urlString, domain);
    const domainAge = mergeDomainAge(rdapAge, backendIntel && backendIntel.domainAge);
    const domainAgeDays = domainAge.ageDays != null ? domainAge.ageDays : -1;
    reputation = resolveReputation(domain, registrable, urlString, backendIntel);
    const redirectChain = getRedirectChain(tabId);

    let analysisStart = prev && prev.analysisStart ? prev.analysisStart : Date.now();
    const prevRisk = prev && prev.riskScore != null ? prev.riskScore : 0;
    const stabilityMs = Date.now() - analysisStart;

    const enrichedDom = { ...(domInput || {}) };
    const suspiciousLinks = await _analyzePageLinks(enrichedDom.pageLinks || [], domain);
    if (suspiciousLinks.length) { enrichedDom.suspiciousLinks = suspiciousLinks; enrichedDom.suspiciousLinkCount = suspiciousLinks.length; }
    const redirectHopRisk = ((c) => { if (!Array.isArray(c)) return {bad:false,badHops:[]}; const bh=[]; for (const u of c) { if (_isKnownBadUrl(u)) bh.push(u); } return {bad:bh.length>0,badHops:bh.slice(0,6)}; })(redirectChain);
    if (redirectHopRisk.bad) { enrichedDom.redirectBadHop = true; enrichedDom.redirectBadHops = redirectHopRisk.badHops; }

    const assessment = computeLiveScore(urlString, { dom: enrichedDom, domainAgeDays, domainAge, reputation, redirectChain, stabilityMs });

    let riskScore = assessment.riskScore, finalScore = assessment.finalScore, confidence = assessment.confidence;

    const resultValues = Object.entries(featuresResult || {}).filter(([k]) => k !== 'tab').map(([,v]) => parseInt(v));
    const clf = await fetchCLF();
    if (clf && resultValues.length) { try { const isPhishML = randomForest(clf).predict([resultValues])[0][0]; if (isPhishML && riskScore < 40) { riskScore += 8; finalScore = Math.max(0, finalScore - 8); } } catch(e){} }

    if (riskScore > prevRisk + 3) analysisStart = Date.now();

    const mergedResult = {};
    for (const k in (featuresResult || {})) { if (k !== 'tab') mergedResult[k] = featuresResult[k]; }
    for (const k in (assessment.result || {})) { mergedResult[k] = assessment.result[k]; }

    const isPhish = finalScore <= 30;
    const finalState = {
      status: ANALYSIS_STATUS.SUCCESS, isPhish, legitimatePercent: finalScore, confidence,
      stage: assessment.stage || 'LIVE',
      trustScore: assessment.trustScore, riskScore, trustContext: assessment.trustContext, isUnknown: assessment.isUnknown,
      result: mergedResult, summary: assessment.summary, explanations: assessment.explanations || [],
      domainAge: assessment.domainAge || domainAge, reputation,
      counts: (() => { if (!enrichedDom || !enrichedDom.counts) return null; const c = {...enrichedDom.counts, suspiciousLinks:enrichedDom.suspiciousLinkCount||0, deceptiveLinks:enrichedDom.deceptiveLinkCount||0}; if(c.links){c.links={...c.links};c.links.dangerous=enrichedDom.suspiciousLinkCount||0;c.links.warning=Math.max(0,(c.links.warning||0)-c.links.dangerous);c.links.safe=Math.max(0,(c.links.total||0)-c.links.warning-c.links.dangerous);} return c; })(),
      analysisStart, url: urlString,
    };
    await setTabState(tabId, finalState);

    // Nếu đây là deep scan tab: lưu kết quả tạm, KHÔNG đóng tab
    // Để dwell timer chạy tiếp — behavioral signals sẽ tiếp tục đổ vào qua ANALYSIS_UPDATE
    if (deepScanTabs.has(tabId)) {
      logger.info(`[DEEP_SCAN_INTERIM] tabId=${tabId} url=${urlString} score=${finalScore} isUpdate=${isUpdate}`);
      await setUrlScanResult(urlString, { ...finalState, scanSource: 'CUSTOM_URL', isInterim: true });
      return; // Không badge, không block, không đóng tab
    }

    if (!isUpdate) { await setUrlCache(urlString, { isPhish, legitimatePercent: finalScore, confidence, riskScore, trustScore: assessment.trustScore, trustContext: assessment.trustContext, result: mergedResult, summary: assessment.summary, explanations: assessment.explanations || [], isUnknown: assessment.isUnknown }, 'LIVE'); }
    updateBadge(isPhish, finalScore, tabId);

    if (!isRiskBlockAllowed(tabId) && shouldAutoBlock(assessment, reputation)) {
      try { const ti = await chrome.tabs.get(tabId); if (ti) blockingFunction(urlString, `Mức rủi ro ${riskScore}/100`, tabId, { summary: assessment.summary || 'Trang có nhiều tín hiệu nguy hiểm.' }); } catch(_) {}
    }
  } catch (err) {
    logger.error(`classify ${tabId}:`, err);
    await setTabState(tabId, { status: ANALYSIS_STATUS.FAILED, isPhish: false, legitimatePercent: null, confidence: 0, result: featuresResult || {}, summary: 'Không thể phân tích trang này.', url: urlString });
  }
};

// Đọc kết quả cuối cùng từ tabState và lưu vào URL scan result, sau đó dọn dẹp
const finalizeDeepScan = async (tabId) => {
  const meta = deepScanTabs.get(tabId);
  if (!meta) return;
  const { url: urlString } = meta;
  logger.info(`[DEEP_SCAN_FINALIZE_START] tabId=${tabId} url=${urlString}`);

  // Chờ classify chạy xong (chuyển sang SUCCESS hoặc FAILED)
  let state = await getTabState(tabId);
  for (let i = 0; i < 30; i++) {
    if (state && state.status !== ANALYSIS_STATUS.ANALYZING) break;
    await new Promise(r => setTimeout(r, 500));
    state = await getTabState(tabId);
  }

  deepScanTabs.delete(tabId);
  removeTabState(tabId); // Bây giờ mới an toàn xoá tabState

  try {
    if (state && state.status === ANALYSIS_STATUS.SUCCESS) {
      await setUrlScanResult(urlString, { ...state, scanSource: 'CUSTOM_URL', isInterim: false });
      logger.info(`[DEEP_SCAN_FINAL] url=${urlString} score=${state.legitimatePercent}`);
    } else {
      logger.warn(`[DEEP_SCAN_FINALIZE] No SUCCESS state for tabId=${tabId}, resolving interim or failing`);
      const currentRes = await getUrlScanResult(urlString);
      if (currentRes && currentRes.isInterim) {
        await setUrlScanResult(urlString, { ...currentRes, isInterim: false });
      } else if (!currentRes || currentRes.status === 'ANALYZING') {
        await setUrlScanResult(urlString, { status: 'FAILED', isPhish: false, legitimatePercent: null, confidence: 0, result: {}, summary: 'Không thể phân tích trang web do quá trình tải bị lỗi.', url: urlString, scanSource: 'CUSTOM_URL', isInterim: false });
      }
    }
  } catch(e) { logger.error('[DEEP_SCAN_FINALIZE]', e); }
  
  try { chrome.tabs.remove(tabId); } catch(e) {}
};

// ═══════════════════════════════════════════════════════════════════════════
// BLOCKING & SAFECHECK
// ═══════════════════════════════════════════════════════════════════════════
const blockingFunction = (url, blackSite, tabId, opts = {}) => {
  const listType = opts.listType || (opts.summary ? 'riskblock' : 'blacklist');
  chrome.tabs.get(tabId).then(tabInfo => {
    if (!tabInfo) return; return getTabState(tabId);
  }).then(state => {
    if (!state) return;
    const message = { site: url, match: blackSite, title: url, lenient: inputBlockLenient, riskBlock: !!opts.summary, listType, reason: opts.summary || '',
      favicon: `https://www.google.com/s2/favicons?domain=${url}`, result: (state&&state.result)||{}, explanations: (state&&state.explanations)||[], finalScore: (state&&state.legitimatePercent)||0, confidence: (state&&state.confidence)||0 };
    setTabState(tabId, { status: ANALYSIS_STATUS.SUCCESS, isBlocked: url, isPhish: true, legitimatePercent: state?state.legitimatePercent:0, confidence: state?state.confidence:95, result: state?state.result:{}, summary: opts.summary || 'Trang này nằm trong danh sách đen đã xác nhận.', url }).catch(()=>{});
    chrome.tabs.update(tabId, { url: `${chrome.runtime.getURL('pages/blocking/index.html')}#${JSON.stringify(message)}` }).catch(e=>logger.warn('blocking', e.message));
  }).catch(e => logger.warn('[blocking]', tabId, e.message));
};

const safeCheck = async ({ url, tabId }) => {
  if (!url || url.startsWith('chrome://') || url.startsWith(chrome.runtime.getURL('/'))) return;
  const cur = createUrlObject(url); if (!cur) return;
  const domain = cur.hostname.toLowerCase(); const registrable = getRegistrable(domain);
  let inWhitelist = (typeof REPUTATION_WHITELIST !== 'undefined' && REPUTATION_WHITELIST.has(registrable));
  if (!inWhitelist) { for (const w of whiteListingSet) { if (w.includes(domain) || w.includes(registrable)) { inWhitelist = true; break; } } }
  if (inWhitelist) return;
  if (blackListingSet.has(url) || blackListingSet.has(url.replace(/\/$/,''))) { blockingFunction(url, url, tabId); return; }
  if (!blackListing || !blackListing.length) return;
  let curDom = ''; try { if (typeof psl!=='undefined') curDom = psl.parse(cur.host).domain || ''; } catch { curDom = cur.host; }
  const curPath = cur.href.replaceAll('/','');
  for (let i=0;i<blackListing.length;++i) { const bs = createUrlObject(blackListing[i]); if (!bs) continue;
    const prefix = bs.host.split('.')[0], suffix = bs.pathname;
    if (prefix === '%2A' && curDom) { const bd = bs.host.slice(4); if (bd === curDom) { blockingFunction(url, bs.host, tabId); return; } }
    if (suffix === '/*' && cur.host === bs.host) { blockingFunction(url, bs.host, tabId); return; }
    if (curPath && curPath === bs.href.replaceAll('/','')) { blockingFunction(url, bs.host, tabId); return; }
  }
};

// ═════════════════════════════════════════════════════════════════════════════════════
// FETCH-BASED URL SCAN — KHÔNG MỞ TAB, KHÔNG CHUYỂN FOCUS, HOÀN TOÀN NGẦM
// ═════════════════════════════════════════════════════════════════════════════════════
//
// Kiến trúc mới:
//   1. Popup gửi SCAN_URL → background fetch HTML
//   2. Parse HTML → extract signals (forms, links, scripts, iframes, brand...)
//   3. computeScore() + ML → kết quả hoàn chỉnh
//   4. Lưu vào chrome.storage.local → popup poll → render
//
// Ưu điểm so với mở tab:
//   - Không mở tab mới, không chuyển focus, không gây nhầm lẫn
//   - Nhanh hơn (không cần load page đầy đủ, chạy JS)
//   - Không bị Cloudflare/captcha block
//   - Ít tốn tài nguyên
//
// Hạn chế:
//   - Không chạy JS → không phát hiện keylogger, clipboard hijack, dynamic content
//   - Nhưng URL heuristics + static HTML signals bao phủ đa số trường hợp lừa đảo
// ═════════════════════════════════════════════════════════════════════════════════════

// Brand detection arrays (từ features.js, dùng cho parseHtmlSignals)
const BRAND_KEYS_SCAN = [
  ['vietcombank','Vietcombank'],['bidv','BIDV'],['mbbank','MB'],['techcombank','Techcombank'],
  ['tpbank','TPBank'],['agribank','Agribank'],['vietinbank','VietinBank'],['vpbank','VPBank'],
  ['sacombank','Sacombank'],['momo','MoMo'],['zalopay','ZaloPay'],['zalo','Zalo'],
  ['shopee','Shopee'],['lazada','Lazada'],['tiki','Tiki'],['google','Google'],
  ['microsoft','Microsoft'],['facebook','Facebook'],['apple','Apple'],['paypal','PayPal'],
  ['amazon','Amazon'],['netflix','Netflix'],['openai','OpenAI'],['chatgpt','ChatGPT'],
  ['telegram','Telegram'],['github','GitHub'],
];
const BRAND_OFFICIAL_SCAN = {
  'vietcombank':['vietcombank.com.vn'],'bidv':['bidv.com.vn'],'mbbank':['mbbank.com.vn'],
  'techcombank':['techcombank.com.vn'],'tpbank':['tpb.vn','tpbank.vn'],'agribank':['agribank.com.vn'],
  'vietinbank':['vietinbank.vn'],'vpbank':['vpbank.vn'],'sacombank':['sacombank.com'],
  'momo':['momo.vn'],'zalopay':['zalopay.vn'],'zalo':['zalo.me'],'shopee':['shopee.vn'],
  'lazada':['lazada.vn'],'tiki':['tiki.vn'],'google':['google.com'],'microsoft':['microsoft.com'],
  'facebook':['facebook.com'],'apple':['apple.com'],'paypal':['paypal.com'],'amazon':['amazon.com'],
  'netflix':['netflix.com'],'openai':['openai.com','chatgpt.com'],'chatgpt':['chatgpt.com','openai.com'],
  'telegram':['telegram.org'],'github':['github.com'],
};

// Scam content patterns (Vietnamese) — từ features.js
const VN_SCAM_PATTERNS = [
  { re: /loi\s*nhuan\s*\d+\s*%|\d+\s*%.*(?:moi\s*ngay|\/\s*ngay|ngay)/, label: 'lợi nhuận cao bất thường' },
  { re: /dau\s*tu|tien\s*dien\s*tu|crypto|coin|forex/, label: 'đầu tư/tiền điện tử' },
  { re: /da\s*cap|he\s*thong\s*tuyen\s*duoi|kim\s*tu\s*thap/, label: 'đa cấp' },
  { re: /vay\s*nong|vay\s*nhanh|giai\s*ngan\s*trong\s*ngay/, label: 'vay nóng' },
  { re: /viec\s*nhe\s*luong\s*cao|kiem\s*tien\s*online|khong\s*can\s*von/, label: 'việc nhẹ lương cao' },
  { re: /nhan\s*thuong|trung\s*thuong|hoa\s*hong\s*khung/, label: 'nhận thưởng bất thường' },
];

const _normalizeText = (str) => {
  try { return (str||'').toString().normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase(); } catch(_) { return (str||'').toString().toLowerCase(); }
};

/**
 * Fetch HTML từ URL — dùng trong service worker, không mở tab
 */
const fetchHtml = async (urlString) => {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 15_000);
  try {
    const res = await fetch(urlString, { 
      signal: ctrl.signal, 
      redirect: 'follow',
      headers: {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36'
      }
    });
    clearTimeout(t);
    if (!res.ok) return null;
    const ct = (res.headers.get('content-type') || '').toLowerCase();
    // Chỉ parse HTML, bỏ qua PDF/images/API
    if (!ct.includes('text/html') && !ct.includes('application/xhtml') && !ct.includes('text/plain')) return null;
    return await res.text();
  } catch (err) {
    clearTimeout(t);
    logger.warn(`[fetchHtml] ${urlString}: ${err.message}`);
    return null;
  }
};

/**
 * Parse HTML → extract signals (giống features.js::collect() nhưng chạy trong SW)
 * Trả về { result: {...ML features}, dom: {...DOM signals} } — cùng format như features.js
 */
const parseHtmlSignals = (urlString, html) => {
  const urlObj = createUrlObject(urlString);
  if (!urlObj) return { result: {}, dom: { scanned: true, fetchBased: true } };

  const domain = urlObj.hostname;
  const currentOnlyDomain = domain.replace(/^www\./, '');
  const result = {};
  const dom = { scanned: true, fetchBased: true };

  // ═══ URL-based ML features (giống features.js) ═══
  result['IP Address'] = ipRe.test(currentOnlyDomain) ? '1' : '-1';
  result['URL Length'] = urlString.length > 100 ? '0' : '-1';
  result['Tiny URL'] = (currentOnlyDomain.length < 5 && !ipRe.test(currentOnlyDomain)) ? '0' : '-1';
  result['@ Symbol'] = urlString.includes('@') ? '0' : '-1';
  result['Redirecting using //'] = (urlString.lastIndexOf('//') > 7 && /\/\/[^/]+@/.test(urlString)) ? '0' : '-1';
  result['(-) Prefix/Suffix in domain'] = ((currentOnlyDomain.match(/-/g) || []).length >= 3) ? '0' : '-1';
  result['No. of Sub Domains'] = ((currentOnlyDomain.match(/\./g) || []).length >= 4) ? '0' : '-1';
  result['HTTPS'] = urlObj.protocol === 'https:' ? '-1' : '0';
  result['HTTPS in URL\'s domain part'] = /https/i.test(currentOnlyDomain) ? '0' : '-1';
  result['Favicon'] = '-1';
  result['Port'] = '-1';
  const port = urlObj.port;
  if (port && !['80','443','8080','8000','3000','5000'].includes(port)) result['Port'] = '0';

  if (!html) return { result, dom }; // Không có HTML → chỉ URL features

  // Giới hạn HTML size
  const maxHtml = html.slice(0, 2_000_000);
  const _stripTags = (s) => (s||'').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();

  // ═══ Extract elements bằng regex ═══
  const allScripts = [...maxHtml.matchAll(/<script[^>]*>/gi)];
  const allScriptsWithSrc = allScripts.filter(m => /\ssrc\s*=/i.test(m[0]));
  const allLinks = [...maxHtml.matchAll(/<link[^>]*>/gi)];
  const allImgs = [...maxHtml.matchAll(/<img[^>]*>/gi)];
  const allAnchors = [...maxHtml.matchAll(/<a[^>]*>([\s\S]*?)<\/a>/gi)];
  const allForms = [...maxHtml.matchAll(/<form[^>]*>([\s\S]*?)<\/form>/gi)];
  const allIframes = [...maxHtml.matchAll(/<iframe[^>]*>/gi)];
  const allInputs = [...maxHtml.matchAll(/<input[^>]*>/gi)];

  const _extractAttr = (tag, attr) => { const m = tag.match(new RegExp(`\\s${attr}\\s*=\\s*["']([^"']+)["']`, 'i')); return m ? m[1] : null; };
  const _hostOf = (href) => { if (!href || href.startsWith('data:') || href.startsWith('javascript:')) return null; try { return new URL(href, urlString).hostname.replace(/^www\./, ''); } catch { return null; } };
  const _isExternal = (host) => host && host !== currentOnlyDomain && !host.endsWith('.' + currentOnlyDomain) && !(typeof isTrustedHost !== 'undefined' && isTrustedHost(host));

  // ═══ Script & Link ratios ═══
  let extRes = 0, totalRes = 0;
  const externalScriptHosts = [];
  const countRes = (getSrc) => { for (const m of getSrc) { const src = _extractAttr(m[0], 'src') || _extractAttr(m[0], 'href'); if (!src) continue; totalRes++; const h = _hostOf(src); if (_isExternal(h)) { extRes++; externalScriptHosts.push(h); } } };
  countRes(allScriptsWithSrc); countRes(allLinks);
  const outPct = totalRes === 0 ? 0 : (extRes / totalRes) * 100;
  result['Script & Link'] = outPct > 80 ? '1' : (outPct > 50 ? '0' : '-1');

  // ═══ Request URL (image ratio) ═══
  let imgExt = 0, imgTotal = 0;
  for (const m of allImgs) { const src = _extractAttr(m[0], 'src'); if (!src) continue; imgTotal++; if (_isExternal(_hostOf(src))) imgExt++; }
  const imgPct = imgTotal === 0 ? 0 : (imgExt / imgTotal) * 100;
  result['Request URL'] = imgPct > 60 ? '1' : (imgPct > 30 ? '0' : '-1');

  // ═══ Anchor analysis ═══
  let aExt = 0, aTotal = 0;
  const pageLinks = [];
  const deceptiveLinks = [];
  const externalLinkHosts = new Set();
  for (const m of allAnchors) {
    const fullTag = m[0];
    const href = _extractAttr(fullTag, 'href');
    if (!href) continue;
    let abs = null; try { abs = new URL(href, urlString).href; } catch {}
    if (abs && /^https?:\/\//i.test(abs) && pageLinks.length < 160) pageLinks.push(abs);
    aTotal++;
    const h = _hostOf(href);
    if (_isExternal(h)) { aExt++; externalLinkHosts.add(h); }
    // Deceptive link: text shows different domain than href
    const text = _stripTags(m[1]).toLowerCase();
    const textMatch = text.match(/(?:https?:\/\/)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)/i);
    if (textMatch && abs) {
      const shownHost = textMatch[1].replace(/^www\./, '');
      const hrefHost = _hostOf(abs) || '';
      if (shownHost && hrefHost && shownHost !== hrefHost && !shownHost.endsWith('.' + hrefHost)) {
        deceptiveLinks.push({ text: shownHost, href: hrefHost });
      }
    }
  }
  const aPct = aTotal === 0 ? 0 : (aExt / aTotal) * 100;
  result['Anchor'] = aPct > 75 ? '1' : (aPct > 40 ? '0' : '-1');
  dom.pageLinks = pageLinks;
  dom.externalLinkHosts = Array.from(externalLinkHosts).slice(0, 40);
  dom.deceptiveLinks = deceptiveLinks.slice(0, 10);
  dom.deceptiveLinkCount = deceptiveLinks.length;

  // ═══ Scam Content ═══
  const scamKeywords = ['phishing', 'scam', 'hack', 'cheat', 'free-fire', 'nhantien', 'tangqua', 'khuyenmai', 'trungthuong', 'napthe'];
  let keywordScamHits = 0;
  const pageText = _stripTags(maxHtml).toLowerCase();
  for (const kw of scamKeywords) { if (pageText.includes(kw)) keywordScamHits++; }
  result['Scam Content'] = keywordScamHits >= 2 ? '2' : (keywordScamHits === 1 ? '0' : '-1');

  // ═══ Forms ═══
  let sensitiveFound = false, hijackFound = false, pwField = false, otpField = false, cardField = false, bankField = false, hiddenFormFound = false, sensitiveFormCount = 0;
  const sensitiveNames = ['password','passcode','passwd','otp','pin','cvv','cvc','cardnumber','card-number','creditcard','cccd','cmnd','stk','sotk','so-tai-khoan','ngan-hang','internet-banking'];
  for (const m of allForms) {
    const formTag = m[0]; const formContent = m[1] || '';
    const formStyle = _extractAttr(formTag, 'style') || '';
    const hiddenByCss = /display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0/i.test(formStyle);
    let sensitive = /type\s*=\s*["']password["']/i.test(formContent) || /autocomplete\s*=\s*["']current-password["']/i.test(formContent);
    if (!sensitive) { for (const nm of sensitiveNames) { if (formContent.toLowerCase().includes(nm)) { sensitive = true; break; } } }
    if (sensitive) { sensitiveFound = true; sensitiveFormCount++; if (/type\s*=\s*["']password["']/i.test(formContent)) pwField = true; if (/otp|ma-xac-thuc|maxacthuc/i.test(formContent)) otpField = true; if (/card|credit|debit|cvv|so-the|sothe/i.test(formContent)) cardField = true; if (/stk|sotk|so-tai-khoan|ngan-hang|internet-banking/i.test(formContent)) bankField = true;
      if (hiddenByCss) hiddenFormFound = true;
      const action = _extractAttr(formTag, 'action') || '';
      if (action.startsWith('http')) { try { const ah = new URL(action, urlString).hostname.replace(/^www\./, ''); if (_isExternal(ah) && !(typeof isTrustedHost !== 'undefined' && isTrustedHost(ah))) hijackFound = true; } catch {} }
    }
  }
  
  result['SFH'] = '-1';
  for (const m of allForms) {
    const action = _extractAttr(m[0], 'action') || '';
    if (!action || action === '' || action === '#') result['SFH'] = '0';
    else if (action.startsWith('http')) { try { const ah = new URL(action, urlString).hostname.replace(/^www\./, ''); if (_isExternal(ah)) result['SFH'] = '1'; } catch {} }
  }

  result['mailto'] = '-1';
  for (const m of allForms) { if ((_extractAttr(m[0], 'action') || '').startsWith('mailto')) { result['mailto'] = '0'; break; } }

  // ═══ iFrames ═══
  dom.numIframes = allIframes.length; dom.hiddenIframe = false;
  let iframeRiskScore = 0;
  for (const m of allIframes) {
    const src = _extractAttr(m[0], 'src');
    const srcHost = _hostOf(src);
    const style = _extractAttr(m[0], 'style') || '';
    const w = parseInt(_extractAttr(m[0], 'width') || '0'); const h = parseInt(_extractAttr(m[0], 'height') || '0');
    const isHidden = /display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0/i.test(style) || (w > 0 && w <= 1) || (h > 0 && h <= 1);
    if (isHidden) { iframeRiskScore += 10; dom.hiddenIframe = true; }
    if (_isExternal(srcHost)) { iframeRiskScore += 15; }
  }
  dom.iframeRiskScore = iframeRiskScore;
  result['iFrames'] = iframeRiskScore >= 40 ? '1' : (iframeRiskScore >= 25 ? '2' : (iframeRiskScore >= 10 ? '0' : '-1'));

  dom.sensitiveForm = sensitiveFound; dom.formHijack = hijackFound; dom.passwordField = pwField;
  dom.otpField = otpField; dom.cardField = cardField; dom.bankAccountField = bankField; dom.hiddenForm = hiddenFormFound;
  result['Sensitive Form'] = sensitiveFound ? (cardField || bankField ? '2' : '0') : '-1';
  result['Form Hijacking'] = hijackFound ? '1' : '-1';
  result['Hidden Form'] = hiddenFormFound ? '2' : '-1';

  if (result['SFH'] === '0' && !sensitiveFound) result['SFH'] = '-1';

  // (Obfuscation detection moved below — dùng inline-script parser nâng cao)

  // ═══ Brand detection from title/meta/h1/h2 ═══
  const titleMatch = maxHtml.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const title = titleMatch ? titleMatch[1].trim().toLowerCase() : '';
  const descMatch = maxHtml.match(/<meta[^>]+name\s*=\s*["']description["'][^>]+content\s*=\s*["']([^"']+)["']/i);
  const metaDesc = descMatch ? descMatch[1].trim().toLowerCase() : '';
  const h1Match = maxHtml.match(/<h1[^>]*>([\s\S]*?)<\/h1>/i);
  const h1 = h1Match ? _stripTags(h1Match[1]).toLowerCase() : '';

  let brandInContent = false, matchedBrand = null, brandSurfaces = 0;
  for (const [key, name] of BRAND_KEYS_SCAN) {
    if (key.length < 3 && !['fpt','mb'].includes(key)) continue;
    const official = BRAND_OFFICIAL_SCAN[key] || [];
    const isOfficial = official.some(d => currentOnlyDomain === d || currentOnlyDomain.endsWith('.' + d));
    if (isOfficial) continue;
    let count = 0;
    if (title.includes(key)) count++;
    if (metaDesc.includes(key)) count++;
    if (h1.includes(key)) count++;
    if (count > 0) { brandInContent = true; if (count > brandSurfaces) { brandSurfaces = count; matchedBrand = name; } }
  }
  dom.brandInContent = brandInContent; dom.brandSurfaces = brandSurfaces; dom.matchedBrand = matchedBrand;

  // ═══ Scam content (Vietnamese) ═══
  let bodyText = '';
  const bodyMatch = maxHtml.match(/<body[^>]*>([\s\S]*?)<\/body>/i);
  bodyText = _normalizeText(bodyMatch ? bodyMatch[1].slice(0, 60000) : maxHtml.slice(0, 60000));
  const scamHits = [];
  for (const p of VN_SCAM_PATTERNS) { if (p.re.test(bodyText)) scamHits.push(p.label); }
  dom.scamContentHits = scamHits; dom.scamContentRisk = scamHits.length;
  
  const patternScamVal = scamHits.length >= 2 ? '2' : (scamHits.length === 1 ? '0' : '-1');
  const keywordScamVal = result['Scam Content'] || '-1';
  if (patternScamVal === '2' || keywordScamVal === '2') {
    result['Scam Content'] = '2';
  } else if (patternScamVal === '0' || keywordScamVal === '0') {
    result['Scam Content'] = '0';
  } else {
    result['Scam Content'] = '-1';
  }
  dom.contentRich = bodyText.length > 200;

  // ═══ Meta refresh redirect ═══
  dom.metaRefreshRedirect = false;
  const metaRefresh = maxHtml.match(/<meta[^>]+http-equiv\s*=\s*["']refresh["'][^>]+content\s*=\s*["']([^"']+)["']/i);
  if (metaRefresh) {
    const urlPart = metaRefresh[1].match(/url\s*=\s*([^;]+)/i);
    if (urlPart) { try { const target = new URL(urlPart[1].trim().replace(/^['"]|['"]$/g,''), urlString); if (_isExternal(target.hostname.replace(/^www\./,''))) dom.metaRefreshRedirect = true; } catch {} }
  }

  // ═══ Obfuscation analysis (inline scripts) ═══
  let maxConf = 0, hasObf = false;
  const inlineScripts = [...maxHtml.matchAll(/<script(?![^>]*\ssrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi)];
  for (const m of inlineScripts) {
    const code = m[1]; if (!code || code.length < 80) continue;
    let conf = 0;
    if ((code.match(/\\x[0-9a-fA-F]{2}/g) || []).length > 15 || (code.match(/\\u[0-9a-fA-F]{4}/g) || []).length > 15) conf += 30;
    if (/unescape\s*\(|String\.fromCharCode\s*\(/i.test(code)) conf += 25;
    if (/atob\s*\(/i.test(code)) conf += code.length > 2000 ? 15 : 8;
    if (/eval\s*\(/i.test(code)) conf += conf > 0 ? 25 : 10;
    if (code.length > 1500 && (code.match(/\n/g) || []).length < 4) conf += 20;
    maxConf = Math.max(maxConf, conf);
    if (conf >= 60) hasObf = true;
  }
  dom.obfuscatedScript = hasObf; dom.jsRiskScore = maxConf;
  result['Obfuscated Script'] = hasObf ? '1' : (maxConf >= 40 ? '0' : '-1');
  result['JavaScript Risk'] = maxConf >= 60 ? '1' : (maxConf >= 35 ? '2' : '-1');

  // ═══ Dangerous download ═══
  const htmlLower = maxHtml.toLowerCase();
  dom.downloadFile = /\.exe|\.scr|\.bat|\.apk|\.msi|\.dll/i.test(htmlLower) && /download|href/i.test(htmlLower);
  dom.archiveDownload = /\.zip|\.rar|\.7z/i.test(htmlLower) && /download|href/i.test(htmlLower);

  // ═══ Favicon from external ═══
  result['Favicon'] = '-1';
  const faviconLink = maxHtml.match(/<link[^>]+rel\s*=\s*["'][^"']*icon[^"']*["'][^>]+href\s*=\s*["']([^"']+)["']/i);
  if (faviconLink) { const fHost = _hostOf(faviconLink[1]); if (_isExternal(fHost)) result['Favicon'] = '0'; }

  // ═══ Counts ═══
  const linkWarnings = aExt;
  const scriptWarnings = extRes;
  const imageWarnings = imgExt;
  const iframeDanger = iframeRiskScore >= 40 ? 1 : 0;
  const iframeWarning = iframeRiskScore > 0 && iframeRiskScore < 40 ? 1 : 0;
  const formDanger = hijackFound ? 1 : 0;
  const formWarning = sensitiveFormCount;
  dom.counts = {
    hiddenIframes: dom.hiddenIframe ? 1 : 0, totalIframes: allIframes.length, iframeRiskScore,
    sensitiveForms: sensitiveFormCount, totalForms: allForms.length,
    externalAnchors: aExt, totalAnchors: aTotal,
    externalScripts: extRes, totalScripts: totalRes,
    externalImages: imgExt, totalImages: imgTotal,
    scamContentHits: scamHits.length, jsRiskScore: maxConf,
    hiddenForms: hiddenFormFound ? 1 : 0,
    suspiciousLinks: 0, deceptiveLinks: deceptiveLinks.length,
    permissionRequests: 0,
    links: { total: aTotal, safe: Math.max(0, aTotal - linkWarnings), warning: linkWarnings, dangerous: 0 },
    scripts: { total: totalRes, safe: Math.max(0, totalRes - scriptWarnings), warning: scriptWarnings, dangerous: 0 },
    images: { total: imgTotal, safe: Math.max(0, imgTotal - imageWarnings), warning: imageWarnings, dangerous: 0 },
    iframes: { total: allIframes.length, safe: Math.max(0, allIframes.length - iframeWarning - iframeDanger), warning: iframeWarning, dangerous: iframeDanger },
    forms: { total: allForms.length, safe: Math.max(0, allForms.length - formWarning - formDanger), warning: formWarning, dangerous: formDanger },
  };

  return { result, dom };
};

// ─────────────────────────────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════
// CUSTOM URL SCAN — HIDDEN TAB DEEP SCAN
// Tái sử dụng hoàn toàn engine Realtime Scan:
//   chrome.tabs.create({ active: false }) → content scripts inject tự động
//   → classify() → dwell 6s → finalizeDeepScan() → lưu urlScanResult
// ═══════════════════════════════════════════════════════════════════════════

const DEEP_SCAN_HARD_TIMEOUT_MS = 15_000; // 15 giây hard timeout tổng
const DEEP_SCAN_DWELL_MS        =  2_500; // 2.5 giây dwell sau khi page load

/**
 * Khởi động Custom URL Deep Scan bằng hidden tab.
 * Tab không active → người dùng không bị chuyển focus.
 * Kết quả được lưu vào urlScanResult khi finalizeDeepScan() chạy.
 */
const startHiddenTabScan = async (urlString) => {
  logger.info(`[HIDDEN_TAB_SCAN_START] url=${urlString}`);
  try {
    const tab = await chrome.tabs.create({ url: urlString, active: false });
    const tabId = tab.id;

    // Hard timeout — phòng tab không bao giờ load xong
    const hardTimeout = setTimeout(async () => {
      logger.warn(`[HIDDEN_TAB_TIMEOUT] tabId=${tabId} url=${urlString}`);
      await finalizeDeepScan(tabId);
    }, DEEP_SCAN_HARD_TIMEOUT_MS);

    // Đăng ký vào deepScanTabs — classify() sẽ tự detect và lưu interim
    deepScanTabs.set(tabId, { url: urlString, hardTimeout, dwellTimer: null });

    logger.info(`[HIDDEN_TAB_CREATED] tabId=${tabId} url=${urlString}`);
  } catch (e) {
    logger.error(`[HIDDEN_TAB_CREATE_FAIL] url=${urlString}`, e.message);
    // Fallback: đánh dấu low-confidence thay vì crash
    await setUrlScanResult(urlString, {
      status: 'LOW_CONFIDENCE',
      isPhish: false,
      legitimatePercent: null,
      confidence: 15,
      result: {},
      summary: 'Không thể khởi động quét sâu. Hãy thử lại hoặc truy cập trang trực tiếp để xem kết quả.',
      url: urlString,
      scanSource: 'CUSTOM_URL',
      updatedAt: Date.now(),
    });
  }
};

  // ─── EVENT LISTENERS ──────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'ANALYSIS_RESULT' || request.type === 'ANALYSIS_UPDATE') {
    const tabId = sender.tab ? sender.tab.id : null;
    const tabUrl = sender.tab ? sender.tab.url : null;
    if (!tabId) { sendResponse({ ok:false }); return true; }
    const isUpdate = request.type === 'ANALYSIS_UPDATE';

    if (!isUpdate) {
      setTabState(tabId, { status: ANALYSIS_STATUS.ANALYZING, result: request.result, url: tabUrl, isPhish: false, legitimatePercent: null })
        .then(() => classify(tabId, request.result, tabUrl, request.dom, false))
        .then(() => sendResponse({ ok:true }))
        .catch(err => { logger.error('ANALYSIS_RESULT', err); sendResponse({ ok:false }); });
    } else {
      getTabState(tabId).then(currentState => {
        return setTabState(tabId, { ...(currentState || {}), status: ANALYSIS_STATUS.ANALYZING, result: request.result, url: tabUrl });
      })
      .then(() => classify(tabId, request.result, tabUrl, request.dom, true))
      .then(() => sendResponse({ ok:true }))
      .catch(err => { logger.error('ANALYSIS_UPDATE', err); sendResponse({ ok:false }); });
    }
    return true;
  }

  if (request.type === 'GET_TAB_STATE') {
    const tabId = request.tabId; if (!tabId) { sendResponse(null); return true; }
    getTabState(tabId).then(sendResponse).catch(()=>sendResponse(null)); return true;
  }
  if (request.type === 'SET_WHITELIST_TEMP') {
    const tabId = request.tabId; if (!tabId) { sendResponse({ ok:false }); return true; }
    Promise.resolve(riskBlockAllowUntil.set(tabId, Date.now() + RISK_BLOCK_ALLOW_MS))
      .then(() => setTabState(tabId, { status: ANALYSIS_STATUS.IDLE, isWhiteList:null, isBlocked:null, url:null }))
      .then(()=>sendResponse({ok:true})).catch(()=>sendResponse({ok:false})); return true;
  }
  if (request.type === 'COMMUNITY_REPORT') {
    const payload = request.payload || {};
    fetch(`${BACKEND_BASE}/api/report`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
      .then(r => r.json()).then(data => sendResponse({ ok:true, data })).catch(err => { logger.warn('COMMUNITY_REPORT', err.message); sendResponse({ ok:false }); });
    return true;
  }
  if (request.type === 'SET_ICON') {
    chrome.action.setIcon({ path: request.path, tabId: request.tabId }).catch(()=>{});
    sendResponse({ ok:true }); return true;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // CUSTOM URL SCAN — Hidden Tab Deep Scan (tái sử dụng engine Realtime)
  // ═══════════════════════════════════════════════════════════════════════
  if (request.type === 'SCAN_URL') {
    const urlString = request.url;
    if (!urlString) { sendResponse({ ok: false, error: 'Missing url' }); return true; }

    logger.info(`[SCAN_JOB_CREATED] url=${urlString}`);
    sendResponse({ ok: true });

    (async () => {
      try {
        const domain = getDomain(urlString);
        const registrable = getRegistrable(domain);

        // 1. Kiểm tra whitelist ngay
        let inCldWhitelist = false;
        for (const w of whiteListingSet) { if (w.includes(domain) || w.includes(registrable)) { inCldWhitelist = true; break; } }
        if (inCldWhitelist || (typeof REPUTATION_WHITELIST !== 'undefined' && REPUTATION_WHITELIST.has(registrable))) {
          await setUrlScanResult(urlString, { status: 'SUCCESS', isWhiteList: domain, isPhish: false, legitimatePercent: 100, confidence: 95, listType: 'whitelist', result: {}, summary: 'Trang nằm trong danh sách tin cậy.', url: urlString, scanSource: 'CUSTOM_URL', updatedAt: Date.now() });
          return;
        }

        // 2. Kiểm tra blacklist ngay
        if (_isKnownBadUrl(urlString)) {
          await setUrlScanResult(urlString, { status: 'SUCCESS', isPhish: true, legitimatePercent: 5, confidence: 95, result: {}, summary: 'URL nằm trong danh sách đen đã xác nhận.', url: urlString, scanSource: 'CUSTOM_URL', updatedAt: Date.now() });
          return;
        }

        // 3. Kiểm tra cache LIVE (kết quả từ lần realtime scan trước)
        const cached = await getUrlCache(urlString, 'LIVE');
        if (cached) {
          await setUrlScanResult(urlString, { status: 'SUCCESS', ...cached, url: urlString, scanSource: 'CUSTOM_URL', updatedAt: Date.now() });
          return;
        }

        // 4. Đánh dấu đang quét
        await setUrlScanResult(urlString, { status: 'ANALYZING', isPhish: false, legitimatePercent: null, confidence: 0, result: {}, url: urlString, scanSource: 'CUSTOM_URL', updatedAt: Date.now() });

        // 5. Khởi động Hidden Tab Deep Scan — engine y hệt Realtime
        await startHiddenTabScan(urlString);

      } catch (err) {
        logger.error(`[SCAN_URL FAILED] ${urlString}:`, err);
        await setUrlScanResult(urlString, { status: 'FAILED', isPhish: false, legitimatePercent: null, confidence: 0, result: {}, url: urlString, scanSource: 'CUSTOM_URL', updatedAt: Date.now() });
      }
    })();
    return true;
  }

  if (request.type === 'GET_URL_SCAN_STATE') {
    const urlString = request.url;
    if (!urlString) { sendResponse(null); return true; }
    getUrlScanResult(urlString).then(state => { sendResponse(state || null); }).catch(() => sendResponse(null)); return true;
  }

  if (request.type === 'CLEAR_URL_SCAN_RESULT') {
    const urlString = request.url;
    if (urlString) { removeUrlScanResult(urlString).catch(() => {}); }
    sendResponse({ ok: true }); return true;
  }
});




// Redirect chain tracking
chrome.webRequest.onBeforeRequest.addListener((details) => {
  if (details.type === 'main_frame' && details.tabId >= 0) { redirectChains.set(details.tabId, [details.url]); }
}, { urls: ['*://*/*'], types: ['main_frame'] });

chrome.webRequest.onBeforeRedirect.addListener((details) => {
  if (details.type === 'main_frame' && details.tabId >= 0 && details.redirectUrl) {
    const chain = redirectChains.get(details.tabId) || []; if (!chain.includes(details.redirectUrl)) chain.push(details.redirectUrl); redirectChains.set(details.tabId, chain);
  }
}, { urls: ['*://*/*'], types: ['main_frame'] });

chrome.tabs.onRemoved.addListener((tabId) => {
  redirectChains.delete(tabId);
  riskBlockAllowUntil.delete(tabId);
  // Nếu tab bị đóng, hãy finalize để kết quả không bị mất. Không xoá tabState vội để classify chạy xong.
  if (deepScanTabs.has(tabId)) {
    const meta = deepScanTabs.get(tabId);
    if (meta.dwellTimer) clearTimeout(meta.dwellTimer);
    if (meta.hardTimeout) clearTimeout(meta.hardTimeout);
    finalizeDeepScan(tabId).catch(() => {});
  } else {
    removeTabState(tabId);
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading' && changeInfo.url) {
    redirectChains.set(tabId, [changeInfo.url]);
    // Không đưa deepScan tab về ANALYZING khi load lại — giữ nguyên trạng thái
    if (!deepScanTabs.has(tabId)) {
      setTabState(tabId, { status: ANALYSIS_STATUS.ANALYZING, result: null, url: changeInfo.url, isPhish: false, legitimatePercent: null }).catch(()=>{});
    }
  }
  // Khi deepScan tab load xong: bắt đầu Dwell Timer
  if (changeInfo.status === 'complete' && deepScanTabs.has(tabId)) {
    const meta = deepScanTabs.get(tabId);
    if (!meta.dwellTimer) {
      logger.info(`[DEEP_SCAN_DWELL_START] tabId=${tabId} url=${meta.url}`);
      meta.dwellTimer = setTimeout(() => {
        logger.info(`[DEEP_SCAN_DWELL_DONE] tabId=${tabId}`);
        if (meta.hardTimeout) clearTimeout(meta.hardTimeout);
        try { chrome.tabs.remove(tabId); } catch(e) {}
      }, DEEP_SCAN_DWELL_MS); // dwell để tích lũy behavioral signals
    }
  }
});

chrome.runtime.onConnect.addListener((port) => {
  switch (port.name) {
    case PORT_REDIRECT: port.onMessage.addListener((msg) => { chrome.tabs.query({ currentWindow:true, active:true }, ([tab]) => { if (tab && msg.redirect) chrome.tabs.update(tab.id, { url: msg.redirect }); }); }); break;
    case PORT_CLOSE_TAB: port.onMessage.addListener((msg) => { if (msg.close_tab) chrome.tabs.query({ currentWindow:true, active:true }, ([tab]) => { if (tab) chrome.tabs.remove(tab.id); }); }); break;
  }
});

chrome.webRequest.onBeforeRequest.addListener(safeCheck, { urls: ['*://*/*'], types: ['main_frame'] });

// Download risk guard
const DANGEROUS_DOWNLOAD_EXTS = ['.exe', '.scr', '.bat', '.cmd', '.apk', '.jar', '.ps1', '.msi', '.dll', '.vbs', '.zip', '.rar', '.7z'];
const pendingDownloads = new Map();
const _downloadExt = (u, filename='', mime='') => {
  const raw = (filename || u || '').split('?')[0].split('#')[0].toLowerCase();
  const doubleExt = /\.(pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|jpeg|png|gif|txt|rtf)\.(exe|scr|bat|cmd|ps1|vbs|jar|apk|msi|dll)$/i.exec(raw);
  if (doubleExt) return '.' + doubleExt[2].toLowerCase();
  const ext = DANGEROUS_DOWNLOAD_EXTS.find(ext => raw.endsWith(ext)); if (ext) return ext;
  const m = String(mime || '').toLowerCase();
  if (/application\/(x-msdownload|x-msdos-program|x-msi|vnd.android.package-archive|java-archive|x-sh|x-bat|x-powershell|zip|x-7z-compressed|vnd.rar)/.test(m)) return m.includes('zip') ? '.zip' : (m.includes('7z') ? '.7z' : (m.includes('rar') ? '.rar' : '.bin'));
  return null;
};
const _isDownloadFromRiskyContext = async (item) => {
  try {
    const tabs = await chrome.tabs.query({ currentWindow:true, active:true }); const tab = tabs && tabs[0];
    const state = tab ? await getTabState(tab.id) : null;
    const itemHost = createUrlObject(item.finalUrl || item.url || '')?.hostname || '';
    const tabHost = createUrlObject((state && state.url) || (tab && tab.url) || '')?.hostname || '';
    const sameContext = item.referrer ? ((createUrlObject(item.referrer)?.hostname || '') === tabHost) : (itemHost === tabHost || !itemHost || !tabHost);
    if (state && sameContext && (state.isPhish || state.riskScore >= 30 || state.legitimatePercent <= 55)) return true;
    const local = typeof analyzeUrl !== 'undefined' ? analyzeUrl(item.finalUrl || item.url || '') : { findings: [] };
    return !!(local.findings || []).find(f => ['DangerousDownload','Typosquat','Homograph','BrandInDomain'].includes(f.key));
  } catch (_) { return false; }
};
if (chrome.downloads && chrome.downloads.onCreated) {
  chrome.downloads.onCreated.addListener(async (item) => {
    const ext = _downloadExt(item.finalUrl || item.url, item.filename, item.mime); if (!ext) return;
    const risky = await _isDownloadFromRiskyContext(item); if (!risky) return;
    try { chrome.downloads.pause(item.id); } catch (_) {}
    const nid = `download-risk-${item.id}`; pendingDownloads.set(nid, item.id);
    chrome.notifications.create(nid, { type:'basic', iconUrl: chrome.runtime.getURL('assets/antiScamLogo.png'), title:'Cảnh báo tải xuống', message:`File ${ext.toUpperCase()} từ website đáng ngờ có thể gây hại.`, buttons:[{ title:'Tiếp tục tải' }, { title:'Hủy tải' }], requireInteraction:true }).catch(()=>{});
  });
  chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
    if (!pendingDownloads.has(notificationId)) return; const id = pendingDownloads.get(notificationId); pendingDownloads.delete(notificationId);
    if (buttonIndex === 0) chrome.downloads.resume(id).catch(()=>{}); else chrome.downloads.cancel(id).catch(()=>{});
    chrome.notifications.clear(notificationId).catch(()=>{});
  });
  chrome.notifications.onClosed.addListener((notificationId) => {
    if (pendingDownloads.has(notificationId)) { const id = pendingDownloads.get(notificationId); pendingDownloads.delete(notificationId); chrome.downloads.cancel(id).catch(()=>{}); }
  });
}

chrome.runtime.onStartup.addListener(() => startup().catch(()=>{}));
chrome.runtime.onInstalled.addListener(() => {
  startup().catch(()=>{});
  chrome.notifications.create({ type:'basic', iconUrl: chrome.runtime.getURL('assets/antiScamLogo.png'), title: 'Cài đặt thành công v2.0!', message: 'AntiScam v2.0 — engine Trust/Risk/Confidence đã sẵn sàng.' });
});

startup().catch(()=>{});

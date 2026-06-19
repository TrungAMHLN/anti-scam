/* global chrome */
/* global psl */

importScripts('heuristic.js'); // Engine V2: computeScore

// ─────────────────────────────────────────────────────────────────────────────
// Logger
// ─────────────────────────────────────────────────────────────────────────────
const IS_DEV = !('update_url' in chrome.runtime.getManifest());
const logger = {
  info: (...a) => IS_DEV && console.info('[AntiScam]', ...a),
  warn: (...a) => IS_DEV && console.warn('[AntiScam]', ...a),
  error: (...a) => IS_DEV && console.error('[AntiScam]', ...a),
};

// ─────────────────────────────────────────────────────────────────────────────
// State Machine & Hằng số
// ─────────────────────────────────────────────────────────────────────────────
const ANALYSIS_STATUS = Object.freeze({ IDLE:'IDLE', ANALYZING:'ANALYZING', SUCCESS:'SUCCESS', FAILED:'FAILED', OFFLINE:'OFFLINE' });
const BLACKLIST_TTL_MS = 60*60*1000, OPENPHISH_TTL_MS = 15*60*1000, CLASSIFIER_TTL_MS = 5*60*1000;
const RESULT_CACHE_TTL_MS = 10*60*1000, INTEL_CACHE_TTL_MS = 30*60*1000, FETCH_TIMEOUT_MS = 10_000, MAX_RETRIES = 3;
const RESULT_CACHE_SCHEMA = 2;
const API_BASE = 'https://api.chongluadao.vn';
const BACKEND_BASE = API_BASE;
const OPENPHISH_URL = 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt';
const PORT_REDIRECT = 'REDIRECT_PORT_NAME', PORT_CLOSE_TAB = 'CLOSE_TAB_PORT_NAME';
const RISK_BLOCK_THRESHOLD = 55;
const RISK_BLOCK_ALLOW_MS = 5 * 60 * 1000;
const riskBlockAllowUntil = new Map(); // tabId -> timestamp

// ─────────────────────────────────────────────────────────────────────────────
// Circuit Breaker
// ─────────────────────────────────────────────────────────────────────────────
const circuitBreaker = { antiScamApi:{failures:0,openUntil:0}, openPhish:{failures:0,openUntil:0}, backendIntel:{failures:0,openUntil:0} };
const CB_THRESHOLD = 3, CB_TIMEOUT_MS = 30_000;
const checkCB = (s) => { const cb = circuitBreaker[s]; if (Date.now() < cb.openUntil) { logger.warn(`CB OPEN ${s}`); return false; } return true; };
const recFail = (s) => { const cb = circuitBreaker[s]; cb.failures++; if (cb.failures >= CB_THRESHOLD) { cb.openUntil = Date.now() + CB_TIMEOUT_MS; logger.error(`CB TRIPPED ${s}`); } };
const recOK = (s) => { circuitBreaker[s].failures = 0; };

const fetchWithRetry = async (u, source, isJson=true, retries=MAX_RETRIES) => {
  if (!checkCB(source)) return null;
  for (let attempt=0; attempt<retries; attempt++) {
    try {
      const ctrl = new AbortController(); const t = setTimeout(()=>ctrl.abort(), FETCH_TIMEOUT_MS);
      const res = await fetch(u, { signal: ctrl.signal }); clearTimeout(t);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = isJson ? await res.json() : await res.text();
      recOK(source); return data;
    } catch (err) {
      logger.warn(`fetch ${attempt+1}/${retries} fail ${u}: ${err.message}`);
      if (attempt < retries-1) await new Promise(r=>setTimeout(r, 1000*Math.pow(2,attempt)));
    }
  }
  recFail(source); return null;
};

// ─────────────────────────────────────────────────────────────────────────────
// Storage helpers
// ─────────────────────────────────────────────────────────────────────────────
const getTabState = async (tabId) => { try { const d = await chrome.storage.session.get(`tab_${tabId}`); return d[`tab_${tabId}`] || null; } catch(e){ return null; } };
const setTabState = async (tabId, state) => { try { await chrome.storage.session.set({ [`tab_${tabId}`]: { ...state, updatedAt: Date.now() } }); } catch(e){ logger.error('setTabState', e); } };
const removeTabState = async (tabId) => { try { await chrome.storage.session.remove(`tab_${tabId}`); } catch(e){} };

const getUrlCache = async (url) => {
  try {
    let h=0; for (let i=0;i<url.length;i++){ h=((h<<5)-h)+url.charCodeAt(i); h|=0; }
    const d = await chrome.storage.session.get(`cache_${h}`);
    const it = d[`cache_${h}`]; if (it && it.schemaVersion === RESULT_CACHE_SCHEMA && Date.now()-it.timestamp < RESULT_CACHE_TTL_MS) return it;
  } catch(e){}
  return null;
};
const setUrlCache = async (url, data) => {
  try {
    let h=0; for (let i=0;i<url.length;i++){ h=((h<<5)-h)+url.charCodeAt(i); h|=0; }
    await chrome.storage.session.set({ [`cache_${h}`]: { ...data, schemaVersion: RESULT_CACHE_SCHEMA, timestamp: Date.now() } });
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
      if (typeof c === 'number') return { ageDays: c, source: 'rdap-cache' };
      return c;
    }
    const ctrl = new AbortController(); const t = setTimeout(()=>ctrl.abort(), 3500);
    const res = await fetch(`https://rdap.org/domain/${base}`, { signal: ctrl.signal }); clearTimeout(t);
    if (!res.ok) return { ageDays: -1, source: 'rdap', status: 'nodata' };
    const data = await res.json();
    const registrationDate = _pickRdapDate(data && data.events, ['registration']);
    const expirationDate = _pickRdapDate(data && data.events, ['expiration', 'expiry']);
    const ageDays = registrationDate ? (Date.now() - new Date(registrationDate).getTime())/(1000*60*60*24) : -1;
    const info = { ageDays, registrationDate, expirationDate, source: 'rdap' };
    await chrome.storage.session.set({ [key]: info });
    return info;
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
    const data = await fetchWithRetry(`${BACKEND_BASE}/v1/intel?url=${payload}`, 'backendIntel', true, 1);
    if (data && data.status !== 'error') {
      await chrome.storage.session.set({ [key]: { data, timestamp: Date.now() } });
      return data;
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
// Classifier ML (tín hiệu PHỤ)
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
    logger.info(`Cache: ${blackListing.length} CLD, ${blackListingSet.size} OP, ${whiteListingSet.size} WL`);
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
      if (data && Array.isArray(data)) { const list = data.map(i=>i.url).filter(Boolean); await chrome.storage.local.set({ blacklist:list, blacklistTime:Date.now() }); blackListing = list; logger.info(`BL: ${list.length}`); }
    }
    const { openPhishTime } = await chrome.storage.local.get('openPhishTime');
    if (!openPhishTime || Date.now()-openPhishTime >= OPENPHISH_TTL_MS) {
      const text = await fetchWithRetry(OPENPHISH_URL, 'openPhish', false);
      if (text) { const list = text.split('\n').map(l=>l.trim()).filter(l=>l.length>0); await chrome.storage.local.set({ openPhishList:list, openPhishTime:Date.now() }); list.forEach(u=>blackListingSet.add(u)); logger.info(`OP: ${list.length}`); }
    }
    const { whitelistTime } = await chrome.storage.local.get('whitelistTime');
    if (!whitelistTime || Date.now()-whitelistTime >= BLACKLIST_TTL_MS) {
      const data = await fetchWithRetry(`${API_BASE}/v1/whitelist`, 'antiScamApi', true);
      if (data && Array.isArray(data)) { const list = data.map(i=>i.url).filter(Boolean); await chrome.storage.local.set({ whitelist:list, whitelistTime:Date.now() }); whiteListingSet.clear(); list.forEach(u=>whiteListingSet.add(u)); logger.info(`WL: ${list.length}`); }
    }
  } catch(e){ logger.error('startup', e); }
  finally { startupInProgress = false; }
};

// ═══════════════════════════════════════════════════════════════════════════
// REDIRECT CHAIN TRACKING  (Vấn đề 7)
// ═══════════════════════════════════════════════════════════════════════════
const redirectChains = new Map(); // tabId -> string[]
const getRedirectChain = (tabId) => redirectChains.get(tabId) || [];

// ═══════════════════════════════════════════════════════════════════════════
// REPUTATION ENGINE  (Vấn đề 11)
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
  const out = [];
  const seen = new Set();
  if (!Array.isArray(links)) return out;
  for (const raw of links.slice(0, 160)) {
    if (!raw || seen.has(raw)) continue;
    seen.add(raw);
    let host = '';
    try { host = new URL(raw).hostname; } catch (_) {}
    const knownBad = _isKnownBadUrl(raw);
    let linkReg = '';
    try { linkReg = getRegistrable(host); } catch (_) {}
    const pageReg = getRegistrable(pageDomain || '');
    const benignHost = host && (linkReg === pageReg || (typeof isTrustedHost !== 'undefined' && isTrustedHost(host)) || (typeof REPUTATION_WHITELIST !== 'undefined' && REPUTATION_WHITELIST.has(linkReg)) || (typeof isOfficialBrandDomain !== 'undefined' && !!isOfficialBrandDomain(host)));
    const local = (!knownBad && benignHost) ? { findings: [] } : (typeof analyzeUrl !== 'undefined' ? analyzeUrl(raw) : { findings: [] });
    const suspicious = (local.findings || []).filter(f =>
      ['DangerousDownload','Typosquat','Homograph','BrandInDomain','BrandInPath','Punycode','UnicodeHost','VNScamKeyword','IPHost','OpenRedirect'].includes(f.key)
    );
    let keys = suspicious.map(f => f.key).slice(0, 5);
    let points = (knownBad ? 45 : 0) + suspicious.reduce((sum, f) => sum + Math.min(f.points || 0, 18), 0);
    const strongLinkSignal = suspicious.some(f => ['DangerousDownload','Typosquat','Homograph','BrandInDomain','BrandInPath','OpenRedirect'].includes(f.key));
    if (!knownBad && strongLinkSignal && host && !benignHost && out.length < 3) {
      try {
        const age = await fetchDomainAge(host);
        if (age && age.ageDays >= 0 && age.ageDays < 14) { keys.push('LinkNewDomain'); points += 10; }
      } catch (_) {}
    }
    if (knownBad || keys.length) {
      out.push({ url: raw, host, knownBad, keys: keys.slice(0, 6), points });
    }
    if (out.length >= 12) break;
  }
  return out;
};

const _analyzeRedirectHopRisk = (chain) => {
  if (!Array.isArray(chain)) return { bad: false, badHops: [] };
  const badHops = [];
  for (const u of chain) {
    if (_isKnownBadUrl(u)) badHops.push(u);
  }
  return { bad: badHops.length > 0, badHops: badHops.slice(0, 6) };
};

const resolveReputation = (domain, registrable, urlString, backendIntel = null) => {
  const inBuiltWhitelist = typeof REPUTATION_WHITELIST !== 'undefined' && REPUTATION_WHITELIST.has(registrable);
  // CLD whitelist (tải từ API)
  let inCldWhitelist = false;
  for (const w of whiteListingSet) { if (w.includes(domain) || w.includes(registrable)) { inCldWhitelist = true; break; } }
  // Blacklist
  let inBlacklist = blackListingSet.has(urlString) || blackListingSet.has(urlString.replace(/\/$/,''));
  // wildcard
  if (!inBlacklist && blackListing.length) {
    for (const b of blackListing) { if (urlString.includes(b.replace(/\/$/,''))) { inBlacklist = true; break; } }
  }
  const officialBrand = typeof isOfficialBrandDomain !== 'undefined' ? isOfficialBrandDomain(domain) : null;
  const intel = backendIntel || {};
  const malware = intel.malware || {};
  const dns = intel.dns || {};
  const communityReports = intel.community && intel.community.reportCount ? intel.community.reportCount : 0;
  return {
    inWhitelist: inBuiltWhitelist || inCldWhitelist,
    inBlacklist: inBlacklist || !!malware.dangerous,
    isOfficialBrand: !!officialBrand,
    malware,
    dns,
    community: intel.community || null,
    communityReports,
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
const isRiskBlockAllowed = (tabId) => {
  const until = riskBlockAllowUntil.get(tabId) || 0;
  if (Date.now() < until) return true;
  riskBlockAllowUntil.delete(tabId);
  return false;
};
const shouldAutoBlock = (assessment, reputation) => {
  if (!assessment || !reputation) return false;
  if (reputation.inWhitelist || reputation.isOfficialBrand) return false;
  const risk = assessment.riskScore || 0;
  const conf = assessment.confidence || 0;
  const finalScore = assessment.finalScore || 0;
  return conf >= 45 && (risk >= RISK_BLOCK_THRESHOLD || (finalScore <= 30 && risk >= 35));
};


// ═══════════════════════════════════════════════════════════════════════════
// CLASSIFICATION  —  ENGINE V2 (Trust / Risk / Confidence)
// ═══════════════════════════════════════════════════════════════════════════
const classify = async (tabId, featuresResult, urlString, domInput = {}, isUpdate = false) => {
  try {
    const domain = getDomain(urlString);
    const registrable = getRegistrable(domain);

    // 1. Whitelist (CLD) → an toàn tuyệt đối
    let inCldWhitelist = false;
    for (const w of whiteListingSet) { if (w.includes(domain) || w.includes(registrable)) { inCldWhitelist = true; break; } }
    if (inCldWhitelist) {
      await setTabState(tabId, { status: ANALYSIS_STATUS.SUCCESS, isWhiteList: domain, isPhish: false,
        legitimatePercent: 100, confidence: 95, result: {}, summary: 'Trang nằm trong danh sách tin cậy.', url: urlString });
      updateBadge(false, 100, tabId); return;
    }

    // 2. Cache (chỉ cho lần đầu, không cho update)
    if (!isUpdate) {
      const cached = await getUrlCache(urlString);
      if (cached) {
        await setTabState(tabId, { status: ANALYSIS_STATUS.SUCCESS, isPhish: cached.isPhish,
          legitimatePercent: cached.legitimatePercent, confidence: cached.confidence,
          riskScore: cached.riskScore || 0, trustScore: cached.trustScore || 0, trustContext: cached.trustContext || null,
          result: cached.result || {}, summary: cached.summary || '', explanations: cached.explanations || [], isUnknown: cached.isUnknown, url: urlString });
        updateBadge(cached.isPhish, cached.legitimatePercent, tabId);
        if (!isRiskBlockAllowed(tabId) && cached.riskScore >= RISK_BLOCK_THRESHOLD && cached.confidence >= 45) {
          blockingFunction(urlString, `Mức rủi ro ${cached.riskScore}/100`, tabId, { summary: cached.summary || 'Trang có nhiều tín hiệu nguy hiểm.' });
        }
        return;
      }
    }

    // 3. Domain age + reputation + redirect chain
    const prev = await getTabState(tabId);
    const rdapAge = await fetchDomainAge(domain);
    const backendIntel = await fetchBackendIntel(urlString, domain);
    const domainAge = mergeDomainAge(rdapAge, backendIntel && backendIntel.domainAge);
    const domainAgeDays = domainAge.ageDays != null ? domainAge.ageDays : -1;
    const reputation = resolveReputation(domain, registrable, urlString, backendIntel);
    const redirectChain = getRedirectChain(tabId);

    // 4. stabilityMs + risk-decay tracking (Vấn đề 9, 13)
    let analysisStart = prev && prev.analysisStart ? prev.analysisStart : Date.now();
    const prevRisk = prev && prev.riskScore != null ? prev.riskScore : 0;
    const stabilityMs = Date.now() - analysisStart;

    // 5. computeScore (engine chính)
    const enrichedDom = { ...(domInput || {}) };
    const suspiciousLinks = await _analyzePageLinks(enrichedDom.pageLinks || [], domain);
    if (suspiciousLinks.length) {
      enrichedDom.suspiciousLinks = suspiciousLinks;
      enrichedDom.suspiciousLinkCount = suspiciousLinks.length;
    }
    const redirectHopRisk = _analyzeRedirectHopRisk(redirectChain);
    if (redirectHopRisk.bad) {
      enrichedDom.redirectBadHop = true;
      enrichedDom.redirectBadHops = redirectHopRisk.badHops;
    }
    const assessment = computeScore(urlString, {
      dom: enrichedDom,
      domainAgeDays,
      domainAge,
      reputation,
      redirectChain,
      stabilityMs,
    });

    let riskScore = assessment.riskScore;
    let finalScore = assessment.finalScore;
    let confidence = assessment.confidence;

    // 6. ML (tín hiệu phụ — giảm FP, không tự kết luận)
    const resultValues = Object.entries(featuresResult || {})
      .filter(([k]) => k !== 'tab').map(([,v]) => parseInt(v));
    const clf = await fetchCLF();
    if (clf && resultValues.length) {
      try {
        const isPhishML = randomForest(clf).predict([resultValues])[0][0];
        if (isPhishML && riskScore < 40) { riskScore += 8; finalScore = Math.max(0, finalScore - 8); }
      } catch(e){ logger.warn('ML fail', e.message); }
    }

    // 7. Risk decay: nếu risk GIẢM so với lần trước → trang ổn định → reset timer
    //    nếu risk TĂNG (tín hiệu mới) → reset stability
    if (riskScore > prevRisk + 3) analysisStart = Date.now();

    // 8. MERGE result: giữ toàn bộ ~20 features từ features.js + overlay badges từ engine
    //    (trước đây bị ghi đè mất → giờ merge để hiển thị đầy đủ)
    const mergedResult = {};
    // Layer 1: features từ content script (IP, URL Length, Anchor, Request URL, ...)
    for (const k in (featuresResult || {})) { if (k !== 'tab') mergedResult[k] = featuresResult[k]; }
    // Layer 2: trust badges + risk badges từ engine (overlay — engine có quyền ưu tiên)
    for (const k in (assessment.result || {})) { mergedResult[k] = assessment.result[k]; }

    // 9. Lưu state
    const isPhish = finalScore <= 30;
    await setTabState(tabId, {
      status: ANALYSIS_STATUS.SUCCESS,
      isPhish,
      legitimatePercent: finalScore,
      confidence,
      trustScore: assessment.trustScore,
      riskScore,
      trustContext: assessment.trustContext,
      isUnknown: assessment.isUnknown,
      result: mergedResult,
      summary: assessment.summary,
      explanations: assessment.explanations || [],
      domainAge: assessment.domainAge || domainAge,
      reputation,
      redirectHops: assessment.redirectHops,
      counts: (() => {
        if (!enrichedDom || !enrichedDom.counts) return null;
        const counts = { ...enrichedDom.counts, suspiciousLinks: enrichedDom.suspiciousLinkCount || 0, deceptiveLinks: enrichedDom.deceptiveLinkCount || 0, permissionRequests: enrichedDom.permissionRequests ? enrichedDom.permissionRequests.length : 0 };
        if (counts.links) {
          counts.links = { ...counts.links };
          counts.links.dangerous = enrichedDom.suspiciousLinkCount || 0;
          counts.links.warning = Math.max(0, (counts.links.warning || 0) - counts.links.dangerous);
          counts.links.safe = Math.max(0, (counts.links.total || 0) - counts.links.warning - counts.links.dangerous);
        }
        return counts;
      })(),
      analysisStart,
      url: urlString,
    });

    // 10. Cache (chỉ lần đầu)
    if (!isUpdate) {
      await setUrlCache(urlString, { isPhish, legitimatePercent: finalScore, confidence, riskScore, trustScore: assessment.trustScore, trustContext: assessment.trustContext, result: mergedResult, summary: assessment.summary, explanations: assessment.explanations || [], isUnknown: assessment.isUnknown });
    }

    updateBadge(isPhish, finalScore, tabId);
    if (!isRiskBlockAllowed(tabId) && shouldAutoBlock(assessment, reputation)) {
      blockingFunction(urlString, `Mức rủi ro ${riskScore}/100`, tabId, { summary: assessment.summary || 'Trang có nhiều tín hiệu nguy hiểm.' });
    }
  } catch (err) {
    logger.error(`classify ${tabId}:`, err);
    await setTabState(tabId, { status: ANALYSIS_STATUS.FAILED, isPhish: false, legitimatePercent: null, confidence: 0,
      result: featuresResult || {}, summary: 'Không thể phân tích trang này.', url: urlString });
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Blocking & SafeCheck
// ─────────────────────────────────────────────────────────────────────────────
const blockingFunction = (url, blackSite, tabId, opts = {}) => {
  const message = { site: url, match: blackSite, title: url, lenient: inputBlockLenient, riskBlock: !!opts.summary,
    reason: opts.summary || '', favicon: `https://www.google.com/s2/favicons?domain=${url}` };
  setTabState(tabId, { status: ANALYSIS_STATUS.SUCCESS, isBlocked: url, isPhish: true,
    legitimatePercent: 0, confidence: 95, result: {}, summary: opts.summary || 'Trang này nằm trong danh sách đen đã xác nhận.', url }).catch(()=>{});
  chrome.tabs.update(tabId, { url: `${chrome.runtime.getURL('blocking.html')}#${JSON.stringify(message)}` }).catch(e=>logger.error('blocking', e));
};

const safeCheck = ({ url, tabId }) => {
  if (!url || url.startsWith('chrome://') || url.startsWith(chrome.runtime.getURL('/'))) return;
  if (blackListingSet.has(url) || blackListingSet.has(url.replace(/\/$/,''))) { blockingFunction(url, url, tabId); return; }
  if (!blackListing || !blackListing.length) return;
  const cur = createUrlObject(url); if (!cur) return;
  let curDom = ''; try { if (typeof psl!=='undefined') curDom = psl.parse(cur.host).domain || ''; } catch { curDom = cur.host; }
  const curPath = cur.href.replaceAll('/','');
  for (let i=0;i<blackListing.length;++i) {
    const bs = createUrlObject(blackListing[i]); if (!bs) continue;
    const prefix = bs.host.split('.')[0], suffix = bs.pathname;
    if (prefix === '%2A' && curDom) { const bd = bs.host.slice(4); if (bd === curDom) { blockingFunction(url, bs.host, tabId); return; } }
    if (suffix === '/*' && cur.host === bs.host) { blockingFunction(url, bs.host, tabId); return; }
    if (curPath && curPath === bs.href.replaceAll('/','')) { blockingFunction(url, bs.host, tabId); return; }
  }
};

// ═══════════════════════════════════════════════════════════════════════════
// Event Listeners
// ═══════════════════════════════════════════════════════════════════════════
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
      // Real-time update — chỉ recompute, không reset status/caching
      classify(tabId, request.result, tabUrl, request.dom, true)
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
    fetch(`${BACKEND_BASE}/v1/community-report`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: payload.url, domain: payload.domain, reason: payload.reason })
    }).then(r => r.json()).then(data => sendResponse({ ok:true, data })).catch(err => {
      logger.warn('COMMUNITY_REPORT', err.message); sendResponse({ ok:false });
    });
    return true;
  }
  if (request.type === 'SET_ICON') {
    chrome.action.setIcon({ path: request.path, tabId: request.tabId }).catch(()=>{});
    sendResponse({ ok:true }); return true;
  }
});

// Redirect chain tracking (Vấn đề 7)
chrome.webRequest.onBeforeRequest.addListener((details) => {
  if (details.type === 'main_frame' && details.tabId >= 0) {
    redirectChains.set(details.tabId, [details.url]);
  }
}, { urls: ['*://*/*'], types: ['main_frame'] });

chrome.webRequest.onBeforeRedirect.addListener((details) => {
  if (details.type === 'main_frame' && details.tabId >= 0 && details.redirectUrl) {
    const chain = redirectChains.get(details.tabId) || [];
    if (!chain.includes(details.redirectUrl)) chain.push(details.redirectUrl);
    redirectChains.set(details.tabId, chain);
  }
}, { urls: ['*://*/*'], types: ['main_frame'] });

chrome.tabs.onRemoved.addListener((tabId) => { removeTabState(tabId); redirectChains.delete(tabId); riskBlockAllowUntil.delete(tabId); });

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading' && changeInfo.url) {
    redirectChains.set(tabId, [changeInfo.url]);
    setTabState(tabId, { status: ANALYSIS_STATUS.ANALYZING, result: null, url: changeInfo.url, isPhish: false, legitimatePercent: null }).catch(()=>{});
  }
});

chrome.runtime.onConnect.addListener((port) => {
  switch (port.name) {
    case PORT_REDIRECT:
      port.onMessage.addListener((msg) => { chrome.tabs.query({ currentWindow:true, active:true }, ([tab]) => { if (tab && msg.redirect) chrome.tabs.update(tab.id, { url: msg.redirect }); }); });
      break;
    case PORT_CLOSE_TAB:
      port.onMessage.addListener((msg) => { if (msg.close_tab) chrome.tabs.query({ currentWindow:true, active:true }, ([tab]) => { if (tab) chrome.tabs.remove(tab.id); }); });
      break;
  }
});

chrome.webRequest.onBeforeRequest.addListener(safeCheck, { urls: ['*://*/*'], types: ['main_frame'] });


// Download risk guard — pause dangerous files from suspicious pages and ask user.
const DANGEROUS_DOWNLOAD_EXTS = ['.exe', '.scr', '.bat', '.cmd', '.apk', '.jar', '.ps1', '.msi', '.dll', '.vbs', '.zip', '.rar', '.7z'];
const pendingDownloads = new Map();
const _downloadExt = (u, filename='', mime='') => {
  const raw = (filename || u || '').split('?')[0].split('#')[0].toLowerCase();
  const doubleExt = /\.(pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|jpeg|png|gif|txt|rtf)\.(exe|scr|bat|cmd|ps1|vbs|jar|apk|msi|dll)$/i.exec(raw);
  if (doubleExt) return '.' + doubleExt[2].toLowerCase();
  const ext = DANGEROUS_DOWNLOAD_EXTS.find(ext => raw.endsWith(ext));
  if (ext) return ext;
  const m = String(mime || '').toLowerCase();
  if (/application\/(x-msdownload|x-msdos-program|x-msi|vnd.android.package-archive|java-archive|x-sh|x-bat|x-powershell|zip|x-7z-compressed|vnd.rar)/.test(m)) return m.includes('zip') ? '.zip' : (m.includes('7z') ? '.7z' : (m.includes('rar') ? '.rar' : '.bin'));
  return null;
};
const _isDownloadFromRiskyContext = async (item) => {
  try {
    const tabs = await chrome.tabs.query({ currentWindow:true, active:true });
    const tab = tabs && tabs[0];
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
    const ext = _downloadExt(item.finalUrl || item.url, item.filename, item.mime);
    if (!ext) return;
    const risky = await _isDownloadFromRiskyContext(item);
    if (!risky) return;
    try { chrome.downloads.pause(item.id); } catch (_) {}
    const nid = `download-risk-${item.id}`;
    pendingDownloads.set(nid, item.id);
    chrome.notifications.create(nid, {
      type:'basic', iconUrl: chrome.runtime.getURL('assets/antiScamLogo.png'),
      title:'Cảnh báo tải xuống',
      message:`File ${ext.toUpperCase()} từ website đáng ngờ có thể gây hại. Bạn có muốn tiếp tục tải không?`,
      buttons:[{ title:'Tiếp tục tải' }, { title:'Hủy tải' }], requireInteraction:true
    }).catch(()=>{});
  });
  chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
    if (!pendingDownloads.has(notificationId)) return;
    const id = pendingDownloads.get(notificationId); pendingDownloads.delete(notificationId);
    if (buttonIndex === 0) chrome.downloads.resume(id).catch(()=>{});
    else chrome.downloads.cancel(id).catch(()=>{});
    chrome.notifications.clear(notificationId).catch(()=>{});
  });
  chrome.notifications.onClosed.addListener((notificationId) => {
    if (pendingDownloads.has(notificationId)) {
      const id = pendingDownloads.get(notificationId); pendingDownloads.delete(notificationId);
      chrome.downloads.cancel(id).catch(()=>{});
    }
  });
}

chrome.runtime.onStartup.addListener(() => startup().catch(()=>{}));
chrome.runtime.onInstalled.addListener(() => {
  startup().catch(()=>{});
  chrome.notifications.create({ type:'basic', iconUrl: chrome.runtime.getURL('assets/antiScamLogo.png'),
    title: 'Cài đặt thành công v2.0!', message: 'AntiScam v2.0 — engine Trust/Risk/Confidence đã sẵn sàng.' });
});

startup().catch(()=>{});

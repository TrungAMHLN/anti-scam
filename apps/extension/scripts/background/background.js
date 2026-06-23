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
  error: (...a) => IS_DEV && console.error('[AntiScam]', ...a),
};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────
const ANALYSIS_STATUS = Object.freeze({ IDLE:'IDLE', ANALYZING:'ANALYZING', SUCCESS:'SUCCESS', FAILED:'FAILED', OFFLINE:'OFFLINE' });
const BLACKLIST_TTL_MS = 60*60*1000, OPENPHISH_TTL_MS = 15*60*1000, CLASSIFIER_TTL_MS = 5*60*1000;
const RESULT_CACHE_TTL_MS = 10*60*1000, INTEL_CACHE_TTL_MS = 30*60*1000, FETCH_TIMEOUT_MS = 10_000, MAX_RETRIES = 3;
const RESULT_CACHE_SCHEMA = 2;
const API_BASE = 'https://anti-scam-6iix.onrender.com';
const BACKEND_BASE = API_BASE;
const OPENPHISH_URL = 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt';
const PORT_REDIRECT = 'REDIRECT_PORT_NAME', PORT_CLOSE_TAB = 'CLOSE_TAB_PORT_NAME';
const RISK_BLOCK_THRESHOLD = 55;
const RISK_BLOCK_ALLOW_MS = 5 * 60 * 1000;
const riskBlockAllowUntil = new Map();
const ipRe = /^(\d{1,3}\.){3}\d{1,3}$/;

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
    const data = await fetchWithRetry(`${BACKEND_BASE}/v1/intel?url=${payload}`, 'backendIntel', true, 1);
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
  const inBuiltWhitelist = typeof REPUTATION_WHITELIST !== 'undefined' && REPUTATION_WHITELIST.has(registrable);
  let inCldWhitelist = false;
  for (const w of whiteListingSet) { if (w.includes(domain) || w.includes(registrable)) { inCldWhitelist = true; break; } }
  let inBlacklist = blackListingSet.has(urlString) || blackListingSet.has(urlString.replace(/\/$/,''));
  if (!inBlacklist && blackListing.length) { for (const b of blackListing) { if (urlString.includes(b.replace(/\/$/,''))) { inBlacklist = true; break; } } }
  const officialBrand = typeof isOfficialBrandDomain !== 'undefined' ? isOfficialBrandDomain(domain) : null;
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
      const cached = await getUrlCache(urlString);
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

    const assessment = computeScore(urlString, { dom: enrichedDom, domainAgeDays, domainAge, reputation, redirectChain, stabilityMs });

    let riskScore = assessment.riskScore, finalScore = assessment.finalScore, confidence = assessment.confidence;

    const resultValues = Object.entries(featuresResult || {}).filter(([k]) => k !== 'tab').map(([,v]) => parseInt(v));
    const clf = await fetchCLF();
    if (clf && resultValues.length) { try { const isPhishML = randomForest(clf).predict([resultValues])[0][0]; if (isPhishML && riskScore < 40) { riskScore += 8; finalScore = Math.max(0, finalScore - 8); } } catch(e){} }

    if (riskScore > prevRisk + 3) analysisStart = Date.now();

    const mergedResult = {};
    for (const k in (featuresResult || {})) { if (k !== 'tab') mergedResult[k] = featuresResult[k]; }
    for (const k in (assessment.result || {})) { mergedResult[k] = assessment.result[k]; }

    const isPhish = finalScore <= 30;
    await setTabState(tabId, {
      status: ANALYSIS_STATUS.SUCCESS, isPhish, legitimatePercent: finalScore, confidence,
      trustScore: assessment.trustScore, riskScore, trustContext: assessment.trustContext, isUnknown: assessment.isUnknown,
      result: mergedResult, summary: assessment.summary, explanations: assessment.explanations || [],
      domainAge: assessment.domainAge || domainAge, reputation,
      counts: (() => { if (!enrichedDom || !enrichedDom.counts) return null; const c = {...enrichedDom.counts, suspiciousLinks:enrichedDom.suspiciousLinkCount||0, deceptiveLinks:enrichedDom.deceptiveLinkCount||0}; if(c.links){c.links={...c.links};c.links.dangerous=enrichedDom.suspiciousLinkCount||0;c.links.warning=Math.max(0,(c.links.warning||0)-c.links.dangerous);c.links.safe=Math.max(0,(c.links.total||0)-c.links.warning-c.links.dangerous);} return c; })(),
      analysisStart, url: urlString,
    });

    if (!isUpdate) { await setUrlCache(urlString, { isPhish, legitimatePercent: finalScore, confidence, riskScore, trustScore: assessment.trustScore, trustContext: assessment.trustContext, result: mergedResult, summary: assessment.summary, explanations: assessment.explanations || [], isUnknown: assessment.isUnknown }); }
    updateBadge(isPhish, finalScore, tabId);

    if (!isRiskBlockAllowed(tabId) && shouldAutoBlock(assessment, reputation)) {
      try { const ti = await chrome.tabs.get(tabId); if (ti) blockingFunction(urlString, `Mức rủi ro ${riskScore}/100`, tabId, { summary: assessment.summary || 'Trang có nhiều tín hiệu nguy hiểm.' }); } catch(_) {}
    }
  } catch (err) {
    logger.error(`classify ${tabId}:`, err);
    await setTabState(tabId, { status: ANALYSIS_STATUS.FAILED, isPhish: false, legitimatePercent: null, confidence: 0, result: featuresResult || {}, summary: 'Không thể phân tích trang này.', url: urlString });
  }
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
    const res = await fetch(urlString, { signal: ctrl.signal, redirect: 'follow' });
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
  dom.sensitiveForm = sensitiveFound; dom.formHijack = hijackFound; dom.passwordField = pwField;
  dom.otpField = otpField; dom.cardField = cardField; dom.bankAccountField = bankField; dom.hiddenForm = hiddenFormFound;
  result['Sensitive Form'] = sensitiveFound ? (cardField || bankField ? '2' : '0') : '-1';
  result['Form Hijacking'] = hijackFound ? '1' : '-1';
  result['Hidden Form'] = hiddenFormFound ? '2' : '-1';

  // ═══ SFH / mailto ═══
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
  result['Scam Content'] = scamHits.length >= 2 ? '2' : (scamHits.length === 1 ? '0' : '-1');
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
    const compactCode = code.replace(/\s+/g, '');
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

/**
 * Phân tích URL bằng fetch + HTML parsing — KHÔNG MỞ TAB
 */
const fetchAndAnalyzeUrl = async (urlString) => {
  const domain = getDomain(urlString);
  const registrable = getRegistrable(domain);

  try {
    // 1. Kiểm tra whitelist
    let inCldWhitelist = false;
    for (const w of whiteListingSet) { if (w.includes(domain) || w.includes(registrable)) { inCldWhitelist = true; break; } }
    if (inCldWhitelist || (typeof REPUTATION_WHITELIST !== 'undefined' && REPUTATION_WHITELIST.has(registrable))) {
      logger.info(`[FEATURES_COLLECTED] url=${urlString} (whitelist)`);
      await setUrlScanResult(urlString, { status: 'SUCCESS', isWhiteList: domain, isPhish: false, legitimatePercent: 100, confidence: 95, listType: 'whitelist', result: {}, summary: 'Trang nằm trong danh sách tin cậy.', url: urlString, scanSource: 'CUSTOM_URL' });
      logger.info(`[RESULT_SAVED] url=${urlString} score=100 whitelist`);
      logger.info(`[COMPLETED] url=${urlString} score=100`);
      return;
    }

    // 2. Kiểm tra cache
    const cached = await getUrlCache(urlString);
    if (cached) {
      logger.info(`[FEATURES_COLLECTED] url=${urlString} (cached)`);
      await setUrlScanResult(urlString, { status: 'SUCCESS', ...cached, url: urlString, scanSource: 'CUSTOM_URL' });
      logger.info(`[RESULT_SAVED] url=${urlString} score=${cached.legitimatePercent} (cached)`);
      logger.info(`[COMPLETED] url=${urlString} score=${cached.legitimatePercent} (cached)`);
      return;
    }

    // 3. Fetch HTML
    logger.info(`[FEATURES_COLLECTED] url=${urlString} fetching...`);
    const html = await fetchHtml(urlString);
    logger.info(`[FEATURES_COLLECTED] url=${urlString} html=${html ? html.length + ' chars' : 'null'}`);

    // 4. Parse HTML signals
    const signals = parseHtmlSignals(urlString, html);
    const featuresResult = signals.result;
    const domInput = signals.dom;

    // 5. Domain age + backend intel + reputation
    const rdapAge = await fetchDomainAge(domain);
    const backendIntel = await fetchBackendIntel(urlString, domain);
    const domainAge = mergeDomainAge(rdapAge, backendIntel && backendIntel.domainAge);
    const domainAgeDays = domainAge.ageDays != null ? domainAge.ageDays : -1;
    const reputation = resolveReputation(domain, registrable, urlString, backendIntel);

    // 6. Compute score
    const enrichedDom = { ...(domInput || {}) };
    const suspiciousLinks = await _analyzePageLinks(enrichedDom.pageLinks || [], domain);
    if (suspiciousLinks.length) { enrichedDom.suspiciousLinks = suspiciousLinks; enrichedDom.suspiciousLinkCount = suspiciousLinks.length; }

    logger.info(`[CLASSIFYING] url=${urlString}`);
    const assessment = computeScore(urlString, { dom: enrichedDom, domainAgeDays, domainAge, reputation, redirectChain: [], stabilityMs: 0 });

    let riskScore = assessment.riskScore, finalScore = assessment.finalScore, confidence = assessment.confidence;

    // 7. ML classifier
    const resultValues = Object.entries(featuresResult || {}).filter(([k]) => k !== 'tab').map(([,v]) => parseInt(v));
    const clf = await fetchCLF();
    if (clf && resultValues.length) {
      try { const isPhishML = randomForest(clf).predict([resultValues])[0][0]; if (isPhishML && riskScore < 40) { riskScore += 8; finalScore = Math.max(0, finalScore - 8); } } catch(e) { logger.warn('ML fail', e.message); }
    }

    // 8. Merge result
    const mergedResult = {};
    for (const k in (featuresResult || {})) { if (k !== 'tab') mergedResult[k] = featuresResult[k]; }
    for (const k in (assessment.result || {})) { mergedResult[k] = assessment.result[k]; }

    const isPhish = finalScore <= 30;

    // 9. Cache
    await setUrlCache(urlString, { isPhish, legitimatePercent: finalScore, confidence, riskScore, trustScore: assessment.trustScore, trustContext: assessment.trustContext, result: mergedResult, summary: assessment.summary, explanations: assessment.explanations || [], isUnknown: assessment.isUnknown });

    // 10. Save result
    const state = {
      status: 'SUCCESS', isPhish, legitimatePercent: finalScore, confidence,
      trustScore: assessment.trustScore, riskScore, trustContext: assessment.trustContext, isUnknown: assessment.isUnknown,
      result: mergedResult, summary: assessment.summary, explanations: assessment.explanations || [],
      domainAge: assessment.domainAge || domainAge, reputation,
      counts: (() => { if (!enrichedDom || !enrichedDom.counts) return null; const c = {...enrichedDom.counts, suspiciousLinks:enrichedDom.suspiciousLinkCount||0, deceptiveLinks:enrichedDom.deceptiveLinkCount||0}; if(c.links){c.links={...c.links};c.links.dangerous=enrichedDom.suspiciousLinkCount||0;c.links.warning=Math.max(0,(c.links.warning||0)-c.links.dangerous);c.links.safe=Math.max(0,(c.links.total||0)-c.links.warning-c.links.dangerous);} return c; })(),
      url: urlString, scanSource: 'CUSTOM_URL',
    };

    await setUrlScanResult(urlString, { ...state, updatedAt: Date.now() });
    logger.info(`[RESULT_SAVED] url=${urlString} score=${finalScore} isPhish=${isPhish}`);
    logger.info(`[COMPLETED] url=${urlString} score=${finalScore}`);

  } catch (err) {
    logger.error(`[FAILED] ${urlString}:`, err);
    await setUrlScanResult(urlString, { status: 'FAILED', isPhish: false, legitimatePercent: null, confidence: 0, result: {}, url: urlString, scanSource: 'CUSTOM_URL', updatedAt: Date.now() });
  }
};

// ═══════════════════════════════════════════════════════════════════════════
// EVENT LISTENERS
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
    fetch(`${BACKEND_BASE}/api/report`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
      .then(r => r.json()).then(data => sendResponse({ ok:true, data })).catch(err => { logger.warn('COMMUNITY_REPORT', err.message); sendResponse({ ok:false }); });
    return true;
  }
  if (request.type === 'SET_ICON') {
    chrome.action.setIcon({ path: request.path, tabId: request.tabId }).catch(()=>{});
    sendResponse({ ok:true }); return true;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // CUSTOM URL SCAN — FETCH-BASED (KHÔNG MỞ TAB)
  // ═══════════════════════════════════════════════════════════════════════
  if (request.type === 'SCAN_URL') {
    const urlString = request.url;
    if (!urlString) { sendResponse({ ok: false, error: 'Missing url' }); return true; }

    logger.info(`[SCAN_JOB_CREATED] url=${urlString}`);
    logger.info(`[SCAN_URL] ${urlString} (fetch-based, no tab)`);

    // ✅ Phản hồi NGAY LẬP TỨC — sendResponse phải gọi đồng bộ trước async work
    // Chrome message channel có thể đóng nếu sendResponse gọi sau await
    sendResponse({ ok: true });

    // Lưu trạng thái ANALYZING + chạy phân tích hoàn toàn ngầm
    (async () => {
      try {
        await setUrlScanResult(urlString, { status: 'ANALYZING', isPhish: false, legitimatePercent: null, confidence: 0, result: {}, url: urlString, scanSource: 'CUSTOM_URL' });
        await fetchAndAnalyzeUrl(urlString);
      } catch (err) {
        logger.error(`[FAILED] ${urlString}:`, err);
        await setUrlScanResult(urlString, { status: 'FAILED', isPhish: false, legitimatePercent: null, confidence: 0, result: {}, url: urlString, scanSource: 'CUSTOM_URL' });
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

chrome.tabs.onRemoved.addListener((tabId) => { removeTabState(tabId); redirectChains.delete(tabId); riskBlockAllowUntil.delete(tabId); });

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading' && changeInfo.url) {
    redirectChains.set(tabId, [changeInfo.url]);
    setTabState(tabId, { status: ANALYSIS_STATUS.ANALYZING, result: null, url: changeInfo.url, isPhish: false, legitimatePercent: null }).catch(()=>{});
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

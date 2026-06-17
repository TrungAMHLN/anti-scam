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
const API_BASE = 'https://api.chongluadao.vn'; // legacy CLD list/classifier source only
const DEFAULT_BACKEND_BASE = (self.ANTISCAM_API_CONFIG && self.ANTISCAM_API_CONFIG.PRODUCTION_API_BASE_URL) || '';
const DEV_BACKEND_BASE = (self.ANTISCAM_API_CONFIG && self.ANTISCAM_API_CONFIG.DEVELOPMENT_API_BASE_URL) || 'http://localhost:3000';
const OPENPHISH_URL = 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt';
const PORT_REDIRECT = 'REDIRECT_PORT_NAME', PORT_CLOSE_TAB = 'CLOSE_TAB_PORT_NAME';
const MANUAL_SCAN_RESULT_KEY = 'manual_scan_result';

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

const getBackendBases = async () => {
  let custom = '';
  try {
    const storageKey = (self.ANTISCAM_API_CONFIG && self.ANTISCAM_API_CONFIG.STORAGE_KEY) || 'antiscamApiBaseUrl';
    const cfg = await chrome.storage.local.get([storageKey, 'antiscamBackendBase']);
    custom = (cfg[storageKey] || cfg.antiscamBackendBase || '').replace(/\/$/, '');
  } catch (_) {}
  const bases = [custom, DEFAULT_BACKEND_BASE, DEV_BACKEND_BASE]
    .filter(Boolean)
    .map(b => b.replace(/\/$/, ''));
  return [...new Set(bases)];
};

const fetchBackendJson = async (path, options = {}, timeoutMs = 6500) => {
  const bases = await getBackendBases();
  for (const base of bases) {
    const url = `${base}${path}`;
    const method = String(options.method || 'GET').toUpperCase();
    const started = Date.now();
    try {
      console.info('[AntiScam Backend Request]', method, url, 'body=', (options.body || '').toString().slice(0, 500));
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), timeoutMs);
      const res = await fetch(url, { ...options, signal: ctrl.signal });
      clearTimeout(t);
      const text = await res.text();
      console.info('[AntiScam Backend Response]', method, url, 'status=', res.status, 'ms=', Date.now() - started, 'body=', text.slice(0, 700));
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      try { return JSON.parse(text); } catch (_) { return null; }
    } catch (err) {
      logger.warn(`backend ${url} unavailable:`, err.message);
    }
  }
  return null;
};

const fetchBackendJsonAny = async (paths, options = {}, timeoutMs = 6500) => {
  for (const path of paths) {
    const data = await fetchBackendJson(path, options, timeoutMs);
    if (data) return data;
  }
  return null;
};

const scanApiPathForTarget = (type) => {
  if (type === 'email') return '/api/scan-email';
  if (type === 'phone') return '/api/scan-phone';
  if (type === 'image' || type === 'qr') return '/api/scan-image';
  if (type === 'url' || type === 'domain' || type === 'ip') return '/api/scan-url';
  return '/v1/scan-object';
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

const setManualScanResult = async (state) => {
  try { await chrome.storage.session.set({ [MANUAL_SCAN_RESULT_KEY]: { ...state, updatedAt: Date.now() } }); } catch(e) { logger.warn('setManualScanResult', e.message); }
};
const getManualScanResult = async () => {
  try { const d = await chrome.storage.session.get(MANUAL_SCAN_RESULT_KEY); return d[MANUAL_SCAN_RESULT_KEY] || null; } catch (_) { return null; }
};

const _stateFromAssessment = (target, urlString, assessment, domainAge, reputation) => ({
  status: ANALYSIS_STATUS.SUCCESS,
  scanMode: 'manual',
  targetType: target.type,
  targetValue: target.displayValue || target.value,
  url: urlString,
  isPhish: assessment.finalScore <= 30,
  legitimatePercent: assessment.finalScore,
  confidence: assessment.confidence,
  trustScore: assessment.trustScore,
  riskScore: assessment.riskScore,
  isUnknown: assessment.isUnknown,
  result: assessment.result || {},
  summary: assessment.summary,
  explanations: assessment.explanations || [],
  domainAge: assessment.domainAge || domainAge,
  reputation,
  externalIntel: !!(reputation && ((reputation.malware && ((reputation.malware.checked || []).length || reputation.malware.dangerous)) || (reputation.dns && (reputation.dns.ip || reputation.dns.asn)) || reputation.communityReports > 0)),
  assessmentLimited: !(reputation && ((reputation.malware && ((reputation.malware.checked || []).length || reputation.malware.dangerous)) || (reputation.dns && (reputation.dns.ip || reputation.dns.asn)) || reputation.communityReports > 0)),
});

const scanUrlLikeTarget = async (target) => {
  const urlString = target.type === 'url' ? AntiScamScanPlatform.normalizeUrl(target.value) : `https://${target.value}`;
  const domain = getDomain(urlString);
  const registrable = getRegistrable(domain);
  const [rdapAge, backendIntel] = await Promise.all([
    fetchDomainAge(domain),
    fetchBackendIntel(urlString, domain),
  ]);
  const domainAge = mergeDomainAge(rdapAge, backendIntel && backendIntel.domainAge);
  const domainAgeDays = domainAge.ageDays != null ? domainAge.ageDays : -1;
  const reputation = resolveReputation(domain, registrable, urlString, backendIntel);
  const assessment = computeScore(urlString, {
    dom: { scanned:false, contentRich:false },
    domainAgeDays,
    domainAge,
    reputation,
    redirectChain: [],
    stabilityMs: 0,
  });
  return _stateFromAssessment(target, urlString, assessment, domainAge, reputation);
};

const mergeBackendObjectScan = (localState, backendData) => {
  if (!backendData || backendData.status === 'error') return localState;
  const result = { ...(localState.result || {}), ...(backendData.result || {}) };
  const explanations = [ ...(localState.explanations || []), ...((backendData.explanations || []).filter(Boolean)) ];
  const riskScore = Math.max(localState.riskScore || 0, backendData.riskScore || 0);
  const finalScore = backendData.finalScore != null ? Math.min(localState.legitimatePercent, backendData.finalScore) : localState.legitimatePercent;
  const externalIntel = !!(backendData.externalIntel || backendData.hasExternalIntel);
  return {
    ...localState,
    legitimatePercent: finalScore,
    isPhish: finalScore <= 30,
    riskScore,
    reputationScore: backendData.reputationScore != null ? backendData.reputationScore : finalScore,
    confidenceScore: backendData.confidenceScore != null ? backendData.confidenceScore : (externalIntel ? 70 : localState.confidence),
    checkedSources: backendData.checkedSources || localState.checkedSources || [],
    missingSources: backendData.missingSources || localState.missingSources || [],
    externalIntel: externalIntel || !!localState.externalIntel,
    assessmentLimited: !(externalIntel || !!localState.externalIntel),
    isUnknown: !(externalIntel || !!localState.externalIntel),
    result,
    explanations,
    summary: backendData.summary || localState.summary,
  };
};

const runUnifiedScan = async (input, meta = {}) => {
  const target = AntiScamScanPlatform.detectTarget(input, meta);
  const imageScan = (target.meta && target.meta.imageScan) || meta.imageScan || {};
  const qrText = imageScan.qrText || meta.qrText;
  if (target.type === 'image') {
    const ent = imageScan.entities || {};
    const chained = qrText || (ent.urls && ent.urls[0]) || (ent.emails && ent.emails[0]) || (ent.phones && ent.phones[0]);
    if (chained) {
      const chainedTarget = AntiScamScanPlatform.detectTarget(chained, { source:'image-entity', imageSource: target.value });
      if (chainedTarget.type !== 'text' && chainedTarget.type !== 'image') return runUnifiedScan(chainedTarget.value, chainedTarget.meta);
    }
  }
  if (['url', 'domain', 'ip'].includes(target.type)) return scanUrlLikeTarget(target);

  const localState = AntiScamScanPlatform.localScanTarget(target);
  const apiPath = scanApiPathForTarget(target.type);
  try {
    const data = await fetchBackendJsonAny([apiPath, '/v1/scan-object'], {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input: target.value, type: target.type, meta: target.meta || {}, displayValue: target.displayValue })
    }, 15000);
    if (data) return mergeBackendObjectScan(localState, data);
  } catch (err) { logger.warn('scan-object backend', err.message); }
  // Backend unreachable: return limited local identification only, never a safe verdict.
  return localState;
};

const createContextMenus = () => {
  try {
    chrome.contextMenus.removeAll(() => {
      chrome.contextMenus.create({ id: 'antiscam-root', title: 'AntiScam', contexts: ['selection', 'link', 'image', 'page'] });
      chrome.contextMenus.create({ id: 'antiscam-scan-object', parentId: 'antiscam-root', title: 'Quét đối tượng', contexts: ['selection', 'link', 'image', 'page'] });
    });
  } catch (err) { logger.warn('contextMenus', err.message); }
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
          result: cached.result || {}, summary: cached.summary || '', explanations: cached.explanations || [], isUnknown: cached.isUnknown, url: urlString });
        updateBadge(cached.isPhish, cached.legitimatePercent, tabId); return;
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
    const assessment = computeScore(urlString, {
      dom: domInput || {},
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
      isUnknown: assessment.isUnknown,
      result: mergedResult,
      summary: assessment.summary,
      explanations: assessment.explanations || [],
      domainAge: assessment.domainAge || domainAge,
      reputation,
      redirectHops: assessment.redirectHops,
      counts: (domInput && domInput.counts) ? domInput.counts : null,
      analysisStart,
      url: urlString,
    });

    // 10. Cache (chỉ lần đầu)
    if (!isUpdate) {
      await setUrlCache(urlString, { isPhish, legitimatePercent: finalScore, confidence, result: mergedResult, summary: assessment.summary, explanations: assessment.explanations || [], isUnknown: assessment.isUnknown });
    }

    updateBadge(isPhish, finalScore, tabId);
  } catch (err) {
    logger.error(`classify ${tabId}:`, err);
    await setTabState(tabId, { status: ANALYSIS_STATUS.FAILED, isPhish: false, legitimatePercent: 0,
      result: featuresResult || {}, summary: 'Không thể phân tích trang này.', url: urlString });
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Blocking & SafeCheck
// ─────────────────────────────────────────────────────────────────────────────
const blockingFunction = (url, blackSite, tabId) => {
  const message = { site: url, match: blackSite, title: url, lenient: inputBlockLenient,
    favicon: `https://www.google.com/s2/favicons?domain=${url}` };
  setTabState(tabId, { status: ANALYSIS_STATUS.SUCCESS, isBlocked: url, isPhish: true,
    legitimatePercent: 0, confidence: 95, result: {}, summary: 'Trang này nằm trong danh sách đen đã xác nhận.', url }).catch(()=>{});
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
      setTabState(tabId, { status: ANALYSIS_STATUS.ANALYZING, result: request.result, url: tabUrl, isPhish: false, legitimatePercent: 0 })
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
  if (request.type === 'MANUAL_SCAN_REQUEST') {
    runUnifiedScan(request.input || '', { ...(request.meta || {}), source:'manual' })
      .then(async (state) => { await setManualScanResult(state); sendResponse({ ok:true, state }); })
      .catch(err => { logger.warn('MANUAL_SCAN_REQUEST', err.message); sendResponse({ ok:false, message: err.message }); });
    return true;
  }
  if (request.type === 'GET_MANUAL_SCAN_RESULT') {
    getManualScanResult().then(state => sendResponse(state)).catch(()=>sendResponse(null));
    return true;
  }
  if (request.type === 'ENABLE_SELECT_MODE') {
    const tabId = request.tabId;
    if (!tabId) { sendResponse({ ok:false }); return true; }
    chrome.tabs.sendMessage(tabId, { type:'ENABLE_SELECT_MODE' }, (resp) => {
      if (chrome.runtime.lastError) sendResponse({ ok:false, message: chrome.runtime.lastError.message });
      else sendResponse(resp || { ok:true });
    });
    return true;
  }
  if (request.type === 'SCAN_SELECTED_OBJECT') {
    const payload = request.payload || {};
    runUnifiedScan(payload.input || payload.value || '', { ...(payload.meta || {}), kind: payload.kind, srcUrl: payload.srcUrl, source:'select-mode' })
      .then(async (state) => {
        await setManualScanResult(state);
        chrome.notifications.create({ type:'basic', iconUrl: chrome.runtime.getURL('assets/antiScamLogo.png'), title:'AntiScam', message:'Đã quét đối tượng được chọn. Mở popup để xem kết quả.' }).catch(()=>{});
        sendResponse({ ok:true, state });
      })
      .catch(err => { logger.warn('SCAN_SELECTED_OBJECT', err.message); sendResponse({ ok:false, message: err.message }); });
    return true;
  }
  if (request.type === 'SET_WHITELIST_TEMP') {
    const tabId = request.tabId; if (!tabId) { sendResponse({ ok:false }); return true; }
    setTabState(tabId, { status: ANALYSIS_STATUS.IDLE, isWhiteList:null, isBlocked:null, url:null })
      .then(()=>sendResponse({ok:true})).catch(()=>sendResponse({ok:false})); return true;
  }
  if (request.type === 'COMMUNITY_REPORT') {
    const payload = request.payload || {};
    fetchBackendJson('/v1/community-report', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: payload.url, domain: payload.domain, reason: payload.reason, type: payload.type, value: payload.value })
    }, 6500).then(data => sendResponse({ ok: !!data, data })).catch(err => {
      logger.warn('COMMUNITY_REPORT', err.message); sendResponse({ ok:false });
    });
    return true;
  }
  if (request.type === 'CLEAR_SCAN_CACHE') {
    chrome.storage.session.clear().then(() => sendResponse({ ok:true })).catch(() => sendResponse({ ok:false }));
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
  if ((details.type === 'main_frame' || details.type === 'sub_frame') && details.tabId >= 0 && details.redirectUrl) {
    const chain = redirectChains.get(details.tabId) || [];
    if (!chain.includes(details.redirectUrl)) chain.push(details.redirectUrl);
    redirectChains.set(details.tabId, chain);
  }
}, { urls: ['*://*/*'], types: ['main_frame', 'sub_frame'] });

chrome.tabs.onRemoved.addListener((tabId) => { removeTabState(tabId); redirectChains.delete(tabId); });

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading' && changeInfo.url) {
    redirectChains.set(tabId, [changeInfo.url]);
    setTabState(tabId, { status: ANALYSIS_STATUS.ANALYZING, result: null, url: changeInfo.url, isPhish: false, legitimatePercent: 0 }).catch(()=>{});
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

if (chrome.contextMenus && chrome.contextMenus.onClicked) {
  chrome.contextMenus.onClicked.addListener((info) => {
    if (info.menuItemId !== 'antiscam-scan-object') return;
    const isImage = !!info.srcUrl;
    const input = info.linkUrl || info.selectionText || info.srcUrl || info.pageUrl || '';
    const meta = { source:'context-menu', linkUrl: info.linkUrl, srcUrl: info.srcUrl, pageUrl: info.pageUrl, kind: isImage ? 'image' : undefined };
    runUnifiedScan(input, meta).then(async (state) => {
      await setManualScanResult(state);
      chrome.notifications.create({ type:'basic', iconUrl: chrome.runtime.getURL('assets/antiScamLogo.png'), title:'AntiScam', message:'Đã quét đối tượng. Mở popup để xem kết quả.' }).catch(()=>{});
    }).catch(err => logger.warn('context scan', err.message));
  });
}


// Download risk guard — pause dangerous files from suspicious pages and ask user.
const DANGEROUS_DOWNLOAD_EXTS = ['.exe', '.scr', '.bat', '.cmd', '.apk', '.jar', '.ps1'];
const ARCHIVE_DOWNLOAD_EXTS = ['.zip', '.rar', '.7z'];
const pendingDownloads = new Map();
const _downloadExt = (u, filename='') => {
  const raw = (filename || u || '').split('?')[0].split('#')[0].toLowerCase();
  return DANGEROUS_DOWNLOAD_EXTS.find(ext => raw.endsWith(ext)) || null;
};
const _archiveDownloadExt = (u, filename='') => {
  const raw = (filename || u || '').split('?')[0].split('#')[0].toLowerCase();
  return ARCHIVE_DOWNLOAD_EXTS.find(ext => raw.endsWith(ext)) || null;
};
const _scanDownloadFileIntel = async (item) => {
  try {
    const fileUrl = item.finalUrl || item.url || '';
    const name = item.filename || fileUrl;
    const ext = _downloadExt(fileUrl, name) || _archiveDownloadExt(fileUrl, name);
    if (!ext || !/^https?:\/\//i.test(fileUrl)) return;
    const head = await fetch(fileUrl, { method:'HEAD' }).catch(()=>null);
    const len = head && head.headers ? parseInt(head.headers.get('content-length') || '0') : 0;
    if (len && len > 25 * 1024 * 1024) return;
    const res = await fetch(fileUrl);
    if (!res.ok) return;
    const buffer = await res.arrayBuffer();
    if (buffer.byteLength > 25 * 1024 * 1024) return;
    const hash = await AntiScamScanPlatform.sha256ArrayBuffer(buffer);
    const state = await runUnifiedScan(hash, { source:'download', kind:'file', fileName:name, size:buffer.byteLength, hash });
    await setManualScanResult(state);
  } catch (err) { logger.warn('download file intel', err.message); }
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
    _scanDownloadFileIntel(item).catch(()=>{});
    const ext = _downloadExt(item.finalUrl || item.url, item.filename);
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

chrome.runtime.onStartup.addListener(() => { createContextMenus(); startup().catch(()=>{}); });
chrome.runtime.onInstalled.addListener(() => {
  createContextMenus();
  startup().catch(()=>{});
  chrome.notifications.create({ type:'basic', iconUrl: chrome.runtime.getURL('assets/antiScamLogo.png'),
    title: 'Cài đặt thành công v2.0!', message: 'AntiScam v2.0 — engine Trust/Risk/Confidence đã sẵn sàng.' });
});

createContextMenus();
startup().catch(()=>{});

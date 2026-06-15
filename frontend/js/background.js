/* global chrome */
/* global psl */

importScripts('heuristic.js'); // Import heuristic engine

// ─────────────────────────────────────────────────────────────────────────────
//  Logger — chỉ hoạt động khi chạy ở chế độ development
// ─────────────────────────────────────────────────────────────────────────────
const IS_DEV = !('update_url' in chrome.runtime.getManifest());
const logger = {
  info:  (...a) => IS_DEV && console.info('[AntiScam]', ...a),
  warn:  (...a) => IS_DEV && console.warn('[AntiScam]', ...a),
  error: (...a) => IS_DEV && console.error('[AntiScam]', ...a),
};

// ─────────────────────────────────────────────────────────────────────────────
//  State Machine & Hằng số
// ─────────────────────────────────────────────────────────────────────────────
const ANALYSIS_STATUS = Object.freeze({
  IDLE:      'IDLE',
  ANALYZING: 'ANALYZING',
  SUCCESS:   'SUCCESS',
  FAILED:    'FAILED',
  OFFLINE:   'OFFLINE',
});

const BLACKLIST_TTL_MS    = 60 * 60 * 1000;  // 1 giờ
const OPENPHISH_TTL_MS    = 15 * 60 * 1000;  // 15 phút
const CLASSIFIER_TTL_MS   = 5  * 60 * 1000;  // 5 phút
const RESULT_CACHE_TTL_MS = 10 * 60 * 1000;  // 10 phút cache kết quả theo URL
const FETCH_TIMEOUT_MS    = 10_000;
const MAX_RETRIES         = 3;

const API_BASE = 'https://api.chongluadao.vn';
const OPENPHISH_URL = 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt';

const PORT_REDIRECT  = 'REDIRECT_PORT_NAME';
const PORT_CLOSE_TAB = 'CLOSE_TAB_PORT_NAME';

// ─────────────────────────────────────────────────────────────────────────────
//  Circuit Breaker Pattern
// ─────────────────────────────────────────────────────────────────────────────
const circuitBreaker = {
  antiScamApi: { failures: 0, openUntil: 0 },
  openPhish:   { failures: 0, openUntil: 0 },
};
const CB_THRESHOLD = 3;
const CB_TIMEOUT_MS = 30_000; // Ngắt 30s

const checkCircuitBreaker = (source) => {
  const cb = circuitBreaker[source];
  if (Date.now() < cb.openUntil) {
    logger.warn(`Circuit breaker OPEN cho ${source}, bỏ qua request.`);
    return false;
  }
  return true;
};

const recordFailure = (source) => {
  const cb = circuitBreaker[source];
  cb.failures++;
  if (cb.failures >= CB_THRESHOLD) {
    cb.openUntil = Date.now() + CB_TIMEOUT_MS;
    logger.error(`Circuit breaker TRIPPED cho ${source}. Ngừng gọi trong 30s.`);
  }
};

const recordSuccess = (source) => {
  circuitBreaker[source].failures = 0;
};

// ─────────────────────────────────────────────────────────────────────────────
//  Utility: fetch với timeout + retry + exponential backoff + circuit breaker
// ─────────────────────────────────────────────────────────────────────────────
const fetchWithRetry = async (url, source, isJson = true, retries = MAX_RETRIES) => {
  if (!checkCircuitBreaker(source)) return null;

  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
      const response = await fetch(url, { signal: controller.signal });
      clearTimeout(timer);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      
      const data = isJson ? await response.json() : await response.text();
      recordSuccess(source);
      logger.info(`fetchWithRetry OK: ${url}`);
      return data;
    } catch (err) {
      logger.warn(`fetchWithRetry attempt ${attempt + 1}/${retries} failed cho ${url}: ${err.message}`);
      if (attempt < retries - 1) {
        await new Promise(r => setTimeout(r, 1000 * Math.pow(2, attempt)));
      }
    }
  }
  recordFailure(source);
  return null;
};

// ─────────────────────────────────────────────────────────────────────────────
//  Storage helpers
// ─────────────────────────────────────────────────────────────────────────────
const getTabState = async (tabId) => {
  try {
    const key = `tab_${tabId}`;
    const data = await chrome.storage.session.get(key);
    return data[key] || null;
  } catch (err) {
    logger.error('getTabState failed:', err);
    return null;
  }
};

const setTabState = async (tabId, state) => {
  try {
    const key = `tab_${tabId}`;
    await chrome.storage.session.set({ [key]: { ...state, updatedAt: Date.now() } });
  } catch (err) {
    logger.error('setTabState failed:', err);
  }
};

const removeTabState = async (tabId) => {
  try {
    await chrome.storage.session.remove(`tab_${tabId}`);
  } catch (err) {
    logger.warn('removeTabState failed:', err);
  }
};

// URL Cache cho classify() để tránh phân tích lại cùng URL nhiều lần
const getUrlCache = async (url) => {
  try {
    // Hash đơn giản
    let hash = 0;
    for (let i = 0; i < url.length; i++) {
      hash = ((hash << 5) - hash) + url.charCodeAt(i);
      hash |= 0;
    }
    const key = `cache_${hash}`;
    const data = await chrome.storage.session.get(key);
    const item = data[key];
    if (item && Date.now() - item.timestamp < RESULT_CACHE_TTL_MS) {
      return item;
    }
  } catch (e) { }
  return null;
};

const setUrlCache = async (url, data) => {
  try {
    let hash = 0;
    for (let i = 0; i < url.length; i++) {
      hash = ((hash << 5) - hash) + url.charCodeAt(i);
      hash |= 0;
    }
    const key = `cache_${hash}`;
    await chrome.storage.session.set({ [key]: { ...data, timestamp: Date.now() } });
  } catch (e) {}
};

// ─────────────────────────────────────────────────────────────────────────────
//  RDAP Domain Age Intelligence
// ─────────────────────────────────────────────────────────────────────────────
const fetchDomainAge = async (domain) => {
  try {
    let baseDomain = domain;
    try {
      if (typeof psl !== 'undefined') {
        baseDomain = psl.parse(domain).domain || domain;
      }
    } catch (e) {}

    const key = `age_${baseDomain}`;
    const cachedAge = await chrome.storage.session.get(key);
    if (cachedAge && cachedAge[key] !== undefined) {
      return cachedAge[key];
    }
    
    // Timeout 3s để không chặn quá trình quét
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);
    
    const response = await fetch(`https://rdap.org/domain/${baseDomain}`, { signal: controller.signal });
    clearTimeout(timer);
    
    if (!response.ok) return -1;
    
    const data = await response.json();
    if (data && data.events) {
      const regEvent = data.events.find(e => e.eventAction === 'registration');
      if (regEvent && regEvent.eventDate) {
        const regDate = new Date(regEvent.eventDate);
        const ageDays = (Date.now() - regDate.getTime()) / (1000 * 60 * 60 * 24);
        
        await chrome.storage.session.set({ [key]: ageDays });
        return ageDays;
      }
    }
  } catch (err) {
    logger.warn(`fetchDomainAge failed cho ${domain}:`, err.message);
  }
  return -1;
};

// ─────────────────────────────────────────────────────────────────────────────
//  Classifier ML
// ─────────────────────────────────────────────────────────────────────────────
const fetchCLF = async () => {
  try {
    const { classifierCache, classifierCacheTime } = await chrome.storage.local.get(['classifierCache', 'classifierCacheTime']);
    if (classifierCache && classifierCacheTime && (Date.now() - classifierCacheTime < CLASSIFIER_TTL_MS)) {
      return classifierCache;
    }
    const data = await fetchWithRetry(`${API_BASE}/classifier.json`, 'antiScamApi', true);
    if (data) {
      await chrome.storage.local.set({ classifierCache: data, classifierCacheTime: Date.now() });
      return data;
    }
    if (classifierCache) return classifierCache;
  } catch (err) {
    logger.error('fetchCLF exception:', err);
  }
  return null;
};

const decisionTree = (root) => {
  const predictOne = (x) => {
    let node = root;
    while (node['type'] == 'split') {
      const threshold = node['threshold'].split(' <= ');
      node = x[threshold[0]] <= threshold[1] ? node['left'] : node['right'];
    }
    return node['value'][0];
  };
  return { predict: (X) => X.map((row) => predictOne(row)) };
};

const randomForest = (clf) => {
  const predict = (X) => {
    let pred = [clf['estimators'].map((row) => decisionTree(row).predict(X))];
    pred = pred[0].map((col, i) => pred.map((row) => row[i]));
    const results = [];
    for (const p in pred) {
      let positive = 0, negative = 0;
      for (const i in pred[p]) {
        positive += pred[p][i][1];
        negative += pred[p][i][0];
      }
      results.push([positive >= negative, Math.max(positive, negative)]);
    }
    return results;
  };
  return { predict };
};

// ─────────────────────────────────────────────────────────────────────────────
//  Blacklist / Whitelist — Multi-source
// ─────────────────────────────────────────────────────────────────────────────
let blackListing = []; // Mảng cho wildcard lookup
let blackListingSet = new Set(); // Set cho exact match O(1)
let whiteListingSet = new Set();
let inputBlockLenient = false;

const loadListsFromCache = async () => {
  try {
    const { blacklist, blacklistTime, whitelist, whitelistTime, openPhishList, openPhishTime } = await chrome.storage.local.get([
      'blacklist', 'blacklistTime', 'whitelist', 'whitelistTime', 'openPhishList', 'openPhishTime'
    ]);

    blackListing = [];
    blackListingSet.clear();
    whiteListingSet.clear();

    if (blacklist && blacklistTime && (Date.now() - blacklistTime < BLACKLIST_TTL_MS)) {
      blacklist.forEach(u => blackListing.push(u));
    }
    if (openPhishList && openPhishTime && (Date.now() - openPhishTime < OPENPHISH_TTL_MS)) {
      openPhishList.forEach(u => blackListingSet.add(u));
    }
    if (whitelist && whitelistTime && (Date.now() - whitelistTime < BLACKLIST_TTL_MS)) {
      whitelist.forEach(u => whiteListingSet.add(u));
    }
    logger.info(`Cache loaded: ${blackListing.length} CLD, ${blackListingSet.size} OpenPhish, ${whiteListingSet.size} Whitelist`);
  } catch (err) {
    logger.error('loadListsFromCache failed:', err);
  }
};

let startupInProgress = false;

const startup = async () => {
  if (startupInProgress) return;
  startupInProgress = true;

  try {
    await loadListsFromCache();

    // 1. AntiScam Blacklist
    const { blacklistTime } = await chrome.storage.local.get('blacklistTime');
    if (!blacklistTime || (Date.now() - blacklistTime >= BLACKLIST_TTL_MS)) {
      const data = await fetchWithRetry(`${API_BASE}/v1/blacklist`, 'antiScamApi', true);
      if (data && Array.isArray(data)) {
        const list = data.map(item => item.url).filter(Boolean);
        await chrome.storage.local.set({ blacklist: list, blacklistTime: Date.now() });
        blackListing = list;
        logger.info(`AntiScam Blacklist cập nhật: ${list.length} entries`);
      }
    }

    // 2. OpenPhish Feed
    const { openPhishTime } = await chrome.storage.local.get('openPhishTime');
    if (!openPhishTime || (Date.now() - openPhishTime >= OPENPHISH_TTL_MS)) {
      const text = await fetchWithRetry(OPENPHISH_URL, 'openPhish', false);
      if (text) {
        const list = text.split('\n').map(line => line.trim()).filter(line => line.length > 0);
        await chrome.storage.local.set({ openPhishList: list, openPhishTime: Date.now() });
        list.forEach(u => blackListingSet.add(u));
        logger.info(`OpenPhish Feed cập nhật: ${list.length} entries`);
      }
    }

    // 3. AntiScam Whitelist
    const { whitelistTime } = await chrome.storage.local.get('whitelistTime');
    if (!whitelistTime || (Date.now() - whitelistTime >= BLACKLIST_TTL_MS)) {
      const data = await fetchWithRetry(`${API_BASE}/v1/whitelist`, 'antiScamApi', true);
      if (data && Array.isArray(data)) {
        const list = data.map(item => item.url).filter(Boolean);
        await chrome.storage.local.set({ whitelist: list, whitelistTime: Date.now() });
        whiteListingSet.clear();
        list.forEach(u => whiteListingSet.add(u));
        logger.info(`Whitelist cập nhật: ${list.length} entries`);
      }
    }

  } catch (err) {
    logger.error('startup error:', err);
  } finally {
    startupInProgress = false;
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  Utility
// ─────────────────────────────────────────────────────────────────────────────
const getDomain = (url) => {
  const matches = url.match(/^https?:\/\/([^/?#]+)(?:[/?#]|$)/i);
  return (matches && matches[1]) || '';
};

const createUrlObject = (url) => {
  try { return new URL(url); } catch { return null; }
};

const updateBadge = (isPhishing, legitimatePercent, tabId) => {
  const title = isPhishing
    ? `AntiScam: ⚠️ Cảnh báo (${Math.round(legitimatePercent)}% an toàn)`
    : `AntiScam: ✅ An toàn (${Math.round(legitimatePercent)}%)`;
  // Chrome MV3 doesn't guarantee setIcon is supported directly with path if not all dimensions are provided,
  // but it's okay, we'll keep the existing code
  chrome.action.setTitle({ title, tabId }).catch(() => {});
  chrome.action.setIcon({ path: 'assets/antiScamLogo.png', tabId }).catch((err) => {
    logger.warn('setIcon failed:', err.message);
  });
};

// ─────────────────────────────────────────────────────────────────────────────
//  Classification
// ─────────────────────────────────────────────────────────────────────────────
const classify = async (tabId, result, urlString) => {
  try {
    const existing = await getTabState(tabId);
    if (existing && existing.url === urlString && existing.status === ANALYSIS_STATUS.SUCCESS) {
      return; // Bỏ qua nếu đã xong
    }

    const domain = getDomain(urlString);
    
    // 1. Kiểm tra Whitelist
    let inWhitelist = false;
    for (const w of whiteListingSet) {
      if (w.includes(domain)) {
        inWhitelist = true;
        break;
      }
    }

    if (inWhitelist) {
      await setTabState(tabId, {
        status: ANALYSIS_STATUS.SUCCESS,
        isWhiteList: domain,
        isPhish: false,
        legitimatePercent: 100,
        result: {},
        url: urlString,
      });
      updateBadge(false, 100, tabId);
      return;
    }

    // 2. Check URL Cache
    const cachedResult = await getUrlCache(urlString);
    if (cachedResult) {
      await setTabState(tabId, {
        status: ANALYSIS_STATUS.SUCCESS,
        isPhish: cachedResult.isPhish,
        legitimatePercent: cachedResult.legitimatePercent,
        result: cachedResult.result || result,
        url: urlString,
      });
      updateBadge(cachedResult.isPhish, cachedResult.legitimatePercent, tabId);
      return;
    }

    // 3. Tính ML Model Score
    let legitimateCount = 0, suspiciousCount = 0, phishingCount = 0;
    for (const key in result) {
      if (key === 'tab') continue;
      if (result[key] == '1') phishingCount++;
      else if (result[key] == '0') suspiciousCount++;
      else legitimateCount++;
    }
    const total = phishingCount + suspiciousCount + legitimateCount;
    let legitimatePercent = total > 0 ? (legitimateCount / total) * 100 : 0;

    const resultValues = Object.entries(result)
      .filter(([k]) => k !== 'tab')
      .map(([, v]) => parseInt(v));

    let isPhishML = false;
    const clf = await fetchCLF();
    if (clf && resultValues.length) {
      const rf = randomForest(clf);
      isPhishML = rf.predict([resultValues])[0][0];
    }

    // 4. Tính Heuristic Score (Local Engine)
    let heuristicIsPhish = false;
    if (typeof computeHeuristicScore !== 'undefined') {
      const hResult = computeHeuristicScore(urlString);
      if (hResult.riskLevel === 'dangerous') {
        heuristicIsPhish = true;
        // Phạt legitimatePercent nếu heuristic phát hiện nguy hiểm
        legitimatePercent = Math.min(legitimatePercent, 100 - hResult.score);
      } else if (hResult.riskLevel === 'suspicious') {
        legitimatePercent = Math.max(0, legitimatePercent - (hResult.score / 2));
      }
    }

    // 5. Tính Tuổi Tên miền (Domain Age) qua RDAP
    const domainAgeDays = await fetchDomainAge(domain);
    if (domainAgeDays >= 0) {
      if (domainAgeDays < 3) {
        heuristicIsPhish = true;
        legitimatePercent = Math.max(0, legitimatePercent - 50); // Phạt nặng
        result['Domain Age'] = '1';
      } else if (domainAgeDays < 30) {
        legitimatePercent = Math.max(0, legitimatePercent - 20); // Phạt vừa
        result['Domain Age'] = '0';
      } else {
        result['Domain Age'] = '-1';
      }
    }

    // 5.a. Hoàn thiện đánh giá Obfuscated Script với Layer 4 (Domain Reputation)
    if (result['Obfuscation Confidence'] !== undefined) {
      let obfConf = result['Obfuscation Confidence'] || 0;
      let obfRisk = result['Obfuscation Risk'] || 0;
      
      if (domainAgeDays >= 0 && domainAgeDays < 3) obfRisk += 20;
      else if (domainAgeDays >= 0 && domainAgeDays < 7) obfRisk += 10;
      
      if (obfConf >= 75 && obfRisk >= 60) {
        result['Obfuscated Script'] = '1';
      } else if (obfConf >= 51) {
        result['Obfuscated Script'] = '0';
      } else {
        result['Obfuscated Script'] = '-1';
      }
      
      delete result['Obfuscation Confidence'];
      delete result['Obfuscation Risk'];
    }

    // 5.b. Override cứng: các tín hiệu cực kỳ nguy hiếm bất kể ML nói gì
    if (result['Obfuscated Script'] === '1') {
      heuristicIsPhish = true;
      legitimatePercent = Math.max(0, legitimatePercent - 15); // Phạt mềm vì engine bên features.js đã quét rất kỹ và chính xác
    }
    if (result['Form Hijacking'] === '1') {
      heuristicIsPhish = true;
      legitimatePercent = Math.min(legitimatePercent, 20); // nguy hiểm cực cao
    }

    // 6. Kết hợp
    let isPhish = isPhishML || heuristicIsPhish;
    
    // Safety guard
    if (isPhish && legitimatePercent > 70) {
      isPhish = false; // Phủ quyết nếu ML phân tích nhầm nhưng URL an toàn cao
    } else if (!isPhish && legitimatePercent < 30) {
      isPhish = true; // Bắt nếu điểm an toàn quá thấp
    }

    await setTabState(tabId, {
      status: ANALYSIS_STATUS.SUCCESS,
      isPhish,
      legitimatePercent,
      result,
      url: urlString,
    });
    
    // Lưu cache để lần sau không phải tính lại
    await setUrlCache(urlString, {
      isPhish,
      legitimatePercent,
      result
    });

    updateBadge(isPhish, legitimatePercent, tabId);

  } catch (err) {
    logger.error(`classify tab ${tabId} exception:`, err);
    await setTabState(tabId, {
      status: ANALYSIS_STATUS.FAILED,
      isPhish: false,
      legitimatePercent: 0,
      result: result || {},
      url: urlString,
    });
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  Blocking & SafeCheck
// ─────────────────────────────────────────────────────────────────────────────
const blockingFunction = (url, blackSite, tabId) => {
  const message = {
    site: url,
    match: blackSite,
    title: url,
    lenient: inputBlockLenient,
    favicon: `https://www.google.com/s2/favicons?domain=${url}`,
  };

  setTabState(tabId, {
    status: ANALYSIS_STATUS.SUCCESS,
    isBlocked: url,
    isPhish: true,
    legitimatePercent: 0,
    result: {},
    url,
  }).catch(() => {});

  const redirectUrl = `${chrome.runtime.getURL('blocking.html')}#${JSON.stringify(message)}`;
  chrome.tabs.update(tabId, { url: redirectUrl }).catch(err => {
    logger.error('blockingFunction tabs.update failed:', err);
  });
};

const safeCheck = ({ url, tabId }) => {
  if (!url || url.startsWith('chrome://') || url.startsWith(chrome.runtime.getURL('/'))) return;

  // Exact match (OpenPhish + CLD)
  if (blackListingSet.has(url) || blackListingSet.has(url.replace(/\/$/, ''))) {
    blockingFunction(url, url, tabId);
    return;
  }

  // Wildcard match (CLD)
  if (!blackListing || !blackListing.length) return;

  const currentUrl = createUrlObject(url);
  if (!currentUrl) return;

  let currentSiteDomain = '';
  try {
    if (typeof psl !== 'undefined') {
      currentSiteDomain = psl.parse(currentUrl.host).domain || '';
    }
  } catch {
    currentSiteDomain = currentUrl.host;
  }

  const currentPath = currentUrl.href.replaceAll('/', '');

  for (let i = 0; i < blackListing.length; ++i) {
    const blackSite = createUrlObject(blackListing[i]);
    if (!blackSite) continue;

    const prefix = blackSite.host.split('.')[0];
    const suffix = blackSite.pathname;

    if (prefix === '%2A' && currentSiteDomain) {
      const blackDomain = blackSite.host.slice(4);
      if (blackDomain === currentSiteDomain) {
        blockingFunction(url, blackSite.host, tabId);
        return;
      }
    }
    if (suffix === '/*' && currentUrl.host === blackSite.host) {
      blockingFunction(url, blackSite.host, tabId);
      return;
    }
    if (currentPath && currentPath === blackSite.href.replaceAll('/', '')) {
      blockingFunction(url, blackSite.host, tabId);
      return;
    }
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  Event Listeners
// ─────────────────────────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'ANALYSIS_RESULT') {
    const tabId = sender.tab ? sender.tab.id : null;
    const tabUrl = sender.tab ? sender.tab.url : null;
    if (!tabId) {
      sendResponse({ ok: false, reason: 'no sender tab' });
      return true;
    }

    setTabState(tabId, {
      status: ANALYSIS_STATUS.ANALYZING,
      result: request.result,
      url: tabUrl,
      isPhish: false,
      legitimatePercent: 0,
    }).then(() => classify(tabId, request.result, tabUrl))
      .then(() => sendResponse({ ok: true }))
      .catch(err => {
        logger.error('ANALYSIS_RESULT handler error:', err);
        sendResponse({ ok: false, reason: err.message });
      });
    return true;
  }

  if (request.type === 'GET_TAB_STATE') {
    const tabId = request.tabId;
    if (!tabId) { sendResponse(null); return true; }
    getTabState(tabId).then(sendResponse).catch(() => sendResponse(null));
    return true;
  }

  if (request.type === 'SET_WHITELIST_TEMP') {
    const tabId = request.tabId;
    if (!tabId) { sendResponse({ ok: false }); return true; }
    setTabState(tabId, {
      status: ANALYSIS_STATUS.IDLE,
      isWhiteList: null,
      isBlocked: null,
      url: null,
    }).then(() => sendResponse({ ok: true })).catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (request.type === 'SET_ICON') {
    chrome.action.setIcon({ path: request.path, tabId: request.tabId }).catch(() => {});
    sendResponse({ ok: true });
    return true;
  }
});

chrome.tabs.onRemoved.addListener((tabId) => removeTabState(tabId));

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading' && changeInfo.url) {
    setTabState(tabId, {
      status: ANALYSIS_STATUS.ANALYZING,
      result: null,
      url: changeInfo.url,
      isPhish: false,
      legitimatePercent: 0,
    }).catch(() => {});
  }
});

chrome.runtime.onConnect.addListener((port) => {
  switch (port.name) {
    case PORT_REDIRECT:
      port.onMessage.addListener((msg) => {
        chrome.tabs.query({ currentWindow: true, active: true }, ([tab]) => {
          if (tab && msg.redirect) chrome.tabs.update(tab.id, { url: msg.redirect });
        });
      });
      break;
    case PORT_CLOSE_TAB:
      port.onMessage.addListener((msg) => {
        if (msg.close_tab) {
          chrome.tabs.query({ currentWindow: true, active: true }, ([tab]) => {
            if (tab) chrome.tabs.remove(tab.id);
          });
        }
      });
      break;
  }
});

chrome.webRequest.onBeforeRequest.addListener(safeCheck, { urls: ['*://*/*'], types: ['main_frame'] });

chrome.runtime.onStartup.addListener(() => startup().catch(() => {}));
chrome.runtime.onInstalled.addListener(() => {
  startup().catch(() => {});
  chrome.notifications.create({
    type: 'basic',
    iconUrl: chrome.runtime.getURL('assets/antiScamLogo.png'),
    title: 'Cài đặt thành công v1.5!',
    message: 'AntiScam v1.5 đã sẵn sàng bảo vệ bạn khỏi các trang lừa đảo.',
  });
});

startup().catch(() => {});

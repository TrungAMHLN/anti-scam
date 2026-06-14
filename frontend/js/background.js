/* global chrome*/
/* global psl*/
import './engines/domain-intelligence.js';
import './engines/ssl-intelligence.js';
import './engines/threat-intelligence.js';
import './engines/risk-engine.js';

// MV3: Service Worker - không dùng window global, dùng Map thay thế
const stateMap = {
  isWhiteList: {},
  isBlocked: {},
  results: {},
  isPhish: {},
  legitimatePercents: {},
  urlIntel: {},      // Module 1
  domainIntel: {},   // Module 2
  sslIntel: {},      // Module 3
  websiteIntel: {},  // Module 4
  brandIntel: {},    // Module 5
  threatIntel: {},   // Module 6
  finalRisk: {},     // Module 7
};

// File level variables
let blackListing = [];
const whiteListing = [];
let inputBlockLenient = false;

// ─── Performance: in-memory CLF cache (tránh chrome.storage round-trip liên tục)
let _cachedCLF = null;

// ─── Performance: chống duplicate scan (mỗi tab chỉ chạy engines 1 lần)
const analysisInProgress = new Set();

const REDIRECT_PORT_NAME = 'REDIRECT_PORT_NAME';
const CLOSE_TAB_PORT_NAME = 'CLOSE_TAB_PORT_NAME';
const ML_PORT_NAME = 'ML_PORT_NAME';

// ─── Shared fetchWithTimeout helper (dùng cho cả fetchLive, startup, v.v.)
function fetchWithTimeout(resource, options = {}) {
  const { timeout = 5000, ...restOptions } = options;
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  return fetch(resource, { ...restOptions, signal: controller.signal })
    .finally(() => clearTimeout(id));
}

// ─── BƯỚC 4 & 5: PERFORMANCE PROFILER & TELEMETRY
const Profiler = {
  start(name) {
    console.log(`[AntiScam Profiler] [START] ${name}`);
    return performance.now();
  },
  end(name, startTime) {
    const elapsed = (performance.now() - startTime).toFixed(2);
    console.log(`[AntiScam Profiler] [END] ${name} ${elapsed}ms`);
  },
  error(name, err) {
    console.error(`[AntiScam Profiler] [ERROR] ${name}:`, err);
  },
  timeout(name) {
    console.warn(`[AntiScam Profiler] [TIMEOUT] ${name}`);
  }
};


const decisionTree = (root) => {
  const predictOne = (x) => {
    let node = root;
    while(node['type'] == 'split') {
      const threshold = node['threshold'].split(' <= ');
      if (x[threshold[0]] <= threshold[1]) { //Left
        node = node['left'];
      } else { //Right
        node = node['right'];
      }
    }
    return node['value'][0];
  };

  const predict = (X) => {
    return X.map((row) => predictOne(row));
  };

  return {
    'predict': predict,
    'predictOne': predictOne
  };
};


const randomForest = (clf) => {
  const predict = (X) => {
    let pred = [clf['estimators'].map((row) => decisionTree(row).predict(X))];
    pred = pred[0].map((col, i) => pred.map((row) => row[i]));
    const results = [];
    for (const p in pred) {
      let positive=0, negative=0;
      for (const i in pred[p]) {
        positive += pred[p][i][1];
        negative += pred[p][i][0];
      }
      results.push([positive>=negative, Math.max(positive, negative)]);
    }
    return results;
  };
  return {
    'predict': predict
  };
};


const fetchLive = (callback) => {
  fetchWithTimeout('https://api.chongluadao.vn/classifier.json', { timeout: 5000 })
    .then((data) => data.json())
    .then((data) => {
      _cachedCLF = data; // Cache in-memory
      chrome.storage.local.set({
        cache: data,
        cacheTime: Date.now()
      }, () => callback(data));
    })
    .catch(() => callback(null)); // Không treo nếu API lỗi
};


const fetchCLF = (callback) => {
  // ─── Performance: dùng in-memory cache trước, tránh chrome.storage round-trip
  if (_cachedCLF) {
    return callback(_cachedCLF);
  }
  chrome.storage.local.get(['cache', 'cacheTime'], (items) => {
    if (items.cache && items.cacheTime) {
      _cachedCLF = items.cache; // Cache lại vào memory
      return callback(items.cache);
    }
    fetchLive(callback);
  });
};


const classify = (tabId, result, url)  => {
  if (stateMap.isWhiteList[tabId] == url) {
    return;
  }

  let legitimateCount = 0;
  let suspiciousCount = 0;
  let phishingCount = 0;
  for (const key in result) {
    if (result[key] == '1') {
      phishingCount++;
    }
    else if (result[key] == '0') {
      suspiciousCount++;
    }
    else {
      legitimateCount++;
    }
  }
  const total = phishingCount + suspiciousCount + legitimateCount;
  stateMap.legitimatePercents[tabId] = total > 0
    ? (legitimateCount / total * 100)
    : 100;

  // ─── FIX: result là Object (key-value), không phải Array
  // result.length luôn là undefined -> ML không bao giờ chạy!
  const resultValues = Object.values(result);
  if (resultValues.length) {
    const X = [resultValues.map((row) => parseInt(row))];
    const startML = Profiler.start('AI Analysis');
    fetchCLF(function(clf) {
      if (!clf) {
        Profiler.error('AI Analysis', 'Failed to fetch classifier');
        updateFinalRisk(tabId); // Vẫn cập nhật dù ML lỗi
        return;
      }
      const rf = randomForest(clf);
      stateMap.isPhish[tabId] = rf.predict(X)[0][0];
      if (stateMap.isPhish[tabId] && stateMap.legitimatePercents[tabId] > 60) {
        stateMap.isPhish[tabId] = false;
      }
      updateBadge(stateMap.isPhish[tabId], stateMap.legitimatePercents[tabId], tabId);
      Profiler.end('AI Analysis', startML);
      updateFinalRisk(tabId); // ─── FIX: cập nhật Risk sau khi ML xong
    });
  } else {
    // Không có features, vẫn cập nhật risk dựa trên các engine khác
    updateFinalRisk(tabId);
  }
};

function updateFinalRisk(tabId) {
  if (self.RiskEngine) {
    const startRisk = Profiler.start('Risk Engine');
    const dataForRiskEngine = {
      urlIntel: stateMap.urlIntel[tabId] || {},
      domainIntel: stateMap.domainIntel[tabId] || {},
      sslIntel: stateMap.sslIntel[tabId] || {},
      websiteIntel: stateMap.websiteIntel[tabId] || {},
      brandIntel: stateMap.brandIntel[tabId] || {},
      threatIntel: stateMap.threatIntel[tabId] || {},
      mlScore: stateMap.isPhish[tabId] ? 100 : (100 - (stateMap.legitimatePercents[tabId] || 100))
    };
    stateMap.finalRisk[tabId] = self.RiskEngine.calculateFinalRisk(dataForRiskEngine) || {
      finalScore: 0,
      riskLevel: 'SAFE',
      explanation: 'Đang chờ phân tích dữ liệu bổ sung...'
    };
    Profiler.end('Risk Engine', startRisk);
    chrome.runtime.sendMessage({type: 'STATE_UPDATED', tabId: tabId}).catch(() => {});
  }
}


const startup = () => {
  // ─── BƯỚC 7: Bỏ fetch blacklist/whitelist (ERR_NAME_NOT_RESOLVED)
  // Các endpoint api.chongluadao.vn/v1/blacklist đã chết, gây lỗi network.
};

/**
 * Method to block user from accessing a phishing site
 */
const blockingFunction = (url, blackSite, tabId) => {
  const message = {
    site: url,
    match: blackSite,
    title: url,
    lenient: inputBlockLenient,
    favicon: `https://www.google.com/s2/favicons?domain=${url}`,
  };
  stateMap.isBlocked[tabId] = url;

  chrome.action.setIcon({
    path: '/assets/antiScamLogo.png',
    tabId
  }).catch(() => {});

  const redirectUrl = `${chrome.runtime.getURL('blocking.html')}#${JSON.stringify(message)}`;
  
  // MV3: Dùng chrome.tabs.update thay vì return redirectUrl cho webRequestBlocking
  chrome.tabs.update(tabId, {url: redirectUrl}).catch(() => {});
};


const createUrlObject = (url) => {
  try {
    return new URL(url);
  } catch(err) {
    return;
  }
};

/**
 * Method to decide if user can access an URL
 * @param {Object} details of onBeforeRequest event
 * @docs https://developer.chrome.com/docs/extensions/reference/webRequest/#event-onBeforeRequest
 */
const safeCheck = ({url, tabId, initiator}) => {
  // Invalid url
  if (!url || url.indexOf('chrome://') === 0 || url.indexOf(chrome.runtime.getURL('/')) === 0) {
    return;
  }

  // Blacklist is empty or undefined
  if (!blackListing || !blackListing.length) {
    return;
  }

  // MV3: dùng chrome.storage.session thay cho localStorage trong service worker
  // Kiểm tra whitelist tạm thời qua stateMap
  if (stateMap.tempWhiteList && stateMap.tempWhiteList[tabId]) {
    delete stateMap.tempWhiteList[tabId];
    return;
  }

  const sites = blackListing;
  const currentUrl = createUrlObject(url);
  const currentSite = psl.parse(currentUrl.host);
  const currentPath = currentUrl.href.replaceAll('/', '');

  for (let i = 0; i < sites.length; ++i) {
    const blackSite = createUrlObject(sites[i]);
    if (!blackSite) {
      continue;
    }
    const prefix = blackSite.host.split('.')[0];
    const suffix = blackSite.pathname;

    /**
     * Here we check if this blackSite is being blocked for all subdomains
     * format: *.blacksite.com
     */
    if (prefix == '%2A') {
      const blackDomain = blackSite.host.slice(4, blackSite.host.length);
      if(blackDomain == currentSite.domain) {
        return blockingFunction(url, blackSite.host, tabId);
      }
    }

    /**
     * Now we check if this blacksite is being blocked for all url suffix
     * format: blacksite.com/*
     */
    if (suffix == '/*' && currentUrl.host === blackSite.host) {
      return blockingFunction(url, blackSite.host, tabId);
    }

    /**
     * If it wasn't blocked by prefix & suffix above, then we finally check if it match the pathname
     * format: blacksite.com/this-is-path-name?query=some-stupid-query
     */
    if(currentPath && currentPath == blackSite.href.replaceAll('/', '')) {
      return blockingFunction(url, blackSite.host, tabId);
    }
  }

  /**
   * Check if this site is in whitelist
   * REMEMBER : Have to check whitelist AFTER blacklist
   */

  // If not blocklisted, then just check the domain of the initiator instead of sub frame url
  const domain = getDomain(initiator || url);
  if (whiteListing.find((row) => row.includes(domain))) {
    stateMap.isWhiteList[tabId] = domain;
    return;
  }

  return;
};

const sendCurrentUrl = (tab = null) => {
  if (tab && tab.tabId) {
    return updateBadge(stateMap.isPhish[tab.tabId], stateMap.legitimatePercents[tab.tabId], tab.tabId);
  }
  chrome.tabs.query({active: true, currentWindow: true}, ([tab]) =>  {
    updateBadge(stateMap.isPhish[tab.id], stateMap.legitimatePercents[tab.id], tab.id);
  });
};


const updateBadge = (isPhishing, legitimatePercent, tabId) => {
  chrome.action.setTitle({title: `P:${isPhishing} per: ${legitimatePercent}`}).catch(() => {});
  if (isPhishing) {
    return chrome.action.setIcon({
      path: '/assets/antiScamLogo.png',
      tabId
    }).catch(() => {});
  }
  chrome.action.setIcon({
    path: '/assets/antiScamLogo.png',
    tabId
  }).catch(() => {});
};

/**
 * function to get domain from url
 * @param  {String}     url
 * @return {String}     domain
 */
const getDomain = (url) => {
  const matches = url.match(/^https?:\/\/([^/?#]+)(?:[/?#]|$)/i);
  return matches && matches[1];
};


// MV3: Expose state qua chrome.runtime.onMessage thay cho getBackgroundPage()
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'GET_STATE') {
    const tabId = request.tabId;
    if (tabId && !stateMap.domainIntel[tabId]) {
      // BƯỚC 1: Bị sleep và mất state -> trigger chạy lại background engines
      chrome.tabs.get(tabId, (tab) => {
        if (tab && tab.url) {
          runEnginesForTab(tabId, tab.url);
        }
      });
      // BƯỚC 2: Yêu cầu content script gửi lại data
      chrome.tabs.sendMessage(tabId, { type: 'RESEND_INTEL' }).catch(() => {});
    }

    if (tabId && !stateMap.finalRisk[tabId]) {
      updateFinalRisk(tabId); // Force populate if missing
    }

    sendResponse({
      isWhiteList: stateMap.isWhiteList,
      isBlocked: stateMap.isBlocked,
      results: stateMap.results,
      isPhish: stateMap.isPhish,
      legitimatePercents: stateMap.legitimatePercents,
      urlIntel: stateMap.urlIntel,      // Module 1
      domainIntel: stateMap.domainIntel, // Module 2
      sslIntel: stateMap.sslIntel,       // Module 3
      websiteIntel: stateMap.websiteIntel, // Module 4
      brandIntel: stateMap.brandIntel,   // Module 5
      threatIntel: stateMap.threatIntel, // Module 6
      finalRisk: stateMap.finalRisk,     // Module 7
    });
    return true;
  }

  if (request.type === 'SET_WHITELIST_TEMP') {
    if (!stateMap.tempWhiteList) stateMap.tempWhiteList = {};
    stateMap.tempWhiteList[request.tabId] = true;
    sendResponse({ok: true});
    return true;
  }

  if (request.type === 'SET_ICON') {
    chrome.action.setIcon({
      path: request.path.startsWith('/') ? request.path : '/' + request.path,
      tabId: request.tabId
    });
    sendResponse({ok: true});
    return true;
  }
});

chrome.runtime.onStartup.addListener(startup);
chrome.runtime.onInstalled.addListener(() => {
  startup();
  chrome.notifications.create({
    type: 'basic',
    // MV3: chrome.runtime.getURL thay cho chrome.extension.getURL
    iconUrl: chrome.runtime.getURL('/assets/antiScamLogo.png'),
    title: 'Cài đặt thành công!',
    message: 'Khởi động lại trình duyệt của bạn để có thể bắt đầu sử dụng AntiScam. Xin cảm ơn!'
  });
});

chrome.tabs.onActivated.addListener(sendCurrentUrl);

// ─── Shared timeout wrapper cho engines (dùng ở cả onUpdated và ML_PORT_NAME)
function runEnginesForTab(tabId, url) {
  // ─── FIX BUG #1: Chống duplicate scan
  // Nếu tab này đang được analyze, bỏ qua
  if (analysisInProgress.has(tabId)) {
    return;
  }
  analysisInProgress.add(tabId);

  const urlObj = createUrlObject(url);
  if (!urlObj || (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:')) {
    analysisInProgress.delete(tabId);
    return;
  }

  const domain = urlObj.hostname;
  const hasHTTPS = urlObj.protocol === 'https:';

  if (!self.DomainIntelligence || !self.SSLIntelligence || !self.ThreatIntelligence) {
    analysisInProgress.delete(tabId);
    return;
  }

  const raceTimeout = (promise, ms) => Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('engine-timeout')), ms))
  ]);

  const profilePromise = (name, promise) => {
    const start = Profiler.start(name);
    return promise
      .then(res => { Profiler.end(name, start); return res; })
      .catch(err => {
        if (err.message === 'engine-timeout') {
          Profiler.timeout(name);
        } else {
          Profiler.error(name, err);
        }
        throw err;
      });
  };

  Promise.allSettled([
    profilePromise('Domain Analysis', raceTimeout(self.DomainIntelligence.analyzeDomain(domain), 5000)),
    profilePromise('SSL Analysis', raceTimeout(self.SSLIntelligence.analyzeSSL(domain, hasHTTPS), 5000)),
    profilePromise('Threat Analysis', raceTimeout(self.ThreatIntelligence.analyzeThreat(url, null), 5000))
  ]).then(([domainResult, sslResult, threatResult]) => {
    stateMap.domainIntel[tabId] = domainResult.status === 'fulfilled'
      ? { status: 'COMPLETED', data: domainResult.value }
      : { status: 'FAILED', data: { score: 0, riskLevel: 'SAFE', explanation: 'Lỗi/Timeout khi phân tích Tên miền' } };
    stateMap.sslIntel[tabId] = sslResult.status === 'fulfilled'
      ? { status: 'COMPLETED', data: sslResult.value }
      : { status: 'FAILED', data: { score: 0, riskLevel: 'SAFE', explanation: 'Lỗi/Timeout khi phân tích SSL' } };
    stateMap.threatIntel[tabId] = threatResult.status === 'fulfilled'
      ? { status: 'COMPLETED', data: threatResult.value }
      : { status: 'FAILED', data: { score: 0, riskLevel: 'SAFE', explanation: 'Lỗi/Timeout khi phân tích Mối đe dọa' } };
    updateFinalRisk(tabId);
  }).finally(() => {
    // Xóa flag để cho phép scan lại nếu user reload
    analysisInProgress.delete(tabId);
  });
}

chrome.tabs.onUpdated.addListener((tabId, changeinfo, tab) => {
  if (changeinfo.status === 'loading' && tab.url) {
    // Clear old state for this tab to avoid stale data
    stateMap.isWhiteList[tabId] = undefined;
    stateMap.isBlocked[tabId] = undefined;
    stateMap.results[tabId] = undefined;
    stateMap.isPhish[tabId] = undefined;
    stateMap.legitimatePercents[tabId] = undefined;
    stateMap.urlIntel[tabId] = { status: 'ANALYZING' };
    stateMap.domainIntel[tabId] = { status: 'ANALYZING' };
    stateMap.sslIntel[tabId] = { status: 'ANALYZING' };
    stateMap.websiteIntel[tabId] = { status: 'ANALYZING' };
    stateMap.brandIntel[tabId] = { status: 'ANALYZING' };
    stateMap.threatIntel[tabId] = { status: 'ANALYZING' };
    stateMap.finalRisk[tabId] = undefined;
    // ─── FIX: Xóa flag dedup khi trang mới bắt đầu load
    analysisInProgress.delete(tabId);

    // ─── WATCHDOG 2S TIMEOUT ───
    setTimeout(() => {
      let changed = false;
      ['urlIntel', 'websiteIntel', 'brandIntel'].forEach(module => {
        if (stateMap[module][tabId] && stateMap[module][tabId].status === 'ANALYZING') {
          stateMap[module][tabId] = { status: 'TIMEOUT' };
          changed = true;
        }
      });
      if (changed) {
        updateFinalRisk(tabId);
      }
    }, 2000);

    // ─── FIX: Chạy engines ngay khi loading (không đợi content script)
    runEnginesForTab(tabId, tab.url);
  }
  // ─── FIX BUG #3: Không sendMessage 'complete' vì nó gây trigger scan lần 3
  // Content script đã tự gửi message qua mlPort khi document_idle
});

chrome.runtime.onConnect.addListener((port) => {
  switch (port.name) {
  case REDIRECT_PORT_NAME:
    port.onMessage.addListener((msg) => {
      chrome.tabs.query({currentWindow: true, active: true}, ([tab,]) => {
        chrome.tabs.update(tab.id, {url: msg.redirect});
      });
    });
    break;
  case CLOSE_TAB_PORT_NAME:
    port.onMessage.addListener((msg) => {
      if (msg.close_tab) {
        chrome.tabs.query({currentWindow: true, active: true}, ([tab,]) => {
          chrome.tabs.remove(tab.id);
        });
      }
    });
    break;
  case ML_PORT_NAME:
    port.onMessage.addListener((msg) => {
      const {request} = msg;
      if (request.input_block_list !== undefined) {
        blackListing = request.input_block_list;
        inputBlockLenient = request.input_block_lenient;
      }
      
      const tab = port.sender && port.sender.tab;
      if (!tab || !tab.id) return;
      const tabId = tab.id;
      
      stateMap.results[tabId] = request;
      
      // ─── ROOT CAUSE FIX #1 & #2:
      // Lưu data từ content scripts (Module 1, 4, 5) TRƯỚC khi gọi bất kỳ thứ gì
      // urlIntel luôn được ghi lại khi content script kết nối
      if (msg.urlIntel) stateMap.urlIntel[tabId] = { status: 'COMPLETED', data: msg.urlIntel };
      if (msg.websiteIntel) stateMap.websiteIntel[tabId] = { status: 'COMPLETED', data: msg.websiteIntel };
      if (msg.brandIntel) stateMap.brandIntel[tabId] = { status: 'COMPLETED', data: msg.brandIntel };

      // ─── ROOT CAUSE FIX #3:
      // KHÔNG gọi runEnginesForTab từ đây!
      // engines đã được khởi động bởi onUpdated(loading)
      // Nếu gọi lại: dedup guard sẽ block -> urlIntel được ghi rồi xong bị block
      // Chỉ chạy engines nếu chưa chạy lần nào (tab restore, extension reload)
      // Lưu ý: stateMap.domainIntel[tabId] giờ là object {status: 'ANALYZING'}, nên check undefined là không đủ
      const isDomainIntelRun = stateMap.domainIntel[tabId] && stateMap.domainIntel[tabId].status !== 'ANALYZING';
      if (!isDomainIntelRun && tab.url) {
        // Có thể watchdog hoặc onUpdated chưa chạy
        runEnginesForTab(tabId, tab.url);
      }

      classify(tabId, request, tab.url);
      updateFinalRisk(tabId);
    });
    break;
  default:
    ML_PORT_NAME;
    break;
  }
});

// MV3: Bỏ ['blocking'] để không vi phạm permissions, sử dụng chrome.tabs.update bên trong safeCheck
chrome.webRequest.onBeforeRequest.addListener(safeCheck, {
  urls: ['*://*/*'],
  types: ['main_frame', 'sub_frame']
});

// ─── FIX: Dọn stateMap khi tab đóng — tránh memory leak
chrome.tabs.onRemoved.addListener((tabId) => {
  delete stateMap.isWhiteList[tabId];
  delete stateMap.isBlocked[tabId];
  delete stateMap.results[tabId];
  delete stateMap.isPhish[tabId];
  delete stateMap.legitimatePercents[tabId];
  delete stateMap.urlIntel[tabId];
  delete stateMap.domainIntel[tabId];
  delete stateMap.sslIntel[tabId];
  delete stateMap.websiteIntel[tabId];
  delete stateMap.brandIntel[tabId];
  delete stateMap.threatIntel[tabId];
  delete stateMap.finalRisk[tabId];
  analysisInProgress.delete(tabId);
});

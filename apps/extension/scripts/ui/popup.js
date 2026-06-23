/* global chrome */
/* global $ */

// ─────────────────────────────────────────────────────────────────────────────
// Màu sắc badge
// ─────────────────────────────────────────────────────────────────────────────
const colors = { '-1':'#22c55e', '0':'#facc15', '2':'#fb923c', '1':'#dc2626' };
const reasonColors = { safe:'#22c55e', warning:'#facc15', suspicious:'#fb923c', danger:'#dc2626' };
let currentTabUrl = '';
let currentDomain = '';
let currentPageTitle = '';

// ═══════════════════════════════════════════════════════════════════════════
// UNIFIED STATE — activeAnalysis LÀ SOURCE OF TRUTH DUY NHẤT
// TOÀN BỘ UI PHẢI RENDER TỪ activeAnalysis
// ═══════════════════════════════════════════════════════════════════════════
const ScanSource = Object.freeze({ CURRENT_TAB: 'CURRENT_TAB', CUSTOM_URL: 'CUSTOM_URL' });

const activeAnalysis = {
  source: null,              // ScanSource.CURRENT_TAB | CUSTOM_URL | null
  url: null,                 // URL đầy đủ đang phân tích
  domain: null,              // Domain hiển thị — LUÔN đồng bộ với #domain_url

  // ── Kết quả phân tích — cùng format với classify() output ──
  status: null,              // 'LOADING' | 'ANALYZING' | 'SUCCESS' | 'FAILED' | 'OFFLINE' | 'SCAN_BLOCKED'
  isWhiteList: null,
  isBlocked: null,
  isPhish: null,
  legitimatePercent: null,
  confidence: null,
  riskScore: null,
  trustScore: null,
  trustContext: null,
  isUnknown: null,
  result: null,              // Object ML features
  summary: null,
  explanations: null,        // Array tín hiệu giải thích
  counts: null,              // Link/script/image/iframe/form counts
  domainAge: null,
  reputation: null,

  // ── Loading state ──
  loadingText: null,         // Text hiển thị khi đang loading

  // ── CURRENT_TAB specific ──
  tabId: null,

  // ── CUSTOM_URL specific ──
  scanUrl: null,

  // ── Timestamps ──
  startedAt: null,
  completedAt: null,
};

/**
 * Cập nhật activeAnalysis và render UI — ĐỘC NHẤT
 * @param {object} partial — Các field cần cập nhật
 */
const updateAnalysis = (partial) => {
  Object.assign(activeAnalysis, partial);
  renderActiveAnalysis();
};

/**
 * Reset toàn bộ analysis data về null (giữ source, url, domain, tabId, scanUrl)
 */
const resetAnalysisData = () => {
  activeAnalysis.status = null;
  activeAnalysis.isWhiteList = null;
  activeAnalysis.isBlocked = null;
  activeAnalysis.isPhish = null;
  activeAnalysis.legitimatePercent = null;
  activeAnalysis.confidence = null;
  activeAnalysis.riskScore = null;
  activeAnalysis.trustScore = null;
  activeAnalysis.trustContext = null;
  activeAnalysis.isUnknown = null;
  activeAnalysis.result = null;
  activeAnalysis.summary = null;
  activeAnalysis.explanations = null;
  activeAnalysis.counts = null;
  activeAnalysis.domainAge = null;
  activeAnalysis.reputation = null;
  activeAnalysis.loadingText = null;
  activeAnalysis.completedAt = null;
};

// Saved CURRENT_TAB analysis — khôi phục khi user nhấn Back
let savedCurrentTabAnalysis = null;

// Custom URL scan poll timer
let customUrlPollTimer = null;

// History
const HISTORY_KEY = 'antiscam_url_scan_history';
const MAX_HISTORY = 5;

// ═══════════════════════════════════════════════════════════════════════════
// THEME
// ═══════════════════════════════════════════════════════════════════════════
const initTheme = () => {
  const stored = localStorage.getItem('antiscam-theme');
  const saved = (stored === 'light' || stored === 'dark') ? stored : 'dark';
  document.documentElement.setAttribute('data-theme', saved);
  localStorage.setItem('antiscam-theme', saved);
  const btn = document.getElementById('themeToggle');
  if (btn) {
    btn.checked = saved === 'light';
    btn.setAttribute('aria-label', saved === 'light' ? 'Đang dùng giao diện sáng' : 'Đang dùng giao diện tối');
  }
};
const toggleTheme = (event) => {
  const checked = event && event.target ? !!event.target.checked : (document.documentElement.getAttribute('data-theme') !== 'light');
  const next = checked ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('antiscam-theme', next);
  const btn = document.getElementById('themeToggle');
  if (btn) {
    btn.checked = next === 'light';
    btn.setAttribute('aria-label', next === 'light' ? 'Đang dùng giao diện sáng' : 'Đang dùng giao diện tối');
  }
};
initTheme();
const themeBtn = document.getElementById('themeToggle');
if (themeBtn) themeBtn.addEventListener('change', toggleTheme);

// ═══════════════════════════════════════════════════════════════════════════
// Collapsible "Xem chi tiết"
// ═══════════════════════════════════════════════════════════════════════════
const setupCollapsible = () => {
  [...document.getElementsByClassName('collapsible')].forEach((el) => {
    const newEl = el.cloneNode(true);
    el.parentNode.replaceChild(newEl, el);
    newEl.addEventListener('click', function () {
      this.classList.toggle('active');
      const content = this.nextElementSibling;
      if (content.style.maxHeight) { content.style.maxHeight = null; }
      else { content.style.maxHeight = `${content.scrollHeight}px`; }
    });
  });
};
setupCollapsible();

// ═══════════════════════════════════════════════════════════════════════════
// Dynamic class tracking
// ═══════════════════════════════════════════════════════════════════════════
let _dynClasses = { pct:[], score:[], msg:[] };
const _cleanDyn = () => {
  const pc = document.getElementById('percentage_content');
  const ss = document.getElementById('site_score');
  const sm = document.getElementById('site_msg');
  _dynClasses.pct.forEach(c => pc && pc.classList.remove(c));
  _dynClasses.score.forEach(c => ss && ss.classList.remove(c));
  _dynClasses.msg.forEach(c => sm && sm.classList.remove(c));
  _dynClasses = { pct:[], score:[], msg:[] };
};

// ═══════════════════════════════════════════════════════════════════════════
// RENDER ENGINE — ĐỘC NHẤT, chỉ đọc từ activeAnalysis
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Render trạng thái LOADING — đọc domain và loadingText từ activeAnalysis
 */
const renderLoadingState = () => {
  const domain = activeAnalysis.domain || '';
  const statusText = activeAnalysis.loadingText || 'Đang phân tích...';

  console.log('[RENDER] renderLoadingState:', domain, statusText);

  $('#pluginBody').show();
  $('#isSafe').hide();
  $('#isPhishing').hide();

  _cleanDyn();

  const pct_content = document.getElementById('percentage_content');
  const site_score = document.getElementById('site_score');
  const site_msg = document.getElementById('site_msg');
  const featureList = document.getElementById('features');

  if (site_score) site_score.textContent = '...';
  if (pct_content) {
    pct_content.className = 'c100 center';
  }

  if (site_msg) {
    site_msg.className = 'site_message';
    site_msg.textContent = statusText;
  }

  $('#domain_url').text(domain);

  if (featureList) featureList.innerHTML = '<li class="feature-empty">Đang thu thập dữ liệu...</li>';

  const collapsible = document.querySelector('.collapsible');
  const featureContent = document.querySelector('.feature-content');
  if (collapsible && !collapsible.classList.contains('active')) {
    collapsible.classList.add('active');
  }
  if (featureContent) {
    featureContent.style.maxHeight = `${featureContent.scrollHeight + 200}px`;
  }
};

/**
 * Render kết quả phân tích — đọc TOÀN BỘ từ activeAnalysis
 */
const renderResultState = () => {
  const domain = activeAnalysis.domain || '';
  const state = activeAnalysis; // activeAnalysis CÓ CÙNG FORMAT với classify() output

  console.log('[RENDER] renderResultState:', domain, state.status, state.legitimatePercent);

  const { isWhiteList, isBlocked, isPhish, legitimatePercent, confidence, status, isUnknown } = state;

  $('#pluginBody').show();
  $('#isSafe').hide();
  $('#isPhishing').hide();

  const phishH2 = document.querySelector('#isPhishing h2');
  if (phishH2) phishH2.textContent = 'Website nguy hiểm';

  if (isWhiteList) {
    $('#pluginBody').hide(); $('#isSafe').show(); $('#isSafe .site-url').text(domain); return;
  }
  if (isBlocked) {
    $('#pluginBody').hide(); $('#isPhishing').show(); $('#isPhishing .site-url').text(isBlocked); return;
  }
  if (status === 'SCAN_BLOCKED') {
    $('#pluginBody').hide(); $('#isPhishing').show();
    $('#isPhishing .site-url').text(domain);
    if (phishH2) phishH2.textContent = 'Không thể quét trang';
    return;
  }

  _cleanDyn();

  const featureList = document.getElementById('features');
  if (typeof renderUnifiedChips === 'function') {
      renderUnifiedChips(featureList, state);
  }

  const featureContent = featureList.closest('.feature-content');
  if (featureContent && featureContent.style.maxHeight) featureContent.style.maxHeight = `${featureContent.scrollHeight}px`;

  const pct = parseInt(legitimatePercent);
  const confidencePct = parseInt(confidence);
  const isValidPct = !isNaN(pct) && isFinite(pct);
  const isValidConfidence = !isNaN(confidencePct) && isFinite(confidencePct);

  const site_score = document.getElementById('site_score');
  const pct_content = document.getElementById('percentage_content');
  const site_msg = document.getElementById('site_msg');

  const pctCls = `p${isValidPct ? pct : 0}`;
  pct_content.classList.add(pctCls); _dynClasses.pct.push(pctCls);
  if (isPhish) { pct_content.classList.add('orange'); _dynClasses.pct.push('orange'); }

  if (isPhish) {
    site_score.classList.add('warning'); _dynClasses.score.push('warning');
    site_msg.classList.add('warning'); _dynClasses.msg.push('warning');
  } else {
    site_score.classList.add('safe'); _dynClasses.score.push('safe');
    site_msg.classList.add('safe'); _dynClasses.msg.push('safe');
  }

  let message;
  if (status === 'OFFLINE') message = 'Không thể kết nối máy chủ phân tích.';
  else if (status === 'FAILED') message = 'Không thể phân tích trang này.';
  else if (isUnknown) message = 'Chưa đủ dữ liệu để đánh giá độ tin cậy.';
  else message = isPhish ? 'Website có nguy cơ cao.' : 'Website đã được phân tích.';

  $('#site_score').text(isValidPct ? `${pct}%` : '...');

  if (isValidPct) {
    const accuracyLine = document.createElement('div');
    accuracyLine.className = 'sub-note accuracy-note';
    accuracyLine.textContent = `Độ tin cậy: ${isValidConfidence ? confidencePct : 0}%`;
    
    $('#site_msg').text(message);
    $('#site_msg').append(accuracyLine);
    
    if (isUnknown) {
      const unknownLine = document.createElement('div');
      unknownLine.className = 'sub-note';
      unknownLine.textContent = 'Chưa đủ dữ liệu — không nhập thông tin nhạy cảm nếu chưa chắc chắn.';
      $('#site_msg').append(unknownLine);
    }
  } else {
    $('#site_msg').text('...');
  }
  $('#domain_url').text(domain);
};

/**
 * ══════════════════════════════════════════════════════════════════════════
 * renderActiveAnalysis — HÀM RENDER DUY NHẤT — ĐỌC TỪ activeAnalysis
 * MỌI thay đổi UI phải đi qua hàm này
 * ══════════════════════════════════════════════════════════════════════════
 */
const renderActiveAnalysis = () => {
  if (!activeAnalysis.source || !activeAnalysis.domain) return;

  const { status } = activeAnalysis;

  // Loading states
  if (status === 'LOADING' || status === 'ANALYZING' || status === null) {
    renderLoadingState();
    return;
  }

  // Result states
  if (status === 'SUCCESS' || status === 'FAILED' || status === 'OFFLINE' || status === 'SCAN_BLOCKED') {
    renderResultState();
    return;
  }

  // Fallback
  renderLoadingState();
};

// ═══════════════════════════════════════════════════════════════════════════
// PIPELINE A — CURRENT TAB SCAN
// ═══════════════════════════════════════════════════════════════════════════
const POLL_INTERVAL_MS = 800;
const UPDATE_INTERVAL_MS = 1500;
const POLL_MAX_ATTEMPTS = 19;

chrome.tabs.query({ currentWindow: true, active: true }, ([tab]) => {
  if (!tab) return;
  const tabId = tab.id;
  let url; try { url = new URL(tab.url); } catch { return; }
  const domain = url.hostname.replace(/^www\./i, '');
  currentTabUrl = tab.url;
  currentDomain = domain;
  currentPageTitle = tab.title || '';
  updateReportTargetInfo();

  if (!['https:', 'http:'].includes(url.protocol)) {
    $('#pluginBody').hide(); $('#domain_url').text(domain); return;
  }

  // Khởi tạo activeAnalysis cho CURRENT_TAB
  activeAnalysis.source = ScanSource.CURRENT_TAB;
  activeAnalysis.url = tab.url;
  activeAnalysis.domain = domain;
  activeAnalysis.tabId = tabId;
  activeAnalysis.status = 'LOADING';
  activeAnalysis.loadingText = 'Đang phân tích...';
  activeAnalysis.startedAt = Date.now();

  // Render loading ngay lập tức
  renderActiveAnalysis();

  let attempts = 0;
  let lastUpdatedAt = 0;

  const poll = () => {
    // ✅ CHỈ poll khi source là CURRENT_TAB
    if (activeAnalysis.source !== ScanSource.CURRENT_TAB) return;

    chrome.runtime.sendMessage({ type: 'GET_TAB_STATE', tabId }, (state) => {
      // ✅ CRITICAL: Kiểm tra lại source sau khi nhận response
      // Tránh race condition: request bay trước khi user chuyển sang CUSTOM_URL
      if (activeAnalysis.source !== ScanSource.CURRENT_TAB) return;

      if (chrome.runtime.lastError) {
        if (attempts < POLL_MAX_ATTEMPTS) { attempts++; setTimeout(poll, POLL_INTERVAL_MS); }
        else {
          updateAnalysis({
            status: 'FAILED',
            loadingText: 'Tiện ích chưa sẵn sàng. Thử tải lại trang.',
            legitimatePercent: null,
          });
        }
        return;
      }

      const stillAnalyzing = !state || state.status === 'ANALYZING' || state.status === 'IDLE';
      if (stillAnalyzing) {
        if (attempts < POLL_MAX_ATTEMPTS) { attempts++; setTimeout(poll, POLL_INTERVAL_MS); }
        else if (state && state.result) {
          // Có kết quả dù vẫn analyzing → cập nhật activeAnalysis
          updateAnalysis({
            status: state.status,
            isWhiteList: state.isWhiteList || null,
            isBlocked: state.isBlocked || null,
            isPhish: state.isPhish,
            legitimatePercent: state.legitimatePercent,
            confidence: state.confidence,
            riskScore: state.riskScore,
            trustScore: state.trustScore,
            trustContext: state.trustContext,
            isUnknown: state.isUnknown,
            result: state.result,
            summary: state.summary,
            explanations: state.explanations,
            counts: state.counts,
            domainAge: state.domainAge,
            reputation: state.reputation,
            completedAt: Date.now(),
          });
        }
        else {
          updateAnalysis({
            status: 'FAILED',
            loadingText: 'Trang chưa được phân tích. Thử tải lại trang.',
            legitimatePercent: null,
          });
        }
        return;
      }

      const updatedNow = state && state.updatedAt && state.updatedAt !== lastUpdatedAt;
      if (updatedNow) {
        lastUpdatedAt = state ? state.updatedAt : 0;
      }

      // ✅ CẬP NHẬT activeAnalysis — SOURCE OF TRUTH
      updateAnalysis({
        status: state.status,
        isWhiteList: state.isWhiteList || null,
        isBlocked: state.isBlocked || null,
        isPhish: state.isPhish,
        legitimatePercent: state.legitimatePercent,
        confidence: state.confidence,
        riskScore: state.riskScore,
        trustScore: state.trustScore,
        trustContext: state.trustContext,
        isUnknown: state.isUnknown,
        result: state.result,
        summary: state.summary,
        explanations: state.explanations,
        counts: state.counts,
        domainAge: state.domainAge,
        reputation: state.reputation,
        completedAt: Date.now(),
      });

      setTimeout(poll, UPDATE_INTERVAL_MS);
    });
  };

  poll();
});


// ═══════════════════════════════════════════════════════════════════════════
// PIPELINE B — CUSTOM URL SCAN
// ═══════════════════════════════════════════════════════════════════════════
const customUrlInput = document.getElementById('customUrlInput');
const customUrlScanBtn = document.getElementById('customUrlScanBtn');
const customUrlScanStatus = document.getElementById('customUrlScanStatus');
const backToCurrentTab = document.getElementById('backToCurrentTab');
const historyToggle = document.getElementById('historyToggle');
const historyPanel = document.getElementById('historyPanel');
const historyCloseBtn = document.getElementById('historyCloseBtn');
const historyList = document.getElementById('historyList');
const historyEmpty = document.getElementById('historyEmpty');

const setCustomScanStatus = (msg, type = '') => {
  if (!customUrlScanStatus) return;
  customUrlScanStatus.textContent = msg || '';
  customUrlScanStatus.classList.remove('success', 'error', 'loading');
  if (type) customUrlScanStatus.classList.add(type);
};

const normalizeUrl = (raw) => {
  let u = (raw || '').trim();
  if (!u) return '';
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  try { return new URL(u).href; } catch { return ''; }
};

// ── Lịch sử quét ─────────────────────────────────────────────────────────
const loadHistory = async () => {
  try {
    const data = await chrome.storage.local.get(HISTORY_KEY);
    return data[HISTORY_KEY] || [];
  } catch { return []; }
};

const saveHistory = async (history) => {
  try {
    await chrome.storage.local.set({ [HISTORY_KEY]: history.slice(0, MAX_HISTORY) });
  } catch {}
};

const addToHistory = async (url, domain, score) => {
  const history = await loadHistory();
  if (history.length > 0 && history[0].url === url) {
    history[0].score = score;
    await saveHistory(history);
    renderHistory();
    return;
  }
  history.unshift({ url, domain, score, timestamp: Date.now() });
  if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;
  await saveHistory(history);
  renderHistory();
};

const removeFromHistory = async (index) => {
  const history = await loadHistory();
  history.splice(index, 1);
  await saveHistory(history);
  renderHistory();
};

const formatTimestamp = (ts) => {
  const d = new Date(ts);
  const pad = (n) => String(n).padStart(2, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())} ${pad(d.getDate())}/${pad(d.getMonth()+1)}/${d.getFullYear()}`;
};

const scoreColor = (score) => {
  if (score == null) return 'var(--muted-text)';
  const s = parseInt(score);
  if (isNaN(s)) return 'var(--muted-text)';
  if (s >= 70) return 'var(--neon-green)';
  if (s >= 40) return '#facc15';
  return '#dc2626';
};

const renderHistory = async () => {
  const history = await loadHistory();
  if (!historyList) return;
  historyList.innerHTML = '';
  if (historyEmpty) historyEmpty.style.display = history.length ? 'none' : 'block';

  history.forEach((item, idx) => {
    const li = document.createElement('li');
    li.className = 'history-item';

    const info = document.createElement('div');
    info.className = 'history-item-info';

    const topRow = document.createElement('div');
    topRow.className = 'history-item-top-row';

    const domainSpan = document.createElement('span');
    domainSpan.className = 'history-item-domain';
    domainSpan.textContent = item.domain || item.url;
    domainSpan.title = item.url;

    const scoreSpan = document.createElement('span');
    scoreSpan.className = 'history-item-score';
    if (item.score != null) {
      scoreSpan.textContent = `${item.score}%`;
      scoreSpan.style.color = scoreColor(item.score);
    } else {
      scoreSpan.textContent = '—';
    }

    topRow.appendChild(domainSpan);
    topRow.appendChild(scoreSpan);

    const timeSpan = document.createElement('span');
    timeSpan.className = 'history-item-time';
    timeSpan.textContent = formatTimestamp(item.timestamp);

    info.appendChild(topRow);
    info.appendChild(timeSpan);

    const deleteBtn = document.createElement('button');
    deleteBtn.type = 'button';
    deleteBtn.className = 'history-item-delete';
    deleteBtn.title = 'Xoá khỏi lịch sử';
    deleteBtn.innerHTML = '<i class="fa-solid fa-trash-can"></i>';
    deleteBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      removeFromHistory(idx);
    });

    li.addEventListener('click', () => {
      if (customUrlInput) customUrlInput.value = item.url;
      startCustomUrlScan(item.url);
      if (historyPanel) historyPanel.hidden = true;
    });

    li.appendChild(info);
    li.appendChild(deleteBtn);
    historyList.appendChild(li);
  });
};

// ── Hiện/ẩn lịch sử ──────────────────────────────────────────────────────
if (historyToggle) {
  historyToggle.addEventListener('click', () => {
    if (!historyPanel) return;
    const isOpen = !historyPanel.hidden;
    historyPanel.hidden = isOpen;
    if (!isOpen) renderHistory();
  });
}
if (historyCloseBtn) {
  historyCloseBtn.addEventListener('click', () => {
    if (historyPanel) historyPanel.hidden = true;
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// startCustomUrlScan — ĐỘNG CƠ CHÍNH CỦA PIPELINE B
// ═══════════════════════════════════════════════════════════════════════════
const startCustomUrlScan = (rawUrl) => {
  const url = normalizeUrl(rawUrl);
  if (!url) {
    setCustomScanStatus('URL không hợp lệ.', 'error');
    return;
  }

  let domain = '';
  try { domain = new URL(url).hostname.replace(/^www\./i, ''); } catch {}

  console.log('[POPUP] [SCAN_JOB_CREATED] source=CUSTOM_URL url=' + url + ' domain=' + domain);

  // ── BƯỚC 1: Lưu activeAnalysis hiện tại (CURRENT_TAB) ──
  if (activeAnalysis.source === ScanSource.CURRENT_TAB) {
    savedCurrentTabAnalysis = { ...activeAnalysis };
    console.log('[POPUP] Saved CURRENT_TAB analysis for domain:', savedCurrentTabAnalysis.domain);
  }

  // ── BƯỚC 2: CHUYỂN activeAnalysis SANG CUSTOM_URL ──
  // Reset TOÀN BỘ data, chỉ giữ source mới
  activeAnalysis.source = ScanSource.CUSTOM_URL;
  activeAnalysis.url = url;
  activeAnalysis.domain = domain;
  activeAnalysis.scanUrl = url;
  activeAnalysis.tabId = null;
  activeAnalysis.startedAt = Date.now();
  resetAnalysisData();
  activeAnalysis.status = 'LOADING';
  activeAnalysis.loadingText = 'Đang gửi yêu cầu quét...';

  // ── BƯỚC 3: RENDER NGAY LẬP TỨC — UI chuyển HOÀN TOÀN sang URL mới ──
  renderActiveAnalysis();
  setCustomScanStatus('Đang quét...', 'loading');
  showBackButton(true);
  if (customUrlScanBtn) customUrlScanBtn.disabled = true;

  // ── BƯỚC 4: Gửi SCAN_URL đến background ──
  console.log('[POPUP] [SCAN_URL] ' + url);
  chrome.runtime.sendMessage({ type: 'SCAN_URL', url }, (resp) => {
    if (chrome.runtime.lastError) {
      console.error('[POPUP] SCAN_URL error:', chrome.runtime.lastError);
      // ✅ Kiểm tra source trước khi cập nhật
      if (activeAnalysis.source === ScanSource.CUSTOM_URL) {
        updateAnalysis({ status: 'FAILED', loadingText: 'Lỗi kết nối đến background.' });
      }
      setCustomScanStatus('Lỗi kết nối đến background.', 'error');
      if (customUrlScanBtn) customUrlScanBtn.disabled = false;
      return;
    }
    if (!resp || !resp.ok) {
      console.error('[POPUP] SCAN_URL rejected:', resp);
      if (activeAnalysis.source === ScanSource.CUSTOM_URL) {
        updateAnalysis({ status: 'FAILED', loadingText: 'Không thể quét URL này.' });
      }
      setCustomScanStatus('Không thể quét URL này.', 'error');
      if (customUrlScanBtn) customUrlScanBtn.disabled = false;
      return;
    }

    console.log('[POPUP] Background accepted scan for ' + url);

    if (customUrlPollTimer) clearInterval(customUrlPollTimer);

    // Cập nhật loading text
    if (activeAnalysis.source === ScanSource.CUSTOM_URL) {
      updateAnalysis({ status: 'LOADING', loadingText: 'Đang tải trang...' });
    }

    let scanAttempts = 0;
    const SCAN_POLL_INTERVAL = 800;
    const SCAN_POLL_MAX = 75;

    const pollScanResult = () => {
      // ✅ Chỉ poll khi vẫn đang ở CUSTOM_URL mode
      if (activeAnalysis.source !== ScanSource.CUSTOM_URL) {
        clearInterval(customUrlPollTimer);
        customUrlPollTimer = null;
        return;
      }

      chrome.runtime.sendMessage({ type: 'GET_URL_SCAN_STATE', url }, (state) => {
        // ✅ CRITICAL: Kiểm tra lại source sau khi nhận response
        if (activeAnalysis.source !== ScanSource.CUSTOM_URL) return;

        if (chrome.runtime.lastError) {
          scanAttempts++;
          if (scanAttempts >= SCAN_POLL_MAX) {
            clearInterval(customUrlPollTimer);
            customUrlPollTimer = null;
            setCustomScanStatus('Lỗi kết nối.', 'error');
            if (customUrlScanBtn) customUrlScanBtn.disabled = false;
          }
          return;
        }

        if (!state || state.status === 'ANALYZING' || state.status === 'IDLE') {
          scanAttempts++;

          // ✅ Cập nhật loading text qua activeAnalysis
          if (activeAnalysis.source === ScanSource.CUSTOM_URL) {
            let loadingText = 'Đang phân tích...';
            if (scanAttempts < 3) loadingText = 'Đang tải trang...';
            else if (scanAttempts < 8) loadingText = 'Đang thu thập dữ liệu...';
            else loadingText = 'Đang phân tích...';
            updateAnalysis({ status: 'ANALYZING', loadingText });
          }

          if (scanAttempts >= SCAN_POLL_MAX) {
            clearInterval(customUrlPollTimer);
            customUrlPollTimer = null;
            updateAnalysis({ status: 'FAILED', loadingText: 'Quá thời gian chờ.' });
            setCustomScanStatus('Quá thời gian chờ.', 'error');
            if (customUrlScanBtn) customUrlScanBtn.disabled = false;
          }
          return;
        }

        // Kết quả sẵn sàng
        clearInterval(customUrlPollTimer);
        customUrlPollTimer = null;

        console.log('[POPUP] [COMPLETED] status=' + state.status + ' score=' + state.legitimatePercent);

        if (state.status === 'FAILED') {
          updateAnalysis({
            status: 'FAILED',
            loadingText: 'Không thể phân tích URL này.',
          });
          setCustomScanStatus('Không thể phân tích URL này.', 'error');
          if (customUrlScanBtn) customUrlScanBtn.disabled = false;
          return;
        }

        if (state.status === 'SCAN_BLOCKED') {
          updateAnalysis({
            status: 'SCAN_BLOCKED',
            isBlocked: activeAnalysis.domain,
          });
          setCustomScanStatus('Trang web có bảo vệ chống bot (Cloudflare/Captcha) — không thể quét tự động.', 'error');
          if (customUrlScanBtn) customUrlScanBtn.disabled = false;
          return;
        }

        // ═══════════════════════════════════════════════════════════════
        // ✅ CẬP NHẬT activeAnalysis — TOÀN BỘ data từ custom URL scan
        // Đây là fix chính: UI render TỪ activeAnalysis, không từ currentTab
        // ═══════════════════════════════════════════════════════════════
        updateAnalysis({
          status: state.status,
          isWhiteList: state.isWhiteList || null,
          isBlocked: state.isBlocked || null,
          isPhish: state.isPhish,
          legitimatePercent: state.legitimatePercent,
          confidence: state.confidence,
          riskScore: state.riskScore,
          trustScore: state.trustScore,
          trustContext: state.trustContext,
          isUnknown: state.isUnknown,
          result: state.result,
          summary: state.summary,
          explanations: state.explanations,
          counts: state.counts,
          domainAge: state.domainAge,
          reputation: state.reputation,
          completedAt: Date.now(),
          loadingText: null,
        });

        setCustomScanStatus('', '');
        showBackButton(true);

        const score = state.legitimatePercent != null ? parseInt(state.legitimatePercent) : null;
        addToHistory(url, domain, score);

        if (customUrlScanBtn) customUrlScanBtn.disabled = false;
      });
    };

    // Poll ngay lập tức, rồi mỗi SCAN_POLL_INTERVAL
    pollScanResult();
    customUrlPollTimer = setInterval(pollScanResult, SCAN_POLL_INTERVAL);
  });
};

// ── Nút quét ──────────────────────────────────────────────────────────────
if (customUrlScanBtn) {
  customUrlScanBtn.addEventListener('click', () => {
    const raw = customUrlInput ? customUrlInput.value : '';
    startCustomUrlScan(raw);
  });
}

if (customUrlInput) {
  customUrlInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      startCustomUrlScan(customUrlInput.value);
    }
  });
}

// ── Nút quay về ───────────────────────────────────────────────────────────
const showBackButton = (show) => {
  if (backToCurrentTab) backToCurrentTab.hidden = !show;
};

if (backToCurrentTab) {
  backToCurrentTab.addEventListener('click', () => {
    if (activeAnalysis.source !== ScanSource.CUSTOM_URL) return;
    console.log('[POPUP] Back to CURRENT_TAB');

    // Dừng custom URL poll
    if (customUrlPollTimer) {
      clearInterval(customUrlPollTimer);
      customUrlPollTimer = null;
    }

    // Cleanup scan result cũ
    if (customUrlInput) {
      const scanUrl = normalizeUrl(customUrlInput.value);
      if (scanUrl) {
        chrome.runtime.sendMessage({ type: 'CLEAR_URL_SCAN_RESULT', url: scanUrl }).catch(() => {});
      }
    }

    setCustomScanStatus('', '');
    showBackButton(false);
    if (customUrlScanBtn) customUrlScanBtn.disabled = false;

    // ✅ KHÔI PHỤC activeAnalysis từ savedCurrentTabAnalysis
    if (savedCurrentTabAnalysis) {
      Object.assign(activeAnalysis, savedCurrentTabAnalysis);
      savedCurrentTabAnalysis = null;

      // Render ngay từ activeAnalysis đã khôi phục
      renderActiveAnalysis();

      // Sau đó poll lại để lấy state mới nhất
      const tabId = activeAnalysis.tabId;
      if (tabId) {
        setTimeout(() => {
          if (activeAnalysis.source === ScanSource.CURRENT_TAB) {
            chrome.runtime.sendMessage({ type: 'GET_TAB_STATE', tabId }, (state) => {
              // ✅ Kiểm tra source trong callback
              if (activeAnalysis.source !== ScanSource.CURRENT_TAB) return;
              if (state && state.status !== 'ANALYZING' && state.status !== 'IDLE') {
                updateAnalysis({
                  status: state.status,
                  isWhiteList: state.isWhiteList || null,
                  isBlocked: state.isBlocked || null,
                  isPhish: state.isPhish,
                  legitimatePercent: state.legitimatePercent,
                  confidence: state.confidence,
                  riskScore: state.riskScore,
                  trustScore: state.trustScore,
                  trustContext: state.trustContext,
                  isUnknown: state.isUnknown,
                  result: state.result,
                  summary: state.summary,
                  explanations: state.explanations,
                  counts: state.counts,
                  domainAge: state.domainAge,
                  reputation: state.reputation,
                  completedAt: Date.now(),
                });
              }
            });
          }
        }, 500);
      }
    } else {
      // Fallback: reset về CURRENT_TAB loading
      activeAnalysis.source = ScanSource.CURRENT_TAB;
      activeAnalysis.url = currentTabUrl;
      activeAnalysis.domain = currentDomain;
      resetAnalysisData();
      activeAnalysis.status = 'LOADING';
      activeAnalysis.loadingText = 'Đang phân tích...';
      renderActiveAnalysis();

      // Re-poll
      setTimeout(() => location.reload(), 300);
    }
  });
}


// ═══════════════════════════════════════════════════════════════════════════
// Community report UI
// ═══════════════════════════════════════════════════════════════════════════
const REPORT_API_URL = 'https://anti-scam-6iix.onrender.com/api/report';
const REPORT_MAX_FILE_SIZE = 5 * 1024 * 1024;
const REPORT_ALLOWED_TYPES = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp'];

const reportToggle = document.getElementById('reportToggle');
const reportForm = document.getElementById('reportForm');
const sendReport = document.getElementById('sendReport');
const reportCancel = document.getElementById('reportCancel');
const reportCategory = document.getElementById('reportCategory');
const reportDescription = document.getElementById('reportDescription');
const reportDescriptionCount = document.getElementById('reportDescriptionCount');
const reportScreenshot = document.getElementById('reportScreenshot');
const reportFileName = document.getElementById('reportFileName');
const reportImagePreviewWrap = document.getElementById('reportImagePreviewWrap');
const reportImagePreview = document.getElementById('reportImagePreview');
const reportRemoveImage = document.getElementById('reportRemoveImage');

let selectedReportFile = null;

const setReportStatus = (message, type = '') => {
  const statusEl = document.getElementById('reportStatus');
  if (!statusEl) return;
  statusEl.textContent = message || '';
  statusEl.classList.remove('success', 'error', 'loading');
  if (type) statusEl.classList.add(type);
};

function updateReportTargetInfo() {
  const urlEl = document.getElementById('reportCurrentUrl');
  const domainEl = document.getElementById('reportCurrentDomain');
  if (urlEl) urlEl.textContent = currentTabUrl || 'Không lấy được URL hiện tại';
  if (domainEl) domainEl.textContent = currentDomain || 'Không lấy được tên miền';
}

const resetReportImage = () => {
  selectedReportFile = null;
  if (reportScreenshot) reportScreenshot.value = '';
  if (reportFileName) reportFileName.textContent = 'PNG, JPG, JPEG, WEBP · tối đa 5MB';
  if (reportImagePreview) reportImagePreview.removeAttribute('src');
  if (reportImagePreviewWrap) reportImagePreviewWrap.hidden = true;
};

const resetReportForm = () => {
  if (reportCategory) reportCategory.value = '';
  if (reportDescription) reportDescription.value = '';
  if (reportDescriptionCount) reportDescriptionCount.textContent = '0/1000 ký tự';
  resetReportImage();
  setReportStatus('');
};

const closeReportPanel = () => {
  if (!reportForm) return;
  reportForm.hidden = true;
  reportToggle && reportToggle.setAttribute('aria-expanded', 'false');
  setReportStatus('');
};

const getBrowserName = () => {
  const ua = navigator.userAgent || '';
  if (/Edg\//.test(ua)) return 'Microsoft Edge';
  if (/OPR\//.test(ua) || /Opera\//.test(ua)) return 'Opera';
  if (/Firefox\//.test(ua)) return 'Firefox';
  if (/Chrome\//.test(ua) || /Chromium\//.test(ua)) return 'Chrome';
  if (/Safari\//.test(ua)) return 'Safari';
  return 'Không xác định';
};

let _cachedGpsLocation = null;
let _gpsLocationError = null;

const getLocationFromGPS = () => {
  return new Promise((resolve) => {
    if (_cachedGpsLocation) { resolve(_cachedGpsLocation); return; }
    if (!navigator.geolocation) { resolve(null); return; }
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        _cachedGpsLocation = { latitude: pos.coords.latitude, longitude: pos.coords.longitude, accuracy: pos.coords.accuracy, source: 'gps' };
        resolve(_cachedGpsLocation);
      },
      () => { resolve(null); },
      { enableHighAccuracy: true, timeout: 8000, maximumAge: 300000 }
    );
  });
};

const validateReportForm = () => {
  let parsedUrl = null;
  try { parsedUrl = new URL(currentTabUrl); } catch (_) {}
  if (!parsedUrl || !['http:', 'https:'].includes(parsedUrl.protocol)) return 'URL không hợp lệ.';
  if (!reportCategory || !reportCategory.value) return 'Vui lòng chọn loại báo cáo.';
  if (reportCategory.value === 'other') {
    const otherVal = (document.getElementById('reportCategoryOther')?.value || '').trim();
    if (otherVal.length < 3) return 'Vui lòng nhập lý do cụ thể (tối thiểu 3 ký tự).';
  }
  const description = (reportDescription && reportDescription.value || '').trim();
  if (description.length < 20) return 'Mô tả phải có tối thiểu 20 ký tự.';
  if (description.length > 1000) return 'Mô tả không được vượt quá 1000 ký tự.';
  if (selectedReportFile && selectedReportFile.size > REPORT_MAX_FILE_SIZE) return 'File vượt quá 5MB.';
  if (selectedReportFile && !REPORT_ALLOWED_TYPES.includes(selectedReportFile.type)) return 'Định dạng ảnh không được hỗ trợ.';
  return '';
};

const buildReportFormData = async () => {
  const manifest = chrome.runtime.getManifest ? chrome.runtime.getManifest() : {};
  const formData = new FormData();
  formData.append('url', currentTabUrl);
  formData.append('domain', currentDomain);
  formData.append('pageTitle', currentPageTitle || document.title || '');
  formData.append('timestamp', new Date().toISOString());
  formData.append('extensionVersion', manifest.version || '');
  formData.append('browserName', getBrowserName());
  formData.append('browserLanguage', navigator.language || '');
  formData.append('userAgent', navigator.userAgent || '');
  formData.append('deviceId', await getReportDeviceId());
  let category = reportCategory.value;
  if (category === 'other') {
    const otherVal = (document.getElementById('reportCategoryOther')?.value || '').trim();
    category = `other: ${otherVal}`;
  }
  formData.append('category', category);
  formData.append('description', (reportDescription.value || '').trim());
  const gpsLoc = await getLocationFromGPS();
  if (gpsLoc) {
    formData.append('latitude', String(gpsLoc.latitude));
    formData.append('longitude', String(gpsLoc.longitude));
    formData.append('gpsAccuracy', String(gpsLoc.accuracy));
    formData.append('locationSource', 'gps');
  } else {
    formData.append('locationSource', 'ip-fallback');
  }
  if (selectedReportFile) formData.append('screenshot', selectedReportFile, selectedReportFile.name);
  return formData;
};

if (reportToggle && reportForm) {
  reportToggle.setAttribute('aria-expanded', 'false');
  reportToggle.addEventListener('click', () => {
    reportForm.hidden = !reportForm.hidden;
    reportToggle.setAttribute('aria-expanded', String(!reportForm.hidden));
    updateReportTargetInfo();
    setReportStatus('');
    if (navigator.geolocation) { navigator.geolocation.getCurrentPosition(()=>{}, ()=>{}, {timeout: 5000}); }
  });
}

document.querySelectorAll('input[name="reportType"]').forEach(radio => {
  radio.addEventListener('change', (e) => {
    const isMalicious = e.target.value === 'malicious';
    const malGroup = document.getElementById('maliciousCategories');
    const safeGroup = document.getElementById('safeCategories');
    const categorySelect = document.getElementById('reportCategory');
    if (malGroup && safeGroup && categorySelect) {
      malGroup.hidden = !isMalicious;
      safeGroup.hidden = isMalicious;
      categorySelect.value = '';
      document.getElementById('otherCategoryWrap').hidden = true;
      const descArea = document.getElementById('reportDescription');
      const hintDiv = document.getElementById('reportHint');
      if (isMalicious) {
        descArea.placeholder = "Lý do bạn báo cáo website này độc hại...";
        hintDiv.textContent = "Ví dụ: Website giả mạo ngân hàng, yêu cầu nhập OTP, mạo danh Shopee.";
      } else {
        descArea.placeholder = "Lý do bạn cho rằng website này an toàn...";
        hintDiv.textContent = "Ví dụ: Đây là website chính thức của một tổ chức giáo dục hoặc doanh nghiệp uy tín.";
      }
    }
  });
});

document.getElementById('reportCategory').addEventListener('change', (e) => {
  const otherWrap = document.getElementById('otherCategoryWrap');
  if (otherWrap) {
    otherWrap.hidden = e.target.value !== 'other';
    if (e.target.value === 'other') document.getElementById('reportCategoryOther').focus();
  }
});

if (reportDescription && reportDescriptionCount) {
  reportDescription.addEventListener('input', () => {
    const len = (reportDescription.value || '').length;
    reportDescriptionCount.textContent = `${len}/1000 ký tự`;
  });
}

if (reportScreenshot) {
  reportScreenshot.addEventListener('change', () => {
    setReportStatus('');
    const file = reportScreenshot.files && reportScreenshot.files[0];
    if (!file) { resetReportImage(); return; }
    if (!REPORT_ALLOWED_TYPES.includes(file.type)) { resetReportImage(); setReportStatus('Định dạng ảnh không được hỗ trợ.', 'error'); return; }
    if (file.size > REPORT_MAX_FILE_SIZE) { resetReportImage(); setReportStatus('File vượt quá 5MB.', 'error'); return; }
    selectedReportFile = file;
    if (reportFileName) reportFileName.textContent = file.name;
    const reader = new FileReader();
    reader.onload = () => {
      if (reportImagePreview) reportImagePreview.src = reader.result;
      if (reportImagePreviewWrap) reportImagePreviewWrap.hidden = false;
    };
    reader.readAsDataURL(file);
  });
}

if (reportRemoveImage) reportRemoveImage.addEventListener('click', resetReportImage);
if (reportCancel) { reportCancel.addEventListener('click', () => { resetReportForm(); closeReportPanel(); }); }

if (sendReport) {
  sendReport.addEventListener('click', async () => {
    if (await hasReportedThisDomain(currentDomain)) { setReportStatus('Bạn đã gửi báo cáo cho trang web này rồi.', 'error'); return; }
    const error = validateReportForm();
    if (error) { setReportStatus(error, 'error'); return; }
    setReportStatus('Đang gửi báo cáo...', 'loading');
    sendReport.disabled = true;
    try {
      const response = await fetch(REPORT_API_URL, { method: 'POST', body: await buildReportFormData() });
      if (!response.ok) throw new Error('Network response was not ok');
      await markAsReported(currentDomain);
      resetReportForm();
      setReportStatus('Báo cáo thành công.', 'success');
      setTimeout(closeReportPanel, 1600);
    } catch (_) {
      setReportStatus('Không thể gửi báo cáo.', 'error');
    } finally {
      sendReport.disabled = false;
    }
  });
}

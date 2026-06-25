/* global chrome */
import { collect, netState, permState } from '../features.js';

const injectPageHooksResource = () => {
  try {
    if (document.getElementById('__antiscam_page_hooks')) return;
    const s = document.createElement('script');
    s.id = '__antiscam_page_hooks';
    s.src = chrome.runtime.getURL('scripts/content/page_hooks.js');
    s.async = false;
    (document.documentElement || document.head || document).appendChild(s);
    s.onload = () => { try { s.remove(); } catch (_) {} };
  } catch (_) {}
};

window.addEventListener('__antiscam_net', (e) => {
  try {
    const currentOnlyDomain = window.location.hostname.replace(/^www\./, '');
    const d = e.detail || {};
    // Note: features.js logic handles most of this now but this hook updates netState which collect() reads
    if (d.host && d.host !== currentOnlyDomain) {
      netState.externalHosts.add(d.host);
      if (d.upload) {
        netState.uploadToExternal = true;
        netState.externalPostHosts.add(d.host);
      }
    }
  } catch (_) {}
});

window.addEventListener('__antiscam_perm', (e) => {
  try { if (e.detail && e.detail.name) { permState.requests.add(String(e.detail.name)); scheduleRescan(250); } } catch (_) {}
});

window.addEventListener('__antiscam_behavior', (e) => {
  try {
    const d = e.detail || {};
    scheduleRescan(250);
  } catch (_) {}
});

const injectNetworkHook = () => {
  try {
    if (document.getElementById('__antiscam_net_hook')) return;
    const s = document.createElement('script');
    s.id = '__antiscam_net_hook';
    s.src = chrome.runtime.getURL('scripts/content/network_hooks.js');
    s.async = false;
    (document.documentElement || document.head || document).appendChild(s);
    s.onload = () => { try { s.remove(); } catch (_) {} };
  } catch (_) { }
};

let _rescanTimer = null;
const scheduleRescan = (ms = 1000) => {
  if (_rescanTimer) clearTimeout(_rescanTimer);
  _rescanTimer = setTimeout(() => {
    const { result, dom } = collect();
    try { chrome.runtime.sendMessage({ type: 'ANALYSIS_UPDATE', result, dom }).catch(() => {}); } catch (_) {}
  }, ms);
};

const observer = new MutationObserver((mutations) => {
  let heavy = false;
  for (const m of mutations) {
    if (m.addedNodes.length > 0) {
      for (const node of m.addedNodes) {
        if (node.nodeType === 1 && ['FORM', 'SCRIPT', 'IFRAME', 'A', 'INPUT'].includes(node.nodeName)) {
          heavy = true; break;
        }
      }
    }
    if (heavy) break;
  }
  if (heavy) scheduleRescan(800);
});
observer.observe(document.documentElement, { childList: true, subtree: true });

const initScan = () => {
  const { result, dom } = collect();
  
  // Kiểm tra xem trang có đang chạy trong chế độ quét ẩn của Offscreen hay không
  // Dựa vào query string __antiscam_scan=1 hoặc URL đặc biệt nếu DNR strip params.
  // Nhưng vì ta dùng tabId=-1 trong DNR, nếu có __antiscam_scan trong location href, chắc chắn là offscreen.
  const isOffscreen = window.location.href.includes('__antiscam_scan=1') || window.name === 'antiscam-offscreen-scan-frame';

  if (isOffscreen) {
    // Nếu là offscreen, chúng ta chỉ gửi kết quả một lần về background rồi bỏ qua các logic Live Scan
    try {
      chrome.runtime.sendMessage({ 
        type: 'OFFSCREEN_DEEP_SCAN_RESULT', 
        url: window.location.href.replace(/([?&])__antiscam_scan=1&?/, '$1').replace(/\?$/, ''), 
        signals: { result, dom }, 
        status: 'OK' 
      }).catch(() => {});
    } catch (_) {}
    return;
  }

  try { chrome.runtime.sendMessage({ type: 'ANALYSIS_RESULT', result, dom }).catch(() => {}); } catch (_) {}
  injectPageHooksResource();
  injectNetworkHook();
};

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initScan);
} else {
  initScan();
}

window.addEventListener('popstate', () => scheduleRescan(500));
window.addEventListener('hashchange', () => scheduleRescan(500));

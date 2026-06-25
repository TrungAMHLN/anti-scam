// Runs in the page's MAIN world — network monitoring hooks
// Tách riêng từ features.js để tránh vi phạm CSP khi inject inline script
(function () {
  if (window.__antiscamNetHookInstalled) return;
  window.__antiscamNetHookInstalled = true;

  var host = location.hostname.replace(/^www\./, '');

  // Gửi network event về content script
  var send = function (host2, upload) {
    try {
      window.dispatchEvent(new CustomEvent('__antiscam_net', {
        detail: { host: host2, upload: upload }
      }));
    } catch (e) {}
  };

  // Gửi behavioral event về content script (các hook mới)
  var sendBehavior = function (type, detail) {
    try {
      window.dispatchEvent(new CustomEvent('__antiscam_behavior', {
        detail: { type: type, detail: detail || {} }
      }));
    } catch (e) {}
  };

  // ── fetch hook ──
  try {
    var _fetch = window.fetch;
    if (_fetch && !_fetch.__antiscamWrapped) {
      window.fetch = function (input, opts) {
        try {
          var u = typeof input === 'string' ? input : (input && input.url);
          if (u) {
            var h = new URL(u, location.href).hostname.replace(/^www\./, '');
            if (h && h !== host) {
              var up = opts && opts.method && /post|put|patch/i.test(opts.method);
              if (opts && opts.body) up = true;
              send(h, !!up);
            }
          }
        } catch (e) {}
        return _fetch.apply(this, arguments);
      };
      window.fetch.__antiscamWrapped = true;
    }
  } catch (e) {}

  // ── XMLHttpRequest hook ──
  try {
    var _open = XMLHttpRequest.prototype.open;
    var _send = XMLHttpRequest.prototype.send;
    if (!_open.__antiscamWrapped) {
      XMLHttpRequest.prototype.open = function (m, u) {
        this.__ascm_m = m;
        this.__ascm_url = u;
        return _open.apply(this, arguments);
      };
      XMLHttpRequest.prototype.open.__antiscamWrapped = true;
    }
    if (!_send.__antiscamWrapped) {
      XMLHttpRequest.prototype.send = function (body) {
        try {
          if (this.__ascm_url) {
            var h = new URL(this.__ascm_url, location.href).hostname.replace(/^www\./, '');
            if (h && h !== host) send(h, !!body || /post|put|patch/i.test(this.__ascm_m || ''));
          }
        } catch (e) {}
        return _send.apply(this, arguments);
      };
      XMLHttpRequest.prototype.send.__antiscamWrapped = true;
    }
  } catch (e) {}

  // ── sendBeacon hook ──
  try {
    if (navigator.sendBeacon && !navigator.sendBeacon.__antiscamWrapped) {
      var _beacon = navigator.sendBeacon.bind(navigator);
      navigator.sendBeacon = function (url) {
        try {
          var h = new URL(url, location.href).hostname.replace(/^www\./, '');
          if (h && h !== host) send(h, true);
        } catch (e) {}
        return _beacon.apply(navigator, arguments);
      };
      navigator.sendBeacon.__antiscamWrapped = true;
    }
  } catch (e) {}

  // ── WebSocket hook ──
  try {
    var _WS = window.WebSocket;
    if (_WS && !_WS.__antiscamWrapped) {
      var OrigWS = _WS;
      var WrappedWS = function (url, protocols) {
        try {
          var h = new URL(url, location.href).hostname.replace(/^www\./, '');
          if (h && h !== host) send(h, false);
        } catch (e) {}
        return protocols !== undefined
          ? new OrigWS(url, protocols)
          : new OrigWS(url);
      };
      WrappedWS.prototype = OrigWS.prototype;
      WrappedWS.__antiscamWrapped = true;
      try { Object.setPrototypeOf(WrappedWS, OrigWS); } catch (_) {}
      if (OrigWS.CONNECTING != null) WrappedWS.CONNECTING = OrigWS.CONNECTING;
      if (OrigWS.OPEN != null) WrappedWS.OPEN = OrigWS.OPEN;
      if (OrigWS.CLOSING != null) WrappedWS.CLOSING = OrigWS.CLOSING;
      if (OrigWS.CLOSED != null) WrappedWS.CLOSED = OrigWS.CLOSED;
      window.WebSocket = WrappedWS;
    }
  } catch (e) {}

  // ── RTCPeerConnection hook — phát hiện WebRTC IP leak ──
  try {
    var _RTC = window.RTCPeerConnection || window.webkitRTCPeerConnection;
    if (_RTC && !_RTC.__antiscamWrapped) {
      var OrigRTC = _RTC;
      var WrappedRTC = function (config, constraints) {
        sendBehavior('rtc-peer-connection', { hasStun: !!(config && config.iceServers && config.iceServers.length) });
        return config !== undefined
          ? new OrigRTC(config, constraints)
          : new OrigRTC();
      };
      WrappedRTC.prototype = OrigRTC.prototype;
      WrappedRTC.__antiscamWrapped = true;
      try { Object.setPrototypeOf(WrappedRTC, OrigRTC); } catch (_) {}
      window.RTCPeerConnection = WrappedRTC;
      if (window.webkitRTCPeerConnection) window.webkitRTCPeerConnection = WrappedRTC;
    }
  } catch (e) {}

  // ── window.open hook — phát hiện popup spam ──
  try {
    var _openWin = window.open;
    if (_openWin && !_openWin.__antiscamWrapped) {
      window.open = function (url) {
        try {
          var target = url ? String(url) : '';
          var h = '';
          if (target && /^https?:\/\//i.test(target)) {
            h = new URL(target, location.href).hostname.replace(/^www\./, '');
          }
          sendBehavior('window-open', { url: target.slice(0, 200), external: !!(h && h !== host) });
          if (h && h !== host) send(h, false);
        } catch (e) {}
        return _openWin.apply(window, arguments);
      };
      window.open.__antiscamWrapped = true;
    }
  } catch (e) {}

  // ── postMessage hook — phát hiện giao tiếp đáng ngờ cross-origin ──
  try {
    var _postMsg = window.postMessage;
    if (_postMsg && !_postMsg.__antiscamWrapped) {
      window.postMessage = function (message, targetOrigin) {
        try {
          var extOrigin = targetOrigin && targetOrigin !== '*' && targetOrigin !== location.origin;
          if (extOrigin) {
            sendBehavior('post-message', { targetOrigin: String(targetOrigin).slice(0, 100) });
          }
        } catch (e) {}
        return _postMsg.apply(window, arguments);
      };
      window.postMessage.__antiscamWrapped = true;
    }
  } catch (e) {}

  // ── document.createElement hook — phát hiện dynamic script/iframe injection ──
  try {
    var _createElement = document.createElement.bind(document);
    if (!document.createElement.__antiscamWrapped) {
      document.createElement = function (tagName) {
        try {
          var tag = String(tagName || '').toLowerCase();
          if (tag === 'script') {
            sendBehavior('dynamic-script-create', {});
          } else if (tag === 'iframe') {
            sendBehavior('dynamic-iframe-create', {});
          }
        } catch (e) {}
        return _createElement.apply(document, arguments);
      };
      document.createElement.__antiscamWrapped = true;
    }
  } catch (e) {}

  // ── localStorage / sessionStorage hook — theo dõi key nhạy cảm ──
  var SENSITIVE_STORAGE_KEYS = ['password', 'passwd', 'token', 'access_token', 'refresh_token',
    'otp', 'pin', 'secret', 'private_key', 'cvv', 'card', 'credit'];
  var isSensitiveKey = function (key) {
    if (!key) return false;
    var k = String(key).toLowerCase();
    return SENSITIVE_STORAGE_KEYS.some(function (s) { return k.indexOf(s) !== -1; });
  };
  var wrapStorage = function (storageObj, storageName) {
    try {
      var _setItem = storageObj.setItem.bind(storageObj);
      if (!storageObj.setItem.__antiscamWrapped) {
        storageObj.setItem = function (key, value) {
          try {
            if (isSensitiveKey(key)) {
              sendBehavior('sensitive-storage', { storage: storageName, key: String(key).slice(0, 50) });
            }
          } catch (e) {}
          return _setItem.apply(storageObj, arguments);
        };
        storageObj.setItem.__antiscamWrapped = true;
      }
    } catch (e) {}
  };
  try { wrapStorage(localStorage, 'localStorage'); } catch (e) {}
  try { wrapStorage(sessionStorage, 'sessionStorage'); } catch (e) {}

  // ── clipboard.readText hook — phát hiện đánh cắp clipboard ──
  try {
    if (navigator.clipboard && navigator.clipboard.readText && !navigator.clipboard.readText.__antiscamWrapped) {
      var _readText = navigator.clipboard.readText.bind(navigator.clipboard);
      navigator.clipboard.readText = function () {
        sendBehavior('clipboard-read', {});
        return _readText.apply(navigator.clipboard, arguments);
      };
      navigator.clipboard.readText.__antiscamWrapped = true;
    }
  } catch (e) {}

})();

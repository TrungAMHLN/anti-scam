(() => {
  // src/features.js
  var ipRe = /^(\d{1,3}\.){3}\d{1,3}$/;
  var _TRUSTED = [
    "googleapis.com",
    "google.com",
    "gstatic.com",
    "google-analytics.com",
    "googletagmanager.com",
    "youtube.com",
    "ytimg.com",
    "doubleclick.net",
    "cloudflare.com",
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "jsdelivr.net",
    "unpkg.com",
    "bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com",
    "netdna.bootstrapcdn.com",
    "stackpath.bootstrapcdn.com",
    "fontawesome.com",
    "use.fontawesome.com",
    "kit.fontawesome.com",
    "ajax.aspnetcdn.com",
    "msecnd.net",
    "code.jquery.com",
    "facebook.net",
    "fbcdn.net",
    "twitter.com",
    "twimg.com",
    "cloudfront.net",
    "akamai.net",
    "akamaized.net",
    "fastly.net",
    "stripe.com",
    "js.stripe.com",
    "mongodb.com",
    "cloud.mongodb.com",
    "tailwindcss.com",
    "polyfill.io",
    "githubassets.com",
    "googlevideo.com"
  ];
  var _ORG_ECOSYSTEMS = [
    ["github.com", "githubusercontent.com", "githubassets.com", "github.io"],
    ["google.com", "gstatic.com", "googleusercontent.com", "googleapis.com", "googletagmanager.com", "google-analytics.com", "youtube.com", "ytimg.com", "googlevideo.com"],
    ["microsoft.com", "live.com", "office.com", "office365.com", "microsoftonline.com", "azure.com", "azureedge.net", "bing.com", "msn.com", "outlook.com"],
    ["cloudflare.com", "cdnjs.cloudflare.com", "cloudflareinsights.com", "challenges.cloudflare.com"],
    ["gitlab.com", "gitlab-static.net", "gitlab.io"],
    ["openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"],
    ["facebook.com", "fbcdn.net", "facebook.net", "instagram.com", "whatsapp.com", "meta.com"]
  ];
  var _registrable = (host) => {
    const h = (host || "").toLowerCase().replace(/^www\./, "");
    const parts = h.split(".").filter(Boolean);
    if (parts.length <= 2) return h;
    const last2 = parts.slice(-2).join(".");
    const last3 = parts.slice(-3).join(".");
    if (/^(com|net|org|gov|edu|ac|biz|info)\.vn$/.test(last2) && parts.length >= 3) return last3;
    return last2;
  };
  var _sameOrgHost = (a, b) => {
    const ra = _registrable(a), rb = _registrable(b);
    if (!ra || !rb) return false;
    if (ra === rb) return true;
    return _ORG_ECOSYSTEMS.some((group) => group.includes(ra) && group.includes(rb));
  };
  var _isTrustedHost = (host) => {
    if (!host) return false;
    const h = host.toLowerCase().replace(/^www\./, "");
    if (_TRUSTED.includes(h)) return true;
    return _TRUSTED.some((t) => h.endsWith("." + t));
  };
  var _hostOf = (raw) => {
    if (!raw || typeof raw !== "string") return null;
    const s = raw.trim();
    const currentOnlyDomain = typeof window !== "undefined" ? window.location.hostname.replace(/^www\./, "") : "";
    if (s.startsWith("//")) {
      try {
        return new URL("https:" + s).hostname;
      } catch (_) {
        return null;
      }
    }
    if (s.startsWith("http://") || s.startsWith("https://")) {
      try {
        return new URL(s).hostname;
      } catch (_) {
        return null;
      }
    }
    if (s.startsWith("/") || s === "") return currentOnlyDomain;
    if (s.startsWith("data:") || s.startsWith("blob:") || s.startsWith("javascript:")) return null;
    return null;
  };
  var _hostEndsWith = (a, b) => !(!a || !b) && (a === b || a.endsWith("." + b) || b.endsWith("." + a));
  var _normalizeText = (str) => {
    try {
      return (str || "").toString().normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase();
    } catch (_) {
      return (str || "").toString().toLowerCase();
    }
  };
  var VN_SCAM_CONTENT_PATTERNS = [
    { re: /loi\s*nhuan\s*\d+\s*%|\d+\s*%\s*(moi\s*ngay|\/\s*ngay|ngay)/, label: "l\u1EE3i nhu\u1EADn cao b\u1EA5t th\u01B0\u1EDDng" },
    { re: /dau\s*tu|tien\s*dien\s*tu|crypto|coin|forex|quyen\s*chon\s*nhi\s*phan/, label: "\u0111\u1EA7u t\u01B0/ti\u1EC1n \u0111i\u1EC7n t\u1EED r\u1EE7i ro" },
    { re: /da\s*cap|he\s*thong\s*tuyen\s*duoi|mo\s*hinh\s*kim\s*tu\s*thap/, label: "\u0111a c\u1EA5p" },
    { re: /vay\s*nong|vay\s*nhanh|giai\s*ngan\s*trong\s*ngay|khong\s*can\s*the\s*chap/, label: "vay n\xF3ng" },
    { re: /viec\s*nhe\s*luong\s*cao|kiem\s*tien\s*online|khong\s*can\s*von|lam\s*nhiem\s*vu/, label: "vi\u1EC7c nh\u1EB9 l\u01B0\u01A1ng cao/ki\u1EBFm ti\u1EC1n online" },
    { re: /nhan\s*thuong|trung\s*thuong|nhan\s*qua|hoa\s*hong\s*khung|nap\s*tien\s*nhan\s*thuong/, label: "nh\u1EADn th\u01B0\u1EDFng/hoa h\u1ED3ng b\u1EA5t th\u01B0\u1EDDng" }
  ];
  var _stickyState = {
    contentRich: false,
    sensitiveForm: false,
    formHijack: false,
    obfuscatedScript: false,
    keylogger: false,
    clipboardHijack: false,
    suspiciousExternalScript: false,
    downloadFile: false,
    networkUploadToExternal: false,
    hiddenIframe: false,
    rtcPeerConnection: false,
    windowOpenCount: 0,
    suspiciousPostMessage: false,
    dynamicScriptInjection: false,
    dynamicIframeInjection: false,
    sensitiveLSKeys: [],
    clipboardRead: false
  };
  var BRAND_KEYS = [
    ["vietcombank", "Vietcombank"],
    ["bidv", "BIDV"],
    ["mbbank", "MB"],
    ["techcombank", "Techcombank"],
    ["tpbank", "TPBank"],
    ["agribank", "Agribank"],
    ["vietinbank", "VietinBank"],
    ["vpbank", "VPBank"],
    ["sacombank", "Sacombank"],
    ["momo", "MoMo"],
    ["zalopay", "ZaloPay"],
    ["zalo", "Zalo"],
    ["acb", "ACB"],
    ["tiki", "Tiki"],
    ["viettel", "Viettel"],
    ["vnpay", "VNPay"],
    ["fpt", "FPT"],
    ["vingroup", "VinGroup"],
    ["vinhomes", "Vinhomes"],
    ["vinfast", "VinFast"],
    ["google", "Google"],
    ["microsoft", "Microsoft"],
    ["facebook", "Facebook"],
    ["apple", "Apple"],
    ["paypal", "PayPal"],
    ["amazon", "Amazon"],
    ["netflix", "Netflix"],
    ["openai", "OpenAI"],
    ["chatgpt", "ChatGPT"],
    ["telegram", "Telegram"],
    ["github", "GitHub"],
    ["shopee", "Shopee"],
    ["lazada", "Lazada"]
  ];
  var BRAND_OFFICIAL = {
    "vietcombank": ["vietcombank.com.vn"],
    "bidv": ["bidv.com.vn"],
    "mbbank": ["mbbank.com.vn"],
    "techcombank": ["techcombank.com.vn"],
    "tpbank": ["tpb.vn", "tpbank.vn"],
    "agribank": ["agribank.com.vn"],
    "vietinbank": ["vietinbank.vn"],
    "vpbank": ["vpbank.vn"],
    "sacombank": ["sacombank.com"],
    "momo": ["momo.vn"],
    "zalopay": ["zalopay.vn"],
    "zalo": ["zalo.me"],
    "acb": ["acb.com.vn"],
    "tiki": ["tiki.vn"],
    "viettel": ["viettel.com.vn", "viettel.vn"],
    "vnpay": ["vnpay.vn"],
    "fpt": ["fpt.com.vn", "fpt.vn"],
    "vingroup": ["vingroup.net"],
    "vinhomes": ["vinhomes.vn"],
    "vinfast": ["vinfastauto.com", "vinfast.vn"],
    "google": ["google.com"],
    "microsoft": ["microsoft.com"],
    "facebook": ["facebook.com"],
    "apple": ["apple.com"],
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com"],
    "netflix": ["netflix.com"],
    "openai": ["openai.com", "chatgpt.com"],
    "chatgpt": ["chatgpt.com", "openai.com"],
    "telegram": ["telegram.org"],
    "github": ["github.com"],
    "shopee": ["shopee.vn"],
    "lazada": ["lazada.vn"],
    "mb": ["mbbank.com.vn"]
  };
  var detectBrandSurfaces = () => {
    if (typeof document === "undefined") return { brandInContent: false, brandSurfaces: 0, matchedBrand: null };
    const title = (document.title || "").toLowerCase();
    const currentOnlyDomain = window.location.hostname.replace(/^www\./, "");
    let h1 = "", h2 = "";
    try {
      const h1el = document.querySelector("h1");
      if (h1el) h1 = (h1el.textContent || "").toLowerCase();
      const h2els = document.querySelectorAll("h2");
      if (h2els.length) h2 = Array.from(h2els).map((e) => e.textContent || "").join(" ").toLowerCase().slice(0, 2e3);
    } catch (_) {
    }
    let meta = "";
    try {
      const m = document.querySelector('meta[name="description"], meta[property="og:title"], meta[property="og:description"]');
      if (m) meta = (m.getAttribute("content") || "").toLowerCase();
    } catch (_) {
    }
    let faviconHost = null;
    try {
      const fl = document.querySelector('link[rel~="icon"], link[rel="shortcut icon"]');
      if (fl) faviconHost = _hostOf(fl.getAttribute("href"));
    } catch (_) {
    }
    let logoText = "";
    try {
      const logoEls = document.querySelectorAll('img[alt], img[src], [class*="logo"], [id*="logo"]');
      logoText = Array.from(logoEls).slice(0, 40).map((el) => [
        el.getAttribute("alt"),
        el.getAttribute("src"),
        el.getAttribute("class"),
        el.getAttribute("id"),
        el.getAttribute("aria-label")
      ].filter(Boolean).join(" ")).join(" ").toLowerCase().slice(0, 4e3);
    } catch (_) {
    }
    const surfaces = { title, h1, h2, meta, logoText };
    const brandHits = {};
    for (const [key, name] of BRAND_KEYS) {
      if (key.length < 4 && !["fpt", "acb"].includes(key)) continue;
      const official = BRAND_OFFICIAL[key] || [];
      const isOfficial = official.some((d) => currentOnlyDomain === d || currentOnlyDomain.endsWith("." + d));
      if (isOfficial) continue;
      let count = 0;
      for (const surf of Object.values(surfaces)) {
        if (surf && surf.includes(key)) count++;
      }
      if (count > 0) brandHits[key] = { name, count };
    }
    const entries = Object.values(brandHits);
    if (entries.length === 0) return { brandInContent: false, brandSurfaces: 0, matchedBrand: null };
    const best = entries.sort((a, b) => b.count - a.count)[0];
    return { brandInContent: true, brandSurfaces: best.count, matchedBrand: best.name };
  };
  var netState = { externalHosts: /* @__PURE__ */ new Set(), uploadToExternal: false, externalPostHosts: /* @__PURE__ */ new Set() };
  var permState = { requests: /* @__PURE__ */ new Set() };
  var collect = () => {
    if (typeof window === "undefined") return { result: {}, dom: { scanned: false } };
    const currentUrl = window.location.href;
    const currentDomain = window.location.hostname;
    const currentOnlyDomain = currentDomain.replace(/^www\./, "");
    const result = {};
    const dom = { scanned: true };
    result["IP Address"] = ipRe.test(currentOnlyDomain) ? "1" : "-1";
    result["URL Length"] = currentUrl.length > 100 ? "0" : "-1";
    result["Tiny URL"] = currentOnlyDomain.length < 5 && !ipRe.test(currentOnlyDomain) ? "0" : "-1";
    result["@ Symbol"] = currentUrl.includes("@") ? "0" : "-1";
    result["Redirecting using //"] = currentUrl.lastIndexOf("//") > 7 && /\/\/[^/]+@/.test(currentUrl) ? "0" : "-1";
    result["(-) Prefix/Suffix in domain"] = (currentOnlyDomain.match(/-/g) || []).length >= 3 ? "0" : "-1";
    result["No. of Sub Domains"] = (currentOnlyDomain.match(/\./g) || []).length >= 4 ? "0" : "-1";
    result["HTTPS"] = window.location.protocol === "https:" ? "-1" : "0";
    result["HTTPS in URL's domain part"] = /https/i.test(currentOnlyDomain) ? "0" : "-1";
    result["Favicon"] = "-1";
    result["Port"] = "-1";
    const port = window.location.port;
    if (port && !["80", "443", "8080", "8000", "8008", "3000", "3001", "4200", "5000", "5173", "5500", "8081", "8443", "9000", "9001", "1234", "2020", "4000"].includes(port)) result["Port"] = "0";
    const sTags = document.getElementsByTagName("script");
    const lTags = document.getElementsByTagName("link");
    const imgTags = document.getElementsByTagName("img");
    const aTags = document.querySelectorAll("a[href]");
    const forms = document.getElementsByTagName("form");
    const iframes = document.getElementsByTagName("iframe");
    let extCount = 0, totalCount = 0;
    const externalScriptHosts = [];
    const countExternal = (getSrc) => {
      for (const el of getSrc) {
        const src = el.getAttribute("src") || el.getAttribute("href");
        if (!src) continue;
        totalCount++;
        const h = _hostOf(src);
        if (h && h !== currentOnlyDomain && !_hostEndsWith(h, currentOnlyDomain) && !_sameOrgHost(h, currentOnlyDomain) && !_isTrustedHost(h)) {
          extCount++;
          externalScriptHosts.push(h);
        }
      }
    };
    countExternal(Array.from(sTags));
    countExternal(Array.from(lTags));
    let outPct = totalCount === 0 ? 0 : extCount / totalCount * 100;
    result["Script & Link"] = outPct > 80 ? "1" : outPct > 50 ? "0" : "-1";
    let imgExt = 0, imgTotal = 0;
    for (const img of imgTags) {
      const src = img.getAttribute("src");
      if (!src) continue;
      imgTotal++;
      const h = _hostOf(src);
      if (h && h !== currentOnlyDomain && !_hostEndsWith(h, currentOnlyDomain) && !_sameOrgHost(h, currentOnlyDomain) && !_isTrustedHost(h)) imgExt++;
    }
    let imgPct = imgTotal === 0 ? 0 : imgExt / imgTotal * 100;
    result["Request URL"] = imgPct > 60 ? "1" : imgPct > 30 ? "0" : "-1";
    let aExt = 0, aTotal = 0;
    const pageLinks = [];
    const externalLinkHosts = /* @__PURE__ */ new Set();
    const deceptiveLinks = [];
    for (const a of aTags) {
      const href = a.getAttribute("href");
      if (!href) continue;
      let abs = null;
      try {
        abs = new URL(href, window.location.href).href;
      } catch (_) {
      }
      if (abs && /^https?:\/\//i.test(abs) && pageLinks.length < 160) pageLinks.push(abs);
      aTotal++;
      const h = _hostOf(href);
      if (h && h !== currentOnlyDomain && !_hostEndsWith(h, currentOnlyDomain) && !_sameOrgHost(h, currentOnlyDomain) && !_isTrustedHost(h)) {
        aExt++;
        externalLinkHosts.add(h);
      }
      try {
        const text = (a.textContent || "").trim().toLowerCase();
        const m = text.match(/(?:https?:\/\/)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)/i);
        if (m && abs) {
          const shownHost = m[1].replace(/^www\./, "");
          const hrefHost = new URL(abs).hostname.replace(/^www\./, "");
          if (shownHost && hrefHost && shownHost !== hrefHost && !_hostEndsWith(shownHost, hrefHost)) {
            deceptiveLinks.push({ text: shownHost, href: hrefHost });
          }
        }
      } catch (_) {
      }
    }
    let aPct = aTotal === 0 ? 0 : aExt / aTotal * 100;
    result["Anchor"] = aPct > 75 ? "1" : aPct > 40 ? "0" : "-1";
    dom.pageLinks = pageLinks;
    dom.externalLinkHosts = Array.from(externalLinkHosts).slice(0, 40);
    dom.deceptiveLinks = deceptiveLinks.slice(0, 10);
    dom.deceptiveLinkCount = deceptiveLinks.length;
    if (!_stickyState.contentRich) {
      let bodyTextLen = 0;
      try {
        bodyTextLen = (document.body && document.body.innerText || "").trim().length;
      } catch (_) {
      }
      if (bodyTextLen > 200) _stickyState.contentRich = true;
    }
    dom.contentRich = _stickyState.contentRich;
    let bodyText = "";
    try {
      bodyText = _normalizeText((document.body && document.body.innerText || "").slice(0, 6e4));
    } catch (_) {
    }
    const scamHits = [];
    for (const p of VN_SCAM_CONTENT_PATTERNS) {
      if (p.re.test(bodyText)) scamHits.push(p.label);
    }
    dom.scamContentHits = scamHits;
    dom.scamContentRisk = scamHits.length;
    result["Scam Content"] = scamHits.length >= 2 ? "2" : scamHits.length === 1 ? "0" : "-1";
    dom.metaRefreshRedirect = false;
    dom.scriptRedirect = false;
    try {
      const metas = document.querySelectorAll('meta[http-equiv="refresh" i]');
      for (const m of metas) {
        const c = m.getAttribute("content") || "";
        const hit = c.match(/url\s*=\s*([^;]+)/i);
        if (hit) {
          const target = new URL(hit[1].trim().replace(/^['"]|['"]$/g, ""), window.location.href);
          if (target.hostname && target.hostname !== currentDomain && !_hostEndsWith(target.hostname, currentOnlyDomain) && !_sameOrgHost(target.hostname, currentOnlyDomain) && !_isTrustedHost(target.hostname)) dom.metaRefreshRedirect = true;
        }
      }
    } catch (_) {
    }
    const bs = detectBrandSurfaces();
    dom.brandInContent = bs.brandInContent;
    dom.brandSurfaces = bs.brandSurfaces;
    dom.matchedBrand = bs.matchedBrand;
    result["SFH"] = "-1";
    for (const f of forms) {
      const action = f.getAttribute("action");
      if (!action || action === "" || action === "#") result["SFH"] = "0";
      else if (action.startsWith("http")) {
        try {
          const ah = new URL(action).hostname.replace(/^www\./, "");
          if (ah !== currentOnlyDomain && !_hostEndsWith(ah, currentOnlyDomain) && !_sameOrgHost(ah, currentOnlyDomain) && !_isTrustedHost(ah)) result["SFH"] = "1";
        } catch (_) {
        }
      }
    }
    result["mailto"] = "-1";
    for (const f of forms) {
      const a = f.getAttribute("action") || "";
      if (a.startsWith("mailto")) {
        result["mailto"] = "0";
        break;
      }
    }
    result["iFrames"] = "-1";
    dom.numIframes = iframes.length;
    dom.hiddenIframe = false;
    let hiddenIframeCountResult = 0;
    let iframeRiskScore = 0;
    const iframeDetails = [];
    const TRUSTED_IFRAME_HOSTS = [
      "google.com",
      "recaptcha",
      "gstatic.com",
      "google-analytics.com",
      "googletagmanager.com",
      "doubleclick.net",
      "facebook.com",
      "fbcdn.net",
      "connect.facebook.net",
      "stripe.com",
      "js.stripe.com",
      "cloudflare.com",
      "challenges.cloudflare.com",
      "twitter.com",
      "twimg.com",
      "linkedin.com",
      "bing.com",
      "microsoft.com",
      "paypal.com",
      "amazon.com",
      "apple.com",
      "openai.com",
      "chatgpt.com",
      "youtube.com",
      "googlevideo.com",
      "player.vimeo.com",
      "cloud.mongodb.com",
      "mongodb.com"
    ];
    const _isTrustedIframeHost = (host) => {
      if (!host) return true;
      const h = host.toLowerCase();
      return TRUSTED_IFRAME_HOSTS.some((t) => h.includes(t)) || _isTrustedHost(h);
    };
    for (const fr of iframes) {
      const src = fr.getAttribute("src");
      const srcHost = _hostOf(src);
      const w = parseInt(fr.getAttribute("width") || (fr.offsetWidth || 0));
      const h = parseInt(fr.getAttribute("height") || (fr.offsetHeight || 0));
      const st = fr.style || {};
      const isHidden = st.display === "none" || st.visibility === "hidden" || parseFloat(st.opacity || "1") === 0 || w > 0 && w <= 1 || h > 0 && h <= 1;
      const isCrossOrigin = srcHost && srcHost !== currentOnlyDomain && !_hostEndsWith(srcHost, currentOnlyDomain);
      const isTrusted = _isTrustedIframeHost(srcHost);
      if (isTrusted && !isHidden) continue;
      if (isTrusted && isHidden) continue;
      let score = 0;
      const reasons = [];
      if (isHidden) {
        score += 10;
        reasons.push("\u1EA9n");
        hiddenIframeCountResult++;
        _stickyState.hiddenIframe = true;
      }
      if (isCrossOrigin && !isTrusted) {
        score += 15;
        reasons.push("cross-origin");
      }
      if (isCrossOrigin && !isTrusted && !_isTrustedHost(srcHost)) {
        score += 20;
        reasons.push("domain l\u1EA1");
      }
      let iframeHasForm = false, iframeHasPassword = false, iframeHasObf = false;
      try {
        const idoc = fr.contentDocument || fr.contentWindow?.document;
        if (idoc) {
          if (idoc.querySelector("form")) {
            iframeHasForm = true;
          }
          if (idoc.querySelector('input[type="password"]')) {
            iframeHasPassword = true;
          }
          const iscripts = idoc.querySelectorAll("script");
          for (const s of iscripts) {
            const c = s.textContent || "";
            if (c.length > 500 && (c.includes("eval(") || c.includes("atob(") || c.includes("fromCharCode"))) {
              iframeHasObf = true;
              break;
            }
          }
        }
      } catch (_) {
      }
      if (iframeHasForm) {
        score += 20;
        reasons.push("ch\u1EE9a form");
      }
      if (iframeHasPassword) {
        score += 30;
        reasons.push("ch\u1EE9a \xF4 m\u1EADt kh\u1EA9u");
      }
      if (iframeHasObf) {
        score += 30;
        reasons.push("ch\u1EE9a m\xE3 \u0111\u1ED9c");
      }
      if (score > 0) {
        iframeRiskScore = Math.max(iframeRiskScore, score);
        iframeDetails.push({ score, reasons, host: srcHost });
      }
    }
    dom.hiddenIframe = _stickyState.hiddenIframe;
    dom.iframeRiskScore = iframeRiskScore;
    dom.iframeDetails = iframeDetails;
    if (iframeRiskScore >= 40) result["iFrames"] = "1";
    else if (iframeRiskScore >= 25) result["iFrames"] = "2";
    else if (iframeRiskScore >= 10) result["iFrames"] = "0";
    else result["iFrames"] = "-1";
    const sensitiveNames = [
      "password",
      "passcode",
      "passwd",
      "otp",
      "pin",
      "cvv",
      "cvc",
      "cardnumber",
      "card-number",
      "creditcard",
      "credit-card",
      "debitcard",
      "debit-card",
      "cc-number",
      "so-the",
      "sothe",
      "the-ngan-hang",
      "cccd",
      "cmnd",
      "cmt",
      "ekyc",
      "e-kyc",
      "taikhoan",
      "tai-khoan",
      "account",
      "username",
      "user-name",
      "stk",
      "sotk",
      "so-tai-khoan",
      "tai-khoan-ngan-hang",
      "bank-account",
      "ngan-hang",
      "internet-banking",
      "secret",
      "token",
      "private",
      "ngayhethan",
      "ngay-het-han",
      "expiry",
      "expire"
    ];
    const TRUSTED_FORM_HOSTS = ["google.com", "facebook.com", "apple.com", "microsoft.com", "github.com"];
    let sensitiveFound = false, hijackFound = false, pwField = false, otpField = false, hiddenFormFound = false, cardField = false, bankAccountField = false;
    let sensitiveFormCount = 0;
    for (const f of forms) {
      const html = (f.innerHTML || "").toLowerCase();
      const style = (f.getAttribute("style") || "").toLowerCase();
      const hiddenByCss = f.hidden || style.includes("display:none") || style.includes("display: none") || style.includes("visibility:hidden") || style.includes("visibility: hidden") || style.includes("opacity:0") || f.offsetWidth === 0 && f.offsetHeight === 0 && f.querySelector("input");
      const hiddenInputCount = f.querySelectorAll ? f.querySelectorAll('input[type="hidden"]').length : 0;
      let sensitive = /type\s*=\s*["']password["']/.test(html) || /autocomplete\s*=\s*["']current-password["']/.test(html) || /autocomplete\s*=\s*["']cc-[a-z]+["']/.test(html);
      if (!sensitive) {
        for (const nm of sensitiveNames) {
          if (html.includes(nm)) {
            sensitive = true;
            break;
          }
        }
      }
      if (sensitive) {
        sensitiveFound = true;
        sensitiveFormCount++;
        if (/type\s*=\s*["']password["']/.test(html)) pwField = true;
        if (html.includes("otp") || html.includes("ma-xac-thuc") || html.includes("maxacthuc") || html.includes("one-time")) otpField = true;
        if (/card|credit|debit|cvv|cvc|so-the|sothe|cc-number/.test(html)) cardField = true;
        if (/stk|sotk|so-tai-khoan|bank-account|ngan-hang|internet-banking/.test(html)) bankAccountField = true;
        if (hiddenByCss || hiddenInputCount >= 3) hiddenFormFound = true;
        const action = f.getAttribute("action") || "";
        if (action.startsWith("http")) {
          try {
            const ah = new URL(action).hostname.replace(/^www\./, "");
            const trusted = TRUSTED_FORM_HOSTS.some((h) => ah === h || ah.endsWith("." + h));
            const same = ah === currentOnlyDomain || _hostEndsWith(ah, currentOnlyDomain) || _sameOrgHost(ah, currentOnlyDomain);
            if (!trusted && !same && !_isTrustedHost(ah)) hijackFound = true;
          } catch (_) {
          }
        }
      }
    }
    dom.sensitiveForm = sensitiveFound || _stickyState.sensitiveForm;
    _stickyState.sensitiveForm = dom.sensitiveForm;
    dom.formHijack = hijackFound || _stickyState.formHijack;
    _stickyState.formHijack = dom.formHijack;
    dom.passwordField = pwField;
    dom.otpField = otpField;
    dom.cardField = cardField;
    dom.bankAccountField = bankAccountField;
    dom.hiddenForm = hiddenFormFound;
    result["Sensitive Form"] = sensitiveFound ? cardField || bankAccountField ? "2" : "0" : "-1";
    result["Form Hijacking"] = hijackFound ? "1" : "-1";
    result["Hidden Form"] = hiddenFormFound ? "2" : "-1";
    if (result["SFH"] === "0" && !sensitiveFound) {
      result["SFH"] = "-1";
    }
    dom.sfh = result["SFH"];
    const TRUSTED_PAT = [/webpack/, /__vite__/, /react\./, /__vue__/, /_nuxt/, /cloudflare/, /gtag\(/, /ga\(/, /dataLayer/, /serviceWorker/, /sentry/, /jquery/];
    const calcEntropy = (str) => {
      if (!str || str.length === 0) return 0;
      const freq = {};
      for (const c of str) freq[c] = (freq[c] || 0) + 1;
      let e = 0;
      const len = str.length;
      for (const k in freq) {
        const p = freq[k] / len;
        e -= p * Math.log2(p);
      }
      return e;
    };
    let maxConf = 0;
    let hasKeylogger = false, hasClipboard = false, hasObf = false, hasWS = false;
    const permissionSignals = /* @__PURE__ */ new Set();
    const jsRiskIndicators = /* @__PURE__ */ new Set();
    for (const s of sTags) {
      const code = s.innerHTML;
      if (!code || code.length < 80) continue;
      let conf = 0;
      const compactCode = code.replace(/\s+/g, "");
      const hex = (code.match(/\\x[0-9a-fA-F]{2}/g) || []).length;
      const uni = (code.match(/\\u[0-9a-fA-F]{4}/g) || []).length;
      if (hex > 15 || uni > 15) {
        conf += 30;
        jsRiskIndicators.add("encoded");
      }
      if (/unescape\s*\(/.test(code) || /(?:String\.)?fromCharCode\s*\(/.test(code)) {
        conf += 25;
        jsRiskIndicators.add("decoder");
      }
      if (/atob\s*\(/.test(code)) {
        conf += code.length > 2e3 ? 15 : 8;
        jsRiskIndicators.add("atob");
      }
      if (/eval\s*\(/.test(code)) {
        conf += conf > 0 ? 25 : 10;
        jsRiskIndicators.add("eval");
      }
      if (/new\s+Function\s*\(/.test(code)) {
        conf += 15;
        jsRiskIndicators.add("new Function");
      }
      if (/document\.write\s*\(/.test(code)) {
        conf += 8;
        jsRiskIndicators.add("document.write");
      }
      if (/["'][A-Za-z0-9+/]{120,}={0,2}["']/.test(compactCode)) {
        conf += 18;
        jsRiskIndicators.add("base64 payload");
      }
      if (code.length > 1500 && (code.match(/\n/g) || []).length < 4 && calcEntropy(code) > 5.2) {
        conf += 20;
        jsRiskIndicators.add("high entropy");
      }
      if (TRUSTED_PAT.some((re) => re.test(code))) conf = Math.max(0, conf - 20);
      maxConf = Math.max(maxConf, conf);
      if (conf >= 60) hasObf = true;
      if (/addEventListener\s*\(\s*["']keydown["']|addEventListener\s*\(\s*["']keypress["']/.test(code)) {
        if (code.length > 500 && (code.includes("XMLHttpRequest") || code.includes("fetch(") || code.includes("sendBeacon"))) hasKeylogger = true;
      }
      if (/navigator\.clipboard\.writeText|clipboard\.writeText/.test(code)) {
        hasClipboard = true;
        permissionSignals.add("clipboard-write");
      }
      if (/Notification\.requestPermission|navigator\.permissions\.query\s*\(/.test(code)) permissionSignals.add("notification-or-permissions");
      if (/navigator\.geolocation\.(getCurrentPosition|watchPosition)/.test(code)) permissionSignals.add("geolocation");
      if (/navigator\.mediaDevices\.getUserMedia|getUserMedia\s*\(/.test(code)) permissionSignals.add("camera-microphone");
      if (/requestFullscreen\s*\(/.test(code)) permissionSignals.add("fullscreen");
      if (/new\s+PaymentRequest\s*\(/.test(code)) permissionSignals.add("payment-request");
      if (/requestMIDIAccess\s*\(/.test(code)) permissionSignals.add("midi");
      if (/Device(Motion|Orientation)Event\.requestPermission|new\s+(Accelerometer|Gyroscope|Magnetometer|AmbientLightSensor)\s*\(/.test(code)) permissionSignals.add("sensors");
      if (/(location\.(href|replace|assign)|window\.open)\s*\(\s*["']https?:\/\//i.test(code) || /location\.(href|replace)\s*=\s*["']https?:\/\//i.test(code)) dom.scriptRedirect = true;
      if (/new\s+WebSocket\s*\(|\.io\s*\(|socket\.io/i.test(code)) hasWS = true;
    }
    dom.obfuscatedScript = hasObf || _stickyState.obfuscatedScript;
    _stickyState.obfuscatedScript = dom.obfuscatedScript;
    dom.keylogger = hasKeylogger || _stickyState.keylogger;
    _stickyState.keylogger = dom.keylogger;
    dom.clipboardHijack = hasClipboard || _stickyState.clipboardHijack;
    _stickyState.clipboardHijack = dom.clipboardHijack;
    dom.websocket = hasWS;
    if (permState && permState.requests) permState.requests.forEach((x) => permissionSignals.add(x));
    dom.permissionRequests = Array.from(permissionSignals).slice(0, 12);
    dom.permissionAbuse = dom.permissionRequests.length > 0;
    dom.jsRiskScore = maxConf;
    dom.jsRiskIndicators = Array.from(jsRiskIndicators).slice(0, 8);
    result["Obfuscated Script"] = hasObf ? "1" : maxConf >= 40 ? "0" : "-1";
    result["JavaScript Risk"] = maxConf >= 60 ? "1" : maxConf >= 35 ? "2" : "-1";
    let suspExt = false;
    for (const h of externalScriptHosts) {
      if (ipRe.test(h)) {
        suspExt = true;
        break;
      }
      const label = h.split(".")[0];
      if (label.length > 24 && /[0-9]/.test(label) && /[a-zA-Z]/.test(label)) {
        suspExt = true;
        break;
      }
    }
    dom.suspiciousExternalScript = suspExt || _stickyState.suspiciousExternalScript;
    _stickyState.suspiciousExternalScript = dom.suspiciousExternalScript;
    const DANGEROUS_EXT = [".exe", ".scr", ".bat", ".cmd", ".ps1", ".apk", ".msi", ".dll", ".vbs", ".jar"];
    const ARCHIVE_EXT = [".zip", ".rar", ".7z"];
    dom.downloadFile = false;
    dom.archiveDownload = false;
    try {
      if (document.querySelector("a[download]") || document.querySelector('meta[http-equiv="refresh"]')) {
        const html = document.documentElement.outerHTML.toLowerCase();
        if (DANGEROUS_EXT.some((e) => html.includes(e))) dom.downloadFile = true;
        if (ARCHIVE_EXT.some((e) => html.includes(e))) dom.archiveDownload = true;
      }
    } catch (_) {
    }
    if (DANGEROUS_EXT.some((e) => window.location.pathname.toLowerCase().endsWith(e))) dom.downloadFile = true;
    if (ARCHIVE_EXT.some((e) => window.location.pathname.toLowerCase().endsWith(e))) dom.archiveDownload = true;
    dom.downloadFile = dom.downloadFile || _stickyState.downloadFile;
    _stickyState.downloadFile = dom.downloadFile;
    if (netState.uploadToExternal) _stickyState.networkUploadToExternal = true;
    dom.networkUploadToExternal = _stickyState.networkUploadToExternal;
    dom.formDestinations = netState.externalPostHosts ? Array.from(netState.externalPostHosts) : [];
    dom.hasUntrustedFormDest = dom.formDestinations.some((h) => !_isTrustedHost(h));
    dom.rtcPeerConnection = _stickyState.rtcPeerConnection;
    dom.windowOpenCount = _stickyState.windowOpenCount;
    dom.suspiciousPostMessage = _stickyState.suspiciousPostMessage;
    dom.dynamicScriptInjection = _stickyState.dynamicScriptInjection;
    dom.dynamicIframeInjection = _stickyState.dynamicIframeInjection;
    dom.sensitiveLSKeys = _stickyState.sensitiveLSKeys;
    dom.clipboardRead = _stickyState.clipboardRead;
    const linkWarnings = aExt;
    const scriptWarnings = extCount;
    const imageWarnings = imgExt;
    const iframeDanger = iframeRiskScore >= 40 ? 1 : 0;
    const iframeWarning = iframeRiskScore > 0 && iframeRiskScore < 40 ? 1 : 0;
    const formDanger = hijackFound ? 1 : 0;
    const formWarning = sensitiveFormCount;
    dom.counts = {
      hiddenIframes: hiddenIframeCountResult,
      totalIframes: iframes.length,
      iframeRiskScore,
      sensitiveForms: sensitiveFormCount,
      totalForms: forms.length,
      externalAnchors: aExt,
      totalAnchors: aTotal,
      externalScripts: extCount,
      totalScripts: totalCount,
      externalImages: imgExt,
      totalImages: imgTotal,
      scamContentHits: scamHits.length,
      jsRiskScore: maxConf,
      hiddenForms: hiddenFormFound ? 1 : 0,
      suspiciousLinks: dom.suspiciousLinkCount || 0,
      deceptiveLinks: dom.deceptiveLinkCount || 0,
      permissionRequests: dom.permissionRequests ? dom.permissionRequests.length : 0,
      links: { total: aTotal, safe: Math.max(0, aTotal - linkWarnings), warning: linkWarnings, dangerous: 0 },
      scripts: { total: totalCount, safe: Math.max(0, totalCount - scriptWarnings), warning: scriptWarnings, dangerous: 0 },
      images: { total: imgTotal, safe: Math.max(0, imgTotal - imageWarnings), warning: imageWarnings, dangerous: 0 },
      iframes: { total: iframes.length, safe: Math.max(0, iframes.length - iframeWarning - iframeDanger), warning: iframeWarning, dangerous: iframeDanger },
      forms: { total: forms.length, safe: Math.max(0, forms.length - formWarning - formDanger), warning: formWarning, dangerous: formDanger }
    };
    return { result, dom };
  };

  // src/extension/features-runner.js
  var injectPageHooksResource = () => {
    try {
      if (document.getElementById("__antiscam_page_hooks")) return;
      const s = document.createElement("script");
      s.id = "__antiscam_page_hooks";
      s.src = chrome.runtime.getURL("scripts/content/page_hooks.js");
      s.async = false;
      (document.documentElement || document.head || document).appendChild(s);
      s.onload = () => {
        try {
          s.remove();
        } catch (_) {
        }
      };
    } catch (_) {
    }
  };
  window.addEventListener("__antiscam_net", (e) => {
    try {
      const currentOnlyDomain = window.location.hostname.replace(/^www\./, "");
      const d = e.detail || {};
      if (d.host && d.host !== currentOnlyDomain) {
        netState.externalHosts.add(d.host);
        if (d.upload) {
          netState.uploadToExternal = true;
          netState.externalPostHosts.add(d.host);
        }
      }
    } catch (_) {
    }
  });
  window.addEventListener("__antiscam_perm", (e) => {
    try {
      if (e.detail && e.detail.name) {
        permState.requests.add(String(e.detail.name));
        scheduleRescan(250);
      }
    } catch (_) {
    }
  });
  window.addEventListener("__antiscam_behavior", (e) => {
    try {
      const d = e.detail || {};
      scheduleRescan(250);
    } catch (_) {
    }
  });
  var injectNetworkHook = () => {
    try {
      if (document.getElementById("__antiscam_net_hook")) return;
      const s = document.createElement("script");
      s.id = "__antiscam_net_hook";
      s.src = chrome.runtime.getURL("scripts/content/network_hooks.js");
      s.async = false;
      (document.documentElement || document.head || document).appendChild(s);
      s.onload = () => {
        try {
          s.remove();
        } catch (_) {
        }
      };
    } catch (_) {
    }
  };
  var _rescanTimer = null;
  var scheduleRescan = (ms = 1e3) => {
    if (_rescanTimer) clearTimeout(_rescanTimer);
    _rescanTimer = setTimeout(() => {
      const { result, dom } = collect();
      chrome.runtime.sendMessage({ type: "ANALYSIS_UPDATE", result, dom }).catch(() => {
      });
    }, ms);
  };
  var observer = new MutationObserver((mutations) => {
    let heavy = false;
    for (const m of mutations) {
      if (m.addedNodes.length > 0) {
        for (const node of m.addedNodes) {
          if (node.nodeType === 1 && ["FORM", "SCRIPT", "IFRAME", "A", "INPUT"].includes(node.nodeName)) {
            heavy = true;
            break;
          }
        }
      }
      if (heavy) break;
    }
    if (heavy) scheduleRescan(800);
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });
  var initScan = () => {
    const { result, dom } = collect();
    const isOffscreen = window.location.href.includes("__antiscam_scan=1") || window.name === "antiscam-offscreen-scan-frame";
    if (isOffscreen) {
      chrome.runtime.sendMessage({
        type: "OFFSCREEN_DEEP_SCAN_RESULT",
        url: window.location.href.replace(/([?&])__antiscam_scan=1&?/, "$1").replace(/\?$/, ""),
        signals: { result, dom },
        status: "OK"
      }).catch(() => {
      });
      return;
    }
    chrome.runtime.sendMessage({ type: "ANALYSIS_RESULT", result, dom }).catch(() => {
    });
    injectPageHooksResource();
    injectNetworkHook();
  };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initScan);
  } else {
    initScan();
  }
  window.addEventListener("popstate", () => scheduleRescan(500));
  window.addEventListener("hashchange", () => scheduleRescan(500));
})();

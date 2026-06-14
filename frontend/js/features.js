/*global chrome*/

// const REDIRECT_PORT_NAME = 'REDIRECT_PORT_NAME';
// const CLOSE_TAB_PORT_NAME = 'CLOSE_TAB_PORT_NAME';
const ML_PORT_NAME = 'ML_PORT_NAME';

// ─── BƯỚC 4 & 5: PERFORMANCE PROFILER & TELEMETRY
const Profiler = {
  start(name) {
    console.log(`[AntiScam Profiler] [START] ${name}`);
    return performance.now();
  },
  end(name, startTime) {
    const elapsed = (performance.now() - startTime).toFixed(2);
    console.log(`[AntiScam Profiler] [END] ${name} ${elapsed}ms`);
  }
};

// ─── URL Intelligence Integration ───────────────────────────────────────────
// url-intelligence.js đã chạy trước và đặt kết quả vào window.antiScamURLIntel
// Nếu chưa có (ví dụ engine bị lỗi), ta dùng object rỗng để tránh crash
const urlIntel = (typeof window !== 'undefined' && window.antiScamURLIntel) || {
  score: 0,
  riskLevel: 'SAFE',
  explanation: '',
  entropy: 0,
  homograph: { detected: false },
  typosquatting: { isTyposquatting: false, isOfficialDomain: false, targetBrand: null, similarity: 0 },
  suspiciousTLD: { suspicious: false, tld: '' },
  urlShortener: { isShortened: false },
  subdomainAbuse: { detected: false, findings: [] },
  suspiciousKeywords: { detected: false, keywords: [], count: 0 },
  redirectIndicators: { detected: false, indicators: [] },
};

// ─── FIX PERF: Không gọi analyzeWebsite() ngay (blocking DOM scan)
// Sẽ chạy defer sau khi gửi message đầu tiên
let websiteIntel = { score: 0, riskLevel: 'SAFE', explanation: '' };
let brandIntel = { score: 0, riskLevel: 'SAFE', explanation: '' };

const result = {};
//---------------------- 1.  IP Address  ----------------------

const url = window.location.href;
// alert(url);
const urlDomain = window.location.hostname;

//url="0x58.0xCC.0xCA.0x62"

let patt = /(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]?[0-9])(\.|$){4}/;
const patt2 = /(0x([0-9][0-9]|[A-F][A-F]|[A-F][0-9]|[0-9][A-F]))(\.|$){4}/;
const ip = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;


if (ip.test(urlDomain) || patt.test(urlDomain) || patt2.test(urlDomain)) {
  result['IP Address'] = '1';
} else {
  result['IP Address'] = '-1';
}

//alert(result);

//---------------------- 2.  URL Length  ----------------------


//alert(url.length);
if (url.length < 54) {
  result['URL Length'] = '-1';
} else if (url.length >= 54 && url.length <= 75) {
  result['URL Length'] = '0';
} else {
  result['URL Length'] = '1';
}
//alert(result);


//---------------------- 3.  Tiny URL  ----------------------

const onlyDomain = urlDomain.replace('www.', '');

if (onlyDomain.length < 7) {
  result['Tiny URL'] = '1';
} else {
  result['Tiny URL'] = '-1';
}
//alert(result);

//---------------------- 4.  @ Symbol  ----------------------

patt = /@/;
if (patt.test(url)) {
  result['@ Symbol'] = '1';
} else {
  result['@ Symbol'] = '-1';
}

//---------------------- 5.  Redirecting using //  ----------------------

if (url.lastIndexOf('//') > 7) {
  result['Redirecting using //'] = '1';
} else {
  result['Redirecting using //'] = '-1';
}

//---------------------- 6. (-) Prefix/Suffix in domain  ----------------------

patt = /-/;
if (patt.test(urlDomain)) {
  result['(-) Prefix/Suffix in domain'] = '1';
} else {
  result['(-) Prefix/Suffix in domain'] = '-1';
}

//---------------------- 7.  No. of Sub Domains  ----------------------

//patt=".";

if ((onlyDomain.match(RegExp('\\.', 'g')) || []).length == 1) {
  result['No. of Sub Domains'] = '-1';
} else if ((onlyDomain.match(RegExp('\\.', 'g')) || []).length == 2) {
  result['No. of Sub Domains'] = '0';
} else {
  result['No. of Sub Domains'] = '1';
}

//---------------------- 8.  HTTPS  ----------------------


patt = /https:\/\//;
if (patt.test(url)) {
  result['HTTPS'] = '-1';
} else {
  result['HTTPS'] = '1';
}

//---------------------- 9.  Domain Registration Length  ----------------------

//---------------------- 10. Favicon  ----------------------

let favicon = undefined;
const nodeList = document.getElementsByTagName('link');
for (let i = 0; i < nodeList.length; i++) {
  if ((nodeList[i].getAttribute('rel') == 'icon') || (nodeList[i].getAttribute('rel') == 'shortcut icon')) {
    favicon = nodeList[i].getAttribute('href');
  }
}
if (!favicon) {
  result['Favicon'] = '-1';
} else if (favicon.length == 12) {
  result['Favicon'] = '-1';
} else {
  patt = RegExp(urlDomain, 'g');
  if (patt.test(favicon)) {
    result['Favicon'] = '-1';
  } else {
    result['Favicon'] = '1';
  }
}


//---------------------- 11. Using Non-Standard Port  ----------------------

result['Port'] = '-1';

//---------------------- 12.  HTTPS in URL's domain part  ----------------------


patt = /https/;
if (patt.test(onlyDomain)) {
  result['HTTPS in URL\'s domain part'] = '1';
} else {
  result['HTTPS in URL\'s domain part'] = '-1';
}

// alert(result);

//---------------------- 13.  Request URL  ----------------------

const imgTags = document.getElementsByTagName('img');

let phishCount = 0;
let legitCount = 0;

patt = RegExp(onlyDomain, 'g');

for (let i = 0; i < imgTags.length; i++) {
  const src = imgTags[i].getAttribute('src');
  if (!src) continue;
  if (patt.test(src)) {
    legitCount++;
  } else if (src.charAt(0) == '/' && src.charAt(1) != '/') {
    legitCount++;
  } else {
    phishCount++;
  }
}
let totalCount = phishCount + legitCount;
let outRequest = (phishCount / totalCount) * 100;
//alert(outRequest);

if (outRequest < 22) {
  result['Request URL'] = '-1';
} else if (outRequest >= 22 && outRequest < 61) {
  result['Request URL'] = '0';
} else {
  result['Request URL'] = '1';
}

//---------------------- 14.  URL of Anchor  ----------------------
const aTags = document.getElementsByTagName('a');

phishCount = 0;
legitCount = 0;

for (let i = 0; i < aTags.length; i++) {
  const hrefs = aTags[i].getAttribute('href');
  if (!hrefs) continue;
  if (patt.test(hrefs)) {
    legitCount++;
  } else if (hrefs.charAt(0) == '#' || (hrefs.charAt(0) == '/' && hrefs.charAt(1) != '/')) {
    legitCount++;
  } else {
    phishCount++;
  }
}
totalCount = phishCount + legitCount;
outRequest = (phishCount / totalCount) * 100;

if (outRequest < 31) {
  result['Anchor'] = '-1';
} else if (outRequest >= 31 && outRequest <= 67) {
  result['Anchor'] = '0';
} else {
  result['Anchor'] = '1';
}

//---------------------- 15. Links in script and link  ----------------------

// const mTags = document.getElementsByTagName('meta');
const sTags = document.getElementsByTagName('script');
const lTags = document.getElementsByTagName('link');

phishCount = 0;
legitCount = 0;


for (let i = 0; i < sTags.length; i++) {
  const sTag = sTags[i].getAttribute('src');
  if (sTag != null) {
    if (patt.test(sTag)) {
      legitCount++;
    } else if (sTag.charAt(0) == '/' && sTag.charAt(1) != '/') {
      legitCount++;
    } else {
      phishCount++;
    }
  }
}

for (let i = 0; i < lTags.length; i++) {
  const lTag = lTags[i].getAttribute('href');
  if (!lTag) continue;
  if (patt.test(lTag)) {
    legitCount++;
  } else if (lTag.charAt(0) == '/' && lTag.charAt(1) != '/') {
    legitCount++;
  } else {
    phishCount++;
  }
}

totalCount = phishCount + legitCount;
outRequest = (phishCount / totalCount) * 100;

if (outRequest < 17) {
  result['Script & Link'] = '-1';
} else if (outRequest >= 17 && outRequest <= 81) {
  result['Script & Link'] = '0';
} else {
  result['Script & Link'] = '1';
}

//---------------------- 16.Server Form Handler ----------------------

const forms = document.getElementsByTagName('form');
result['SFH'] = '-1';

for (let i = 0; i < forms.length; i++) {
  const action = forms[i].getAttribute('action');
  if (!action || action == '') {
    result['SFH'] = '1';
    break;
  } else if (!(action.charAt(0) == '/' || patt.test(action))) {
    result['SFH'] = '0';
  }
}

//---------------------- 17.Submitting to mail ----------------------

result['mailto'] = '-1';

for (let i = 0; i < forms.length; i++) {
  const action = forms[i].getAttribute('action');
  if (!action) continue;
  if (action.startsWith('mailto')) {
    result['mailto'] = '1';
    break;
  }
}

//---------------------- 23.Using iFrame ----------------------

const iframes = document.getElementsByTagName('iframe');

if (iframes.length == 0) {
  result['iFrames'] = '-1';
} else {
  result['iFrames'] = '1';
}

// ─── Phase 1: Gửi ngay kết quả URL-based (< 50ms, không cần chờ DOM scan nặng)
const mlPort = chrome.runtime.connect({name: ML_PORT_NAME});
mlPort.postMessage({
  request: result,
  urlIntel: urlIntel,
  websiteIntel: websiteIntel,
  brandIntel: brandIntel,
});

// ─── Phase 2: Chạy DOM scan nặng sau (defer qua setTimeout(0))
// analyzeWebsite() và BrandDetection có thể tốn 50-200ms trên page lớn như YouTube
setTimeout(() => {
  const _currentHostname = (typeof window !== 'undefined') ? window.location.hostname : '';

  const startWeb = Profiler.start('Website Analysis (DOM)');
  const _websiteIntel = (typeof window !== 'undefined' && window.WebsiteIntelligence &&
    window.WebsiteIntelligence.analyzeWebsite()) || { score: 0, riskLevel: 'SAFE', explanation: '' };
  Profiler.end('Website Analysis (DOM)', startWeb);

  const startBrand = Profiler.start('Brand Analysis (DOM)');
  const _brandIntel = (typeof window !== 'undefined' && window.BrandDetection &&
    window.BrandDetection.detectBrandImpersonation(_currentHostname)) || { score: 0, riskLevel: 'SAFE', explanation: '' };
  Profiler.end('Brand Analysis (DOM)', startBrand);

  // Luôn gửi update kết quả DOM scan lên background để UI biết là đã phân tích xong
  mlPort.postMessage({
    request: result,
    urlIntel: urlIntel,
    websiteIntel: _websiteIntel,
    brandIntel: _brandIntel,
  });
}, 0);

// ─── Lắng nghe yêu cầu gửi lại dữ liệu từ background (khi Service Worker thức dậy)
chrome.runtime.onMessage.addListener((msg) => {
  if (msg && msg.type === 'RESEND_INTEL') {
    const port = chrome.runtime.connect({name: ML_PORT_NAME});
    port.postMessage({
      request: result,
      urlIntel: urlIntel,
      websiteIntel: typeof window !== 'undefined' && window.WebsiteIntelligence ? window.WebsiteIntelligence.analyzeWebsite() : websiteIntel,
      brandIntel: typeof window !== 'undefined' && window.BrandDetection ? window.BrandDetection.detectBrandImpersonation(window.location.hostname) : brandIntel,
    });
  }
});

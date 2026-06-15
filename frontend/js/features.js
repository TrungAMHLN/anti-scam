/*global chrome*/

/*
$('a').click(function(){
    alert("You are about to go to "+$(this).attr('href'));
});
*/

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
let outRequest = totalCount === 0 ? 0 : (phishCount / totalCount) * 100;
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
outRequest = totalCount === 0 ? 0 : (phishCount / totalCount) * 100;

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
outRequest = totalCount === 0 ? 0 : (phishCount / totalCount) * 100;

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

//---------------------- 23. Using iFrame (Smart Hidden Detection) ----------------------

const iframes = document.getElementsByTagName('iframe');

if (iframes.length === 0) {
  result['iFrames'] = '-1';
} else {
  // Chỉ cảnh báo nếu có iFrame thực sự bị ẩn/vô hình (mánh khóe của hacker)
  // iFrame thông thường như nhúng video, bản đồ, nút Like... thì bỏ qua
  let hasHiddenIframe = false;
  for (let i = 0; i < iframes.length; i++) {
    const fr = iframes[i];
    const w = parseInt(fr.getAttribute('width') || fr.offsetWidth);
    const h = parseInt(fr.getAttribute('height') || fr.offsetHeight);
    const st = fr.style;
    const isInvisible = (
      st.display === 'none' ||
      st.visibility === 'hidden' ||
      parseFloat(st.opacity) === 0 ||
      (w <= 1 && h <= 1)
    );
    if (isInvisible) {
      hasHiddenIframe = true;
      break;
    }
  }
  result['iFrames'] = hasHiddenIframe ? '1' : '-1';
}

//---------------------- 24. Sensitive Form Analysis + Form Action Hijacking ----------------------
result['Sensitive Form'] = '-1';
result['Form Hijacking'] = '-1';
const sensitiveKeywords = ['otp', 'mật khẩu', 'password', 'passcode', 'ccv', 'số thẻ', 'pin', 'bảo mật', 'đăng nhập'];
// Các OAuth/API đăng nhập hợp lệ phổ biến — không bị coi là Form Hijacking
const TRUSTED_FORM_HOSTS = ['google.com', 'accounts.google.com', 'facebook.com', 'apple.com', 'microsoft.com', 'github.com'];

let foundSensitive = false;
let foundHijacking = false;
const currentHost = window.location.hostname.replace('www.', '');

for (let i = 0; i < forms.length; i++) {
  const formHtml = forms[i].innerHTML.toLowerCase();
  const formAction = forms[i].getAttribute('action') || '';

  // Kiểm tra form có đòi nhập thông tin nhạy cảm
  let isSensitiveForm = formHtml.includes('type="password"') || formHtml.includes("type='password'");
  if (!isSensitiveForm) {
    for (const kw of sensitiveKeywords) {
      if (formHtml.includes(kw)) {
        isSensitiveForm = true;
        break;
      }
    }
  }

  if (isSensitiveForm) {
    foundSensitive = true;
    // Kiểm tra Form Action Hijacking: form nhạy cảm nhưng gửi sang domain khác
    if (formAction.startsWith('http')) {
      try {
        const actionHost = new URL(formAction).hostname.replace('www.', '');
        const isTrusted = TRUSTED_FORM_HOSTS.some(h => actionHost === h || actionHost.endsWith('.' + h));
        const isSameDomain = actionHost === currentHost || currentHost.endsWith('.' + actionHost) || actionHost.endsWith('.' + currentHost);
        if (!isTrusted && !isSameDomain) {
          foundHijacking = true;
        }
      } catch (_) { /* bỏ qua nếu URL action không hợp lệ */ }
    }
  }
}

if (foundSensitive) result['Sensitive Form'] = '1';
if (foundHijacking) result['Form Hijacking'] = '1';

//---------------------- 25. Obfuscated Script (Multi-Layer Risk Scoring) ----------------------
result['Obfuscated Script'] = '-1';
let maxRiskScore = 0;
let maxObfuscationConfidence = 0;

const TRUSTED_PATTERNS = [
  /webpackBootstrap/, /webpackChunk/, /__vite_/, /vitePreload/,
  /react\.development/, /react\.production/, /__vue_/, /nuxt\./, /_nuxt/,
  /next\/dist\//, /cloudflare\.com\/cdn/, /gtag\(/, /ga\(/, /dataLayer\.push/,
  /serviceWorker\.register/
];

const calculateEntropy = (str) => {
  const len = str.length;
  if (len === 0) return 0;
  const frequencies = {};
  for (let i = 0; i < len; i++) {
    const c = str[i];
    frequencies[c] = (frequencies[c] || 0) + 1;
  }
  let entropy = 0;
  for (const key in frequencies) {
    const f = frequencies[key] / len;
    entropy -= f * Math.log2(f);
  }
  return entropy;
};

for (let i = 0; i < sTags.length; i++) {
  const scriptContent = sTags[i].innerHTML;
  if (!scriptContent || scriptContent.length < 50) continue;

  let riskScore = 0;
  let obfuscationConfidence = 0;

  // Layer 1: Structural Analysis (max +10)
  let structuralScore = 0;
  if (scriptContent.length > 500 && (scriptContent.match(/\n/g) || []).length < 5) structuralScore += 3;
  if (calculateEntropy(scriptContent) > 5.5) structuralScore += 3;
  if (scriptContent.split('\n').some(line => line.length > 1000)) structuralScore += 2;
  if (scriptContent.length > 50000) structuralScore += 2; // >50KB inline
  riskScore += Math.min(10, structuralScore);
  
  const hexCount = (scriptContent.match(/\\x[0-9a-fA-F]{2}/g) || []).length;
  const unicodeCount = (scriptContent.match(/\\u[0-9a-fA-F]{4}/g) || []).length;
  if (hexCount > 10 || unicodeCount > 10) obfuscationConfidence += 25;
  if (scriptContent.includes('unescape(') || scriptContent.includes('String.fromCharCode(')) obfuscationConfidence += 25;

  // Layer 2: Suspicious Execution
  const hasEval = scriptContent.includes('eval(');
  if (hasEval && obfuscationConfidence > 0) { riskScore += 25; obfuscationConfidence += 25; }
  if (scriptContent.includes('new Function(')) { riskScore += 20; obfuscationConfidence += 20; }
  if (scriptContent.includes('document.write(') && scriptContent.includes('<iframe')) riskScore += 25;
  if (scriptContent.includes('style.display') && scriptContent.includes('none')) riskScore += 20;
  if (scriptContent.includes('location.href') && obfuscationConfidence > 0) riskScore += 20;
  if (scriptContent.includes('navigator.clipboard.write')) riskScore += 30;
  if (scriptContent.includes("addEventListener('keydown'") || scriptContent.includes('addEventListener("keydown"') ||
      scriptContent.includes("addEventListener('keyup'") || scriptContent.includes('addEventListener("keyup"')) riskScore += 40;

  // Layer 3: Phishing Indicators
  const lcScript = scriptContent.toLowerCase();
  if (foundSensitive && obfuscationConfidence > 0) riskScore += 20;
  if (lcScript.includes('otp')) riskScore += 25;
  if (['username', 'password', 'login'].some(kw => lcScript.includes(kw))) riskScore += 25;
  if (['ngân hàng', 'tài khoản', 'chuyển khoản'].some(kw => lcScript.includes(kw))) riskScore += 20;
  if (['seed phrase', 'private key', 'metamask'].some(kw => lcScript.includes(kw))) riskScore += 20;
  if (['telegram', 't.me'].some(kw => lcScript.includes(kw))) riskScore += 20;

  // Layer 4: Trusted Patterns
  for (const pattern of TRUSTED_PATTERNS) {
    if (pattern.test(scriptContent)) {
      riskScore = Math.max(0, riskScore - 15);
      obfuscationConfidence = Math.max(0, obfuscationConfidence - 15);
    }
  }

  maxRiskScore = Math.max(maxRiskScore, riskScore);
  maxObfuscationConfidence = Math.max(maxObfuscationConfidence, obfuscationConfidence);
}

// Chuyển việc đánh giá cuối cùng sang background.js để kết hợp với Layer 4 (Domain Reputation)
result['Obfuscation Confidence'] = maxObfuscationConfidence;
result['Obfuscation Risk'] = maxRiskScore;
result['Obfuscated Script'] = '-1'; // Sẽ được tính lại trong background.js

//---------------------- Sending the result  ----------------------
// MV3: Dùng sendMessage thay cho port (port bị ngắt khi SW restart)
chrome.runtime.sendMessage({ type: 'ANALYSIS_RESULT', result }, () => {
  if (chrome.runtime.lastError) {
    // Service worker có thể đang khởi động lại — bỏ qua, popup sẽ polling
    console.warn('[AntiScam] features.js: could not send result —', chrome.runtime.lastError.message);
  }
});

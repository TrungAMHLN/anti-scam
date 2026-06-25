// ============================================================
// @anti-scam/core — Brand detection, typosquat, homograph
// ============================================================
import { BRANDS, SHORT_BRAND_KEYS } from './constants.js';

// ── Punycode decoder (minimal RFC3492) ──
const punycodeDecodeLabel = (input) => {
  if (!input || !input.startsWith('xn--')) return input;
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700, initialBias = 72, initialN = 128;
  const label = input.slice(4);
  const out = [];
  let i = 0, n = initialN, bias = initialBias;
  const adapt = (delta, numPoints, firstTime) => {
    delta = firstTime ? Math.floor(delta / damp) : (delta >> 1);
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > Math.floor(((base - tMin) * tMax) / 2)) { delta = Math.floor(delta / (base - tMin)); k += base; }
    return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
  };
  const digit = (cp) => {
    if (cp >= 48 && cp <= 57) return cp - 22;
    if (cp >= 65 && cp <= 90) return cp - 65;
    if (cp >= 97 && cp <= 122) return cp - 97;
    return base;
  };
  const dash = label.lastIndexOf('-');
  if (dash > -1) { for (let j = 0; j < dash; j++) out.push(label.charCodeAt(j)); }
  let idx = dash > -1 ? dash + 1 : 0;
  while (idx < label.length) {
    const oldi = i;
    let w = 1;
    for (let k = base; ; k += base) {
      if (idx >= label.length) return input;
      const d = digit(label.charCodeAt(idx++));
      if (d >= base) return input;
      i += d * w;
      const t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias);
      if (d < t) break;
      w *= (base - t);
    }
    const outLen = out.length + 1;
    bias = adapt(i - oldi, outLen, oldi === 0);
    n += Math.floor(i / outLen);
    i %= outLen;
    out.splice(i, 0, n);
    i++;
  }
  try { return String.fromCodePoint.apply(String, out); } catch (_) { return input; }
};

export const toUnicodeDomain = (host) => (host || '').split('.').map(punycodeDecodeLabel).join('.');

// ── Confusables mapping ──
export const CONFUSABLES_MAP = {
  'а':'a','А':'a','В':'b','Е':'e','е':'e','К':'k','М':'m','Н':'h','О':'o','о':'o','Р':'p','р':'p','С':'c','с':'c','Т':'t','Х':'x','х':'x','У':'y','у':'y','І':'i','і':'i','ӏ':'l','Ь':'b','ԁ':'d','ԛ':'q','ԝ':'w',
  'Α':'a','Β':'b','Ε':'e','Ζ':'z','Η':'h','Ι':'i','Κ':'k','Μ':'m','Ν':'n','Ο':'o','ο':'o','Ρ':'p','Τ':'t','Υ':'y','Χ':'x','α':'a','β':'b','γ':'y','δ':'d','ε':'e','ι':'i','κ':'k','ν':'v','ρ':'p','τ':'t','χ':'x','ϲ':'c',
  '０':'0','１':'1','３':'3','４':'4','５':'5','６':'6','７':'7','８':'8','＠':'@','Ｉ':'i','ｌ':'l','Ｏ':'o'
};

export const dehomoglyph = (s) => {
  let r = (s || '').split('').map(ch => CONFUSABLES_MAP[ch] || ch).join('').toLowerCase();
  try { r = r.normalize('NFD').replace(/[\u0300-\u036f]/g, ''); } catch (_) {}
  r = r.replace(/rn/g, 'm');
  r = r.replace(/[0]/g, 'o');
  r = r.replace(/[1|!¡]/g, 'l');
  r = r.replace(/[3]/g, 'e');
  r = r.replace(/[4@àáâãäå]/g, 'a');
  r = r.replace(/[5$]/g, 's');
  r = r.replace(/[7]/g, 't');
  r = r.replace(/[8]/g, 'b');
  r = r.replace(/[6]/g, 'g');
  r = r.replace(/[íìîï]/g, 'i');
  r = r.replace(/vv/g, 'w');
  return r;
};

export const hasSuspiciousUnicode = (host) => {
  for (let i = 0; i < (host || '').length; i++) {
    const c = host.charCodeAt(i);
    if (c > 0x7e || (c < 0x30 && c !== 0x2d && c !== 0x2e)) return true;
  }
  return false;
};

export const levenshtein = (a, b) => {
  if (a === b) return 0;
  const al = a.length, bl = b.length;
  if (al === 0) return bl;
  if (bl === 0) return al;
  let prev = new Array(bl + 1), curr = new Array(bl + 1);
  for (let j = 0; j <= bl; j++) prev[j] = j;
  for (let i = 1; i <= al; i++) {
    curr[0] = i;
    for (let j = 1; j <= bl; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[bl];
};

export const jaroWinkler = (a, b) => {
  a = (a || '').toLowerCase(); b = (b || '').toLowerCase();
  if (a === b) return 1;
  const al = a.length, bl = b.length;
  if (!al || !bl) return 0;
  const matchDistance = Math.floor(Math.max(al, bl) / 2) - 1;
  const aMatches = new Array(al).fill(false);
  const bMatches = new Array(bl).fill(false);
  let matches = 0;
  for (let i = 0; i < al; i++) {
    const start = Math.max(0, i - matchDistance);
    const end = Math.min(i + matchDistance + 1, bl);
    for (let j = start; j < end; j++) {
      if (bMatches[j] || a[i] !== b[j]) continue;
      aMatches[i] = true; bMatches[j] = true; matches++; break;
    }
  }
  if (!matches) return 0;
  let k = 0, transpositions = 0;
  for (let i = 0; i < al; i++) {
    if (!aMatches[i]) continue;
    while (!bMatches[k]) k++;
    if (a[i] !== b[k]) transpositions++;
    k++;
  }
  const jaro = ((matches / al) + (matches / bl) + ((matches - transpositions / 2) / matches)) / 3;
  let prefix = 0;
  for (let i = 0; i < Math.min(4, al, bl); i++) { if (a[i] === b[i]) prefix++; else break; }
  return jaro + prefix * 0.1 * (1 - jaro);
};
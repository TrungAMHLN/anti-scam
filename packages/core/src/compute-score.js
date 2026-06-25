// ============================================================
// @anti-scam/core — computeScore engine
// ============================================================
import { RISK_PTS, FINDING_CONFIDENCE, REPUTATION_WHITELIST } from './constants.js';
import { normalizeDomainAge } from './url.js';
import { analyzeUrl, analyzeRedirectChain, getTrustContext } from './analyze-url.js';
import { isOfficialBrandDomain } from './url.js';

export const computeScore = (urlString, context = {}) => {
  const ctx = context || {};
  const dom = ctx.dom || {};
  const domainAgeInfo = normalizeDomainAge(ctx.domainAge || ctx.domainAgeDetails || ctx.domainAgeDays);
  const domainAgeDays = domainAgeInfo.ageDays != null ? domainAgeInfo.ageDays : -1;
  const rep = ctx.reputation || { checked: false };
  const trustContext = getTrustContext(urlString, rep, domainAgeDays);
  const redirectChain = ctx.redirectChain || [];
  const stabilityMs = ctx.stabilityMs || 0;

  const urlPart = analyzeUrl(urlString);
  const findings = urlPart.findings.slice();
  const matchedBrand = urlPart.matchedBrand || dom.matchedBrand;

  if (domainAgeDays >= 0 && domainAgeDays < 7) {
    findings.push({ key: 'NewDomain', label: 'Website mới được đăng ký gần đây.', points: RISK_PTS.NEW_DOMAIN_7, group: 'domain', decays: false });
  } else if (domainAgeDays >= 0 && domainAgeDays < 30) {
    findings.push({ key: 'NewDomain', label: 'Website mới được đăng ký gần đây.', points: RISK_PTS.NEW_DOMAIN_30, group: 'domain', decays: false });
  }

  const malwareSources = rep.malware && Array.isArray(rep.malware.sources) ? rep.malware.sources.length :
    (rep.malware && rep.malware.maliciousSources ? rep.malware.maliciousSources : 0);
  if (rep.malware && (rep.malware.dangerous || malwareSources > 0)) {
    findings.push({ key: 'MalwareReputation', label: 'Bị nhiều nguồn cảnh báo nguy hiểm.', points: Math.min(70, RISK_PTS.MALWARE_REPUTATION + Math.max(0, malwareSources - 1) * 8), group: 'reputation', decays: false });
  }
  if (rep.dns && rep.dns.riskyInfrastructure) {
    findings.push({ key: 'DNSRisk', label: 'Hạ tầng DNS/hosting có lịch sử rủi ro.', points: RISK_PTS.DNS_RISK, group: 'dns', decays: false });
  }
  const reportCount = rep.communityReports || (rep.community && rep.community.count) || 0;
  if (reportCount >= 3) {
    findings.push({ key: 'CommunityReport', label: 'Website đã bị cộng đồng báo cáo nhiều lần.', points: RISK_PTS.COMMUNITY_REPORT + Math.min(12, reportCount), group: 'community', decays: false });
  }

  // DOM findings
  if (dom.brandInContent) {
    const surfaces = dom.brandSurfaces || 1;
    const strong = surfaces >= 2;
    const lbl = matchedBrand
      ? `Trang dùng logo/tiêu đề thương hiệu ${matchedBrand} nhưng tên miền không chính thức`
      : 'Trang hiển thị thương hiệu quen thuộc nhưng tên miền không chính thức';
    findings.push({ key: 'BrandImpersonation', label: lbl,
      points: strong ? RISK_PTS.BRAND_IMPERSONATION_STRONG : RISK_PTS.BRAND_IMPERSONATION_WEAK,
      group: 'brand', decays: false });
  }
  if (dom.formHijack) findings.push({ key: 'FormHijack', label: 'Biểu mẫu gửi thông tin sang một tên miền khác lạ', points: RISK_PTS.FORM_HIJACK, group: 'form', decays: false });
  if (dom.obfuscatedScript) findings.push({ key: 'ObfuscatedScript', label: 'Trang web chứa mã JavaScript đáng ngờ.', points: RISK_PTS.OBFUSCATION, group: 'obfuscation', decays: false });
  if (dom.jsRiskScore >= 35 && !dom.obfuscatedScript) findings.push({ key: 'JavaScriptRisk', label: 'Trang web chứa mã JavaScript đáng ngờ.', points: RISK_PTS.JS_RISK, group: 'obfuscation', decays: false });
  if (dom.suspiciousExternalScript) findings.push({ key: 'SuspiciousExternal', label: 'Tải mã từ nguồn không phổ biến / địa chỉ IP', points: RISK_PTS.SUSPICIOUS_EXT_IP, group: 'external', decays: false });
  if (dom.keylogger) findings.push({ key: 'Keylogger', label: 'Có dấu hiệu theo dõi thao tác gõ phím', points: RISK_PTS.KEYLOGGER, group: 'malware', decays: false });
  if (dom.clipboardHijack) findings.push({ key: 'ClipboardHijack', label: 'Có dấu hiệu can thiệp bộ nhớ tạm (clipboard)', points: RISK_PTS.CLIPBOARD, group: 'malware', decays: false });
  if (dom.downloadFile) findings.push({ key: 'DangerousDownload', label: 'Trang yêu cầu tải file có thể gây hại.', points: RISK_PTS.DOWNLOAD, group: 'download', decays: false });
  if (dom.archiveDownload && !rep.inWhitelist && !rep.isOfficialBrand) findings.push({ key: 'ArchiveDownload', label: 'Trang có liên kết tải file nén; cần thận trọng nếu nguồn không quen thuộc.', points: RISK_PTS.ARCHIVE_DOWNLOAD, group: 'download', decays: true });
  if (dom.suspiciousLinkCount > 0) findings.push({ key: 'SuspiciousLinks', label: `Trang chứa ${dom.suspiciousLinkCount} liên kết có dấu hiệu nguy hiểm hoặc lừa đảo.`, points: Math.min(32, RISK_PTS.LINK_RISK + (dom.suspiciousLinkCount - 1) * 3), group: 'links', decays: false });
  if (dom.deceptiveLinkCount > 0) findings.push({ key: 'DeceptiveLinks', label: `Trang có ${dom.deceptiveLinkCount} liên kết hiển thị một miền nhưng trỏ sang miền khác.`, points: Math.min(28, RISK_PTS.DECEPTIVE_LINK + (dom.deceptiveLinkCount - 1) * 2), group: 'links', decays: false });
  if (dom.metaRefreshRedirect) findings.push({ key: 'MetaRefreshRedirect', label: 'Trang dùng meta refresh để chuyển hướng sang tên miền khác.', points: RISK_PTS.META_REFRESH, group: 'redirect', decays: true });
  if (dom.scriptRedirect) findings.push({ key: 'ScriptRedirect', label: 'Trang có mã JavaScript chuyển hướng sang URL ngoài.', points: RISK_PTS.SCRIPT_REDIRECT, group: 'redirect', decays: true });
  if (dom.permissionAbuse && !rep.inWhitelist && !rep.isOfficialBrand) {
    const reqs = Array.isArray(dom.permissionRequests) ? dom.permissionRequests.join(', ') : 'quyền nhạy cảm';
    const strongReqs = (dom.permissionRequests || []).filter(x => !String(x).startsWith('permissions-'));
    const pts = strongReqs.length ? RISK_PTS.PERMISSION_ABUSE + Math.max(0, strongReqs.length - 1) * 3 : 6;
    findings.push({ key: 'PermissionAbuse', label: `Trang gọi hoặc yêu cầu quyền nhạy cảm: ${reqs}.`, points: Math.min(30, pts), group: 'permission', decays: false });
  }
  if (dom.redirectBadHop) findings.push({ key: 'RedirectBadHop', label: 'Chuỗi chuyển hướng đi qua URL nằm trong danh sách cảnh báo.', points: RISK_PTS.COMMUNITY_REPORT, group: 'redirect', decays: false });
  if (dom.hiddenForm && (dom.sensitiveForm || dom.passwordField || dom.otpField)) findings.push({ key: 'HiddenForm', label: 'Trang có biểu mẫu nhạy cảm bị ẩn.', points: RISK_PTS.HIDDEN_FORM, group: 'form', decays: false });
  if (dom.scamContentRisk >= 2) findings.push({ key: 'ScamContent', label: 'Nội dung có dấu hiệu kêu gọi lừa đảo.', points: Math.min(28, RISK_PTS.SCAM_CONTENT + (dom.scamContentRisk - 2) * 4), group: 'content', decays: true });
  if (dom.iframeRiskScore > 0) {
    const detail = dom.iframeDetails && dom.iframeDetails[0];
    const lbl = detail
      ? `Khung trang (iFrame) đáng ngờ: ${detail.reasons.join(', ')}`
      : 'Phát hiện khung trang ẩn (iFrame vô hình)';
    const pts = Math.min(Math.round(dom.iframeRiskScore * 0.5), 35);
    findings.push({ key: 'iFrames', label: lbl, points: pts, group: 'malware', decays: false });
  }
  if (dom.networkUploadToExternal) findings.push({ key: 'DataExfil', label: 'Có dấu hiệu gửi dữ liệu ra tên miền lạ', points: RISK_PTS.KEYLOGGER, group: 'malware', decays: false });
  if (dom.hasUntrustedFormDest && (dom.sensitiveForm || dom.passwordField || dom.otpField)) {
    const dests = dom.formDestinations || [];
    findings.push({ key: 'FormDest', label: `Biểu mẫu gửi dữ liệu đến ${dests.length > 1 ? dests.length + ' tên miền lạ' : 'tên miền lạ'}`, points: RISK_PTS.FORM_HIJACK, group: 'form', decays: false });
  }

  const rc = analyzeRedirectChain(redirectChain);
  if (rc.points > 0 && rc.label) {
    findings.push({ key: rc.openRedirects && rc.openRedirects.length ? 'OpenRedirect' : 'RedirectChain', label: rc.label, points: rc.points, group: 'redirect', decays: true });
  }

  if (dom.sfh === '0' && (dom.sensitiveForm || dom.passwordField || dom.otpField)) {
    findings.push({ key: 'SFH', label: 'Biểu mẫu nhập liệu không chỉ rõ nơi nhận dữ liệu', points: 8, group: 'form', decays: true });
  }

  const isReputableSite = trustContext === 'HIGH_TRUST';
  const confirmedDanger = !!(rep.inBlacklist || (rep.malware && rep.malware.dangerous));
  const TIER_A = new Set(['MalwareReputation', 'CommunityReport', 'RedirectBadHop']);
  const TIER_B = new Set(['BrandImpersonation', 'Homograph', 'Typosquat', 'BrandInDomain', 'FormHijack', 'FormDest', 'DangerousDownload', 'Keylogger', 'DataExfil', 'OpenRedirect']);
  for (const f of findings) {
    f.baseWeight = f.points || 0;
    f.tier = TIER_A.has(f.key) ? 'A' : (TIER_B.has(f.key) ? 'B' : 'C');
    f.confidence = FINDING_CONFIDENCE[f.key] != null ? FINDING_CONFIDENCE[f.key] : (f.tier === 'A' ? 0.95 : (f.tier === 'B' ? 0.75 : 0.2));
    f.riskContribution = f.baseWeight * f.confidence;
    f.points = f.riskContribution;
    if (trustContext === 'HIGH_TRUST' && !confirmedDanger && f.tier === 'C') {
      f.points *= 0.2;
      f.decays = true;
    } else if (trustContext === 'MEDIUM_TRUST' && !confirmedDanger && f.tier === 'C') {
      f.points *= 0.5;
      f.decays = true;
    }
    if (isReputableSite && !confirmedDanger && ['ArchiveDownload', 'PermissionAbuse', 'SuspiciousExternal', 'JavaScriptRisk', 'ObfuscatedScript', 'iFrames'].includes(f.key)) {
      f.points = 0;
    }
  }

  const groupMax = { 'brand': 45, 'brand-path': 10, 'punycode': 15, 'form': 45, 'malware': 45,
    'obfuscation': 14, 'external': 8, 'download': 32, 'vn-scam': 18, 'redirect': 35, 'misc': 8,
    'domain': 18, 'reputation': 85, 'dns': 18, 'community': 35, 'content': 18, 'links': 24, 'permission': 16 };
  const byGroup = {};
  for (const f of findings) byGroup[f.group] = (byGroup[f.group] || 0) + f.points;
  let baseRisk = 0;
  for (const g in byGroup) baseRisk += Math.min(byGroup[g], groupMax[g] != null ? groupMax[g] : 25);

  const has = (g) => (byGroup[g] || 0) > 0;
  const hasBrand = has('brand') || has('brand-path');
  const hasMalware = has('malware');
  const hasObf = has('obfuscation') || has('external');
  const hasVnScam = has('vn-scam');
  const hasRedirect = has('redirect');
  const hasLinks = has('links');
  const hasPermission = has('permission');
  const hasReputationDanger = has('reputation');
  const hasContentScam = has('content');

  const veryNew = domainAgeDays >= 0 && domainAgeDays < 7;
  const young = domainAgeDays >= 0 && domainAgeDays < 30;
  const noRep = !rep.inWhitelist && !rep.isOfficialBrand;

  let bonus = 0;
  const reasons = [];

  if (dom.passwordField || dom.otpField) {
    if (hasBrand) {
      bonus += 25;
      reasons.push(matchedBrand
        ? `Trang yêu cầu nhập mật khẩu/OTP và có dấu hiệu giả mạo thương hiệu ${matchedBrand}.`
        : 'Trang yêu cầu nhập mật khẩu/OTP và có dấu hiệu giả mạo thương hiệu.');
    } else if (veryNew && noRep) {
      bonus += 12;
      reasons.push('Tên miền mới đăng ký yêu cầu nhập mật khẩu/OTP mà chưa có uy tín.');
    }
  }
  if (dom.formHijack && dom.passwordField) { bonus += 15; }
  if (hasBrand && young) { bonus += 18; reasons.push('Tên miền vừa mới đăng ký lại có dấu hiệu giả mạo thương hiệu.'); }
  if (hasObf && (dom.passwordField || dom.otpField)) { bonus += 14; reasons.push('Trang vừa yêu cầu nhập mật khẩu vừa dùng mã bị làm rối.'); }
  if (hasMalware && (dom.passwordField || hasBrand || young)) { bonus += 16; reasons.push('Trang có dấu hiệu mã độc đi kèm các yếu tố đáng ngờ khác.'); }
  if (hasVnScam && (dom.passwordField || dom.otpField)) { bonus += 15; reasons.push('URL chứa từ khoá "xác minh/định danh/OTP" và trang yêu cầu nhập thông tin nhạy cảm.'); }
  if (hasRedirect && hasBrand) { bonus += 15; reasons.push('Chuỗi chuyển hướng phức tạp kết hợp giả mạo thương hiệu.'); }
  if (hasLinks && (hasBrand || hasRedirect || veryNew)) { bonus += 10; reasons.push('Trang chứa liên kết đáng ngờ đi kèm các tín hiệu rủi ro khác.'); }
  if (hasPermission && (hasBrand || dom.sensitiveForm || veryNew)) { bonus += 10; reasons.push('Trang yêu cầu quyền nhạy cảm trong ngữ cảnh đáng ngờ.'); }
  if (hasContentScam && (veryNew || hasBrand || dom.sensitiveForm)) { bonus += 12; reasons.push('Nội dung kêu gọi lợi nhuận/nhận thưởng đi kèm dấu hiệu đáng ngờ khác.'); }
  if (hasReputationDanger) { bonus += 10; reasons.push('URL hoặc tên miền bị nguồn uy tín cảnh báo nguy hiểm.'); }

  let riskScore = Math.min(100, Math.round(baseRisk + bonus));

  if (bonus > 0 && findings.length === 0 && reasons.length > 0) {
    findings.push({ key: 'ContextRisk', label: reasons[0], points: bonus, group: 'context', decays: true });
  }

  if (dom.websocket && riskScore >= 20) riskScore = Math.min(100, riskScore + 5);

  if (stabilityMs > 20000 && riskScore > 0 && !rep.inBlacklist) {
    const softRisk = findings.filter(f => f.decays).reduce((s, f) => s + f.points, 0);
    const hardRisk = riskScore - Math.min(softRisk, 25);
    const decay = Math.max(0.5, 1 - stabilityMs / 240000);
    riskScore = Math.round(hardRisk + Math.min(softRisk, 25) * decay);
    riskScore = Math.max(hardRisk, riskScore);
  }

  let trustScore = 0;
  const trustBadges = [];
  if (domainAgeDays >= 0) {
    if (domainAgeDays > 730) { trustScore += 38; trustBadges.push({ key: 'EstablishedDomain', label: 'Website đã tồn tại nhiều năm.' }); }
    else if (domainAgeDays > 365) { trustScore += 30; trustBadges.push({ key: 'EstablishedDomain', label: 'Website đã tồn tại nhiều năm.' }); }
    else if (domainAgeDays > 90) { trustScore += 18; trustBadges.push({ key: 'EstablishedDomain', label: 'Tên miền đã hoạt động vài tháng.' }); }
    else if (domainAgeDays > 30) { trustScore += 8; }
  }
  if (rep.inWhitelist) { trustScore += 20; trustBadges.push({ key: 'ReputationVerified', label: 'Website nằm trong danh sách tin cậy.' }); }
  if (rep.isOfficialBrand) { trustScore += 15; trustBadges.push({ key: 'OfficialBrand', label: 'Tên miền chính thức của thương hiệu lớn.' }); }
  if (/^https:/.test(urlString || '')) { trustScore += 3; trustBadges.push({ key: 'SSL', label: 'Website sử dụng kết nối HTTPS.' }); }
  if (rep.trustedCdnOnly !== false && dom.scanned && !dom.suspiciousExternalScript) {
    trustBadges.push({ key: 'TrustedResources', label: 'Tài nguyên đến từ nguồn phổ biến.' });
  }
  if (dom.scanned && !dom.sensitiveForm && !dom.passwordField && !dom.otpField && !dom.formHijack) {
    trustBadges.push({ key: 'NoPhishingForm', label: 'Không phát hiện biểu mẫu đánh cắp thông tin.' });
  }
  trustScore = Math.min(trustScore, 45);

  if (rep.inBlacklist) { riskScore = Math.max(riskScore, 90); trustScore = 0; }

  if (!rep.inBlacklist && dom.scanned && trustScore < 32) {
    if (riskScore === 0) {
      trustScore = Math.max(trustScore, 32);
    } else if (riskScore < 8) {
      trustScore = Math.max(trustScore, 24);
    }
  }

  let confidence = 0;
  if (domainAgeDays >= 0) confidence += 30;
  if (rep.checked) confidence += 25;
  if (dom.scanned) confidence += 25;
  if (redirectChain.length > 0) confidence += 10;
  if (dom.contentRich) confidence += 10;
  confidence = Math.min(confidence, 100);
  if (rep.inWhitelist || rep.isOfficialBrand) confidence = Math.max(confidence, 80);

  let finalScore = Math.round(Math.max(0, Math.min(100, 50 + trustScore - riskScore)));
  if (rep.inBlacklist || (rep.malware && rep.malware.dangerous)) finalScore = Math.min(finalScore, 10);
  const hasHighImpactRisk = findings.some(f => f.points >= 12 && (f.tier === 'A' || f.tier === 'B'));
  if (!confirmedDanger && trustContext === 'HIGH_TRUST' && !hasHighImpactRisk) finalScore = Math.max(finalScore, 90);
  if (!confirmedDanger && trustContext === 'MEDIUM_TRUST' && domainAgeDays > 365 && /^https:/i.test(urlString || '') && riskScore < 12) finalScore = Math.max(finalScore, 85);
  if (!confirmedDanger && trustContext === 'LOW_TRUST' && !hasHighImpactRisk && riskScore <= 15 && /^https:/i.test(urlString || '')) finalScore = Math.max(finalScore, 55);
  const isUnknown = confidence < 45;
  if (isUnknown) {
    let cap;
    if (riskScore === 0) cap = 75;
    else if (riskScore < 10) cap = 65;
    else if (riskScore < 20) cap = 55;
    else cap = 45;
    if (finalScore > cap) finalScore = cap;
    if (finalScore < 25) finalScore = 25;
  }
  const isPhish = finalScore <= 30;

  const result = {};
  for (const tb of trustBadges) result[tb.key] = '-1';
  for (const f of findings) {
    if (result[f.key] !== undefined) continue;
    let value;
    if (f.points >= 22 || (f.group === 'brand' && riskScore >= 35) || f.key === 'FormHijack' || f.key === 'MalwareReputation')
      value = '1';
    else if (f.points >= 14 || (f.group === 'malware' && riskScore >= 25))
      value = '2';
    else if (f.points >= 7)
      value = '0';
    else
      value = '0';
    if ((f.points || 0) <= 2) value = '-1';
    if (['NoHTTPS', 'AtSymbol', 'LongURL', 'SuspiciousTLD', 'IPHost'].includes(f.key) && riskScore < 22) value = '-1';
    result[f.key] = value;
  }
  if (dom.sensitiveForm) {
    if (rep.inWhitelist || rep.isOfficialBrand) result['Sensitive Form'] = '-1';
    else if (hasBrand || dom.formHijack) result['Sensitive Form'] = '1';
    else if (veryNew && noRep) result['Sensitive Form'] = '2';
    else result['Sensitive Form'] = '0';
  }

  const explanations = [];
  const pushReason = (level, text, key) => {
    if (!text) return;
    const clean = text.replace(/\s+/g, ' ').trim().replace(/\.+$/, '.');
    if (explanations.some(e => e.text === clean)) return;
    explanations.push({ level, text: clean, key });
  };
  for (const tb of trustBadges) pushReason('safe', tb.label, tb.key);
  const sortedFindings = findings.slice().sort((a, b) => b.points - a.points);
  for (const f of sortedFindings) {
    if ((f.points || 0) <= 2) continue;
    const level = (f.points >= 22 || f.key === 'MalwareReputation') ? 'danger' : (f.points >= 14 ? 'suspicious' : 'warning');
    pushReason(level, f.label, f.key);
    if (explanations.filter(e => e.level !== 'safe').length >= 6) break;
  }

  let summary;
  const firstDanger = explanations.find(e => e.level === 'danger' || e.level === 'suspicious');
  const firstSafe = explanations.find(e => e.level === 'safe');
  if (isUnknown) {
    summary = 'Chưa đủ dữ liệu để đánh giá chính xác độ tin cậy. Hãy thận trọng khi nhập thông tin.';
  } else if (riskScore >= 55) {
    summary = 'Nguy cơ lừa đảo hoặc mã độc cao. ' + (firstDanger ? firstDanger.text : 'Phát hiện nhiều dấu hiệu nguy hiểm.');
  } else if (riskScore >= 30) {
    summary = 'Website có dấu hiệu đáng ngờ. ' + (firstDanger ? firstDanger.text : 'Nên kiểm tra kỹ trước khi nhập thông tin.');
  } else if (riskScore > 0 && firstDanger) {
    summary = 'Website nhìn chung chưa có bằng chứng nguy hiểm mạnh, nhưng cần chú ý. ' + firstDanger.text;
  } else if (firstSafe) {
    summary = firstSafe.text;
  } else {
    summary = 'Không phát hiện dấu hiệu giả mạo, mã độc hoặc thu thập dữ liệu nhạy cảm.';
  }

  const riskLevel = finalScore <= 20 ? 'critical' : finalScore <= 35 ? 'dangerous' :
    finalScore <= 55 ? 'suspicious' : finalScore <= 75 ? 'caution' : 'safe';

  return {
    finalScore, trustScore, riskScore, confidence, isUnknown, isPhish,
    summary, result, findings, explanations, domainAge: domainAgeInfo,
    matchedBrand, riskLevel, redirectHops: rc.hops, trustContext,
  };
};

export const assessRisk = (urlString, domSignals = {}, domainAgeDays = -1) => {
  const r = computeScore(urlString, { dom: domSignals || {}, domainAgeDays });
  return {
    riskScore: r.riskScore, riskLevel: r.riskLevel,
    findings: Object.entries(r.result).map(([key, value]) => ({ key, label: key, value })),
    summary: r.summary, matchedBrand: r.matchedBrand,
  };
};

export const computeHeuristicScore = (urlString) => {
  const r = computeScore(urlString, {});
  return { score: r.riskScore, flags: [], riskLevel: r.riskLevel };
};

// ─── Quick / Live scan variants ────────────────────────────────────────────

export const buildQuickScanSummary = (assessment) => {
  const { riskScore, isUnknown, findings } = assessment;
  const hasCritical = (findings || []).some(f =>
    ['MalwareReputation','CommunityReport','Homograph','Typosquat','BrandInDomain',
     'FormHijack','DangerousDownload','OpenRedirect'].includes(f.key)
  );
  if (hasCritical || riskScore >= 55) {
    const firstDanger = (findings || []).slice().sort((a,b)=>b.points-a.points).find(f => f.points >= 14);
    return `Phát hiện nguy cơ rõ ràng từ phân tích URL/domain. ${ firstDanger ? firstDanger.label : 'Hãy thận trọng.' }`;
  }
  if (riskScore >= 30) return `Có dấu hiệu đáng ngờ từ phân tích sơ bộ. Chưa phân tích hành vi thực tế của website.`;
  if (isUnknown) return `Chưa đủ dữ liệu để đánh giá. Đây là phân tích sơ bộ — chưa kiểm tra JavaScript và hành vi website.`;
  return `Chưa phát hiện nguy cơ rõ ràng từ URL và domain. Đây là đánh giá sơ bộ — chưa phân tích hành vi thực tế của website.`;
};

export const buildLiveScanSummary = (assessment) => assessment.summary;

/**
 * Quick Scan — Static Analysis only (Custom URL Scan, fetch-based, no real tab)
 * Confidence capped at 50% — no real DOM/behavior signals.
 */
export const computeQuickScore = (urlString, ctx = {}) => {
  const result = computeScore(urlString, ctx);
  return {
    ...result,
    stage: 'QUICK',
    confidence: Math.min(result.confidence, 50),
    summary: buildQuickScanSummary(result),
  };
};

/**
 * Live Scan — Dynamic Analysis (user visits a real tab, content script injected)
 * Full confidence, more accurate summary.
 */
export const computeLiveScore = (urlString, ctx = {}) => {
  const result = computeScore(urlString, ctx);
  return {
    ...result,
    stage: 'LIVE',
    summary: buildLiveScanSummary(result),
  };
};
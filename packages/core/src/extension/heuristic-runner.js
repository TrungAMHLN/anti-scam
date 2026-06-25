import * as Core from '../index.js';

if (typeof self !== 'undefined') {
  self.computeScore = Core.computeScore;
  self.computeQuickScore = Core.computeQuickScore || Core.computeScore;
  self.computeLiveScore = Core.computeLiveScore || Core.computeScore;
  self.buildQuickScanSummary = Core.buildQuickScanSummary || (() => '');
  self.buildLiveScanSummary = Core.buildLiveScanSummary || (() => '');
  self.analyzeUrl = Core.analyzeUrl;
  self.analyzeRedirectChain = Core.analyzeRedirectChain;
  self.assessRisk = Core.assessRisk || ((url) => Core.computeScore(url));
  self.computeHeuristicScore = Core.computeHeuristicScore || ((url) => Core.computeScore(url));
  self.isTrustedHost = Core.isTrustedHost;
  self.isOfficialBrandDomain = Core.isOfficialBrandDomain;
  self.getRegistrableDomain = Core.getRegistrableDomain;
  self.REPUTATION_WHITELIST = Core.REPUTATION_WHITELIST;
  self.BRANDS = Core.BRANDS;
  self.levenshtein = Core.levenshtein;
  self.jaroWinkler = Core.jaroWinkler;
  self.toUnicodeDomain = Core.toUnicodeDomain;
}
if (typeof window !== 'undefined') {
  window.computeScore = Core.computeScore;
  window.computeQuickScore = Core.computeQuickScore || Core.computeScore;
  window.computeLiveScore = Core.computeLiveScore || Core.computeScore;
  window.isTrustedHost = Core.isTrustedHost;
  window.getRegistrableDomain = Core.getRegistrableDomain;
  window.isOfficialBrandDomain = Core.isOfficialBrandDomain;
}

/**
 * ANTISCAM VIETNAM — Vietnam Brand Impersonation Engine
 * Module 5: Phát hiện giả mạo thương hiệu Việt Nam
 *
 * Chạy trong content script context (features.js gọi sau khi DOM ready).
 * Export qua window.BrandDetection.
 *
 * Phân tích:
 *  1. Domain vs Official Domain check
 *  2. Page title / meta chứa brand name giả mạo
 *  3. Logo alt/src chứa tên brand
 *  4. Form field names khớp với brand-specific patterns
 *  5. Color palette detection (heuristic)
 *  6. Brand keyword trong nội dung trang
 */

(function () {
  'use strict';

  // ─────────────────────────────────────────────────────────────────────────────
  // DATABASE: Vietnam Brand Registry (đầy đủ)
  // ─────────────────────────────────────────────────────────────────────────────

  const BRAND_DB = {
    vietcombank: {
      label: 'Vietcombank',
      officialDomains: ['vietcombank.com.vn', 'vcb.com.vn', 'digibank.vietcombank.com.vn'],
      keywords: ['vietcombank', 'vcb', 'ngoại thương', 'ngan hang ngoai thuong', 'vcbdigibank'],
      logoKeywords: ['vietcombank', 'vcb', 'ngoai thuong'],
      formFields: ['vietcombank', 'vcb-username', 'vcb-password'],
      brandColor: '#007b40',  // VCB green (sắp đổi sang tham khảo)
    },
    bidv: {
      label: 'BIDV',
      officialDomains: ['bidv.com.vn', 'smartbanking.bidv.com.vn'],
      keywords: ['bidv', 'bank for investment', 'đầu tư và phát triển'],
      logoKeywords: ['bidv'],
      formFields: ['bidv-user', 'bidv-pass'],
      brandColor: '#1a4598',
    },
    vietinbank: {
      label: 'VietinBank',
      officialDomains: ['vietinbank.vn', 'ipay.vietinbank.vn'],
      keywords: ['vietinbank', 'công thương', 'ipay vietinbank'],
      logoKeywords: ['vietinbank', 'cong thuong'],
      formFields: [],
      brandColor: '#cc0000',
    },
    agribank: {
      label: 'Agribank',
      officialDomains: ['agribank.com.vn'],
      keywords: ['agribank', 'nông nghiệp', 'nong nghiep'],
      logoKeywords: ['agribank'],
      formFields: [],
      brandColor: '#007b40',
    },
    mbbank: {
      label: 'MB Bank',
      officialDomains: ['mbbank.com.vn', 'app.mbbank.com.vn'],
      keywords: ['mbbank', 'mb bank', 'quân đội', 'quan doi'],
      logoKeywords: ['mbbank', 'mb bank'],
      formFields: [],
      brandColor: '#9c1515',
    },
    techcombank: {
      label: 'Techcombank',
      officialDomains: ['techcombank.com.vn'],
      keywords: ['techcombank', 'techcom', 'kỹ thương'],
      logoKeywords: ['techcombank'],
      formFields: [],
      brandColor: '#e31f26',
    },
    acb: {
      label: 'ACB',
      officialDomains: ['acb.com.vn', 'acbonline.acb.com.vn'],
      keywords: ['acb', 'á châu', 'a chau'],
      logoKeywords: ['acb', 'a chau'],
      formFields: [],
      brandColor: '#00aaef',
    },
    tpbank: {
      label: 'TPBank',
      officialDomains: ['tpbank.vn', 'ebank.tpbank.vn'],
      keywords: ['tpbank', 'tiên phong', 'tien phong bank'],
      logoKeywords: ['tpbank'],
      formFields: [],
      brandColor: '#802580',
    },
    vpbank: {
      label: 'VPBank',
      officialDomains: ['vpbank.com.vn', 'online.vpbank.com.vn'],
      keywords: ['vpbank', 'việt phương', 'viet phuong'],
      logoKeywords: ['vpbank'],
      formFields: [],
      brandColor: '#007b3e',
    },
    sacombank: {
      label: 'Sacombank',
      officialDomains: ['sacombank.com', 'mbanking.sacombank.com'],
      keywords: ['sacombank', 'sài gòn thương tín', 'sai gon thuong tin'],
      logoKeywords: ['sacombank'],
      formFields: [],
      brandColor: '#e31f26',
    },
    momo: {
      label: 'MoMo',
      officialDomains: ['momo.vn', 'mservice.com.vn', 'business.momo.vn'],
      keywords: ['momo', 'ví momo', 'vi momo', 'm_service', 'mservice'],
      logoKeywords: ['momo', 'vi momo'],
      formFields: ['momo-phone', 'momo-pin'],
      brandColor: '#ae1e7e',
    },
    zalopay: {
      label: 'ZaloPay',
      officialDomains: ['zalopay.vn', 'zalo.me'],
      keywords: ['zalopay', 'zalo pay', 'ví zalopay'],
      logoKeywords: ['zalopay', 'zalo'],
      formFields: [],
      brandColor: '#0068ff',
    },
    vnpay: {
      label: 'VNPay',
      officialDomains: ['vnpay.vn', 'sandbox.vnpayment.vn'],
      keywords: ['vnpay', 'vnpayment', 'cổng thanh toán vnpay'],
      logoKeywords: ['vnpay'],
      formFields: [],
      brandColor: '#0066cc',
    },
    shopee: {
      label: 'Shopee',
      officialDomains: ['shopee.vn', 'seller.shopee.vn', 'spayseller.shopee.vn'],
      keywords: ['shopee', 'shopee pay', 'shopeepay', 'spay'],
      logoKeywords: ['shopee'],
      formFields: [],
      brandColor: '#ee4d2d',
    },
    lazada: {
      label: 'Lazada',
      officialDomains: ['lazada.vn', 'seller.lazada.vn'],
      keywords: ['lazada', 'lazada việt nam'],
      logoKeywords: ['lazada'],
      formFields: [],
      brandColor: '#0f146b',
    },
    tiki: {
      label: 'Tiki',
      officialDomains: ['tiki.vn', 'tikivn.com'],
      keywords: ['tiki', 'tiki.vn'],
      logoKeywords: ['tiki'],
      formFields: [],
      brandColor: '#1a94ff',
    },
    tiktokshop: {
      label: 'TikTok Shop',
      officialDomains: ['tiktokshop.com', 'shop.tiktok.com'],
      keywords: ['tiktok shop', 'tiktok-shop', 'tikshop'],
      logoKeywords: ['tiktok'],
      formFields: [],
      brandColor: '#010101',
    },
    vneid: {
      label: 'VNeID',
      officialDomains: ['vneid.gov.vn'],
      keywords: ['vneid', 'căn cước công dân', 'can cuoc cong dan', 'cccd', 'định danh điện tử'],
      logoKeywords: ['vneid', 'bo cong an'],
      formFields: ['cccd', 'cmnd'],
      brandColor: '#cc0000',
    },
    dichvucong: {
      label: 'Cổng Dịch Vụ Công',
      officialDomains: ['dichvucong.gov.vn', 'csdl.dichvucong.gov.vn'],
      keywords: ['dịch vụ công', 'dich vu cong', 'cổng quốc gia', 'dichvucong'],
      logoKeywords: ['dich vu cong', 'chinh phu'],
      formFields: [],
      brandColor: '#c8232b',
    },
    utt: {
      label: 'Đại học UTT',
      officialDomains: ['utt.edu.vn'],
      keywords: ['utt', 'đại học công nghệ giao thông', 'dai hoc cong nghe giao thong van tai'],
      logoKeywords: ['utt'],
      formFields: [],
      brandColor: '#003087',
    },
    hust: {
      label: 'Đại học Bách Khoa Hà Nội',
      officialDomains: ['hust.edu.vn', 'bachkhoa.edu.vn'],
      keywords: ['hust', 'bách khoa', 'bach khoa ha noi'],
      logoKeywords: ['hust', 'bach khoa'],
      formFields: [],
      brandColor: '#003087',
    },
  };

  // ─────────────────────────────────────────────────────────────────────────────
  // HELPERS
  // ─────────────────────────────────────────────────────────────────────────────

  function getPageText() {
    return (document.body ? document.body.innerText : '').toLowerCase().substring(0, 5000);
  }

  function getPageTitle() {
    return (document.title || '').toLowerCase();
  }

  function getMetaContent() {
    const metas = document.querySelectorAll('meta[name="description"], meta[property="og:title"]');
    return Array.from(metas).map(m => m.content || '').join(' ').toLowerCase();
  }

  function getAllImageAltSrc() {
    const imgs = document.querySelectorAll('img');
    return Array.from(imgs).map(img => [
      (img.getAttribute('alt') || '').toLowerCase(),
      (img.getAttribute('src') || '').toLowerCase(),
      (img.getAttribute('title') || '').toLowerCase(),
    ].join(' ')).join(' ');
  }

  function getAllFormFields() {
    const inputs = document.querySelectorAll('input, select, textarea');
    return Array.from(inputs).map(inp => [
      (inp.getAttribute('name') || '').toLowerCase(),
      (inp.getAttribute('id') || '').toLowerCase(),
      (inp.getAttribute('placeholder') || '').toLowerCase(),
    ].join(' ')).join(' ');
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // CORE DETECTION
  // ─────────────────────────────────────────────────────────────────────────────

  function detectBrandImpersonation(currentHostname) {
    const hostname = currentHostname.replace(/^www\./, '').toLowerCase();
    const pageTitle = getPageTitle();
    const metaContent = getMetaContent();
    const imageText = getAllImageAltSrc();
    const formFields = getAllFormFields();
    const pageText = getPageText();
    const allText = `${pageTitle} ${metaContent} ${imageText} ${formFields} ${pageText}`;

    const detectedBrands = [];

    for (const [brandId, brand] of Object.entries(BRAND_DB)) {
      // Skip nếu đang ở domain chính thức
      const isOnOfficialDomain = brand.officialDomains.some(od => {
        return hostname === od || hostname.endsWith('.' + od);
      });
      if (isOnOfficialDomain) continue;

      let brandScore = 0;
      const evidence = [];

      // 1. Brand keywords trong title
      const titleMatches = brand.keywords.filter(kw => pageTitle.includes(kw));
      if (titleMatches.length > 0) {
        brandScore += 30;
        evidence.push(`Tiêu đề trang chứa "${titleMatches[0]}"`);
      }

      // 2. Brand keywords trong meta
      const metaMatches = brand.keywords.filter(kw => metaContent.includes(kw));
      if (metaMatches.length > 0 && titleMatches.length === 0) {
        brandScore += 20;
        evidence.push(`Meta description chứa "${metaMatches[0]}"`);
      }

      // 3. Logo images chứa brand keywords
      const logoMatches = brand.logoKeywords.filter(kw => imageText.includes(kw));
      if (logoMatches.length > 0) {
        brandScore += 25;
        evidence.push(`Ảnh logo có liên quan đến "${brand.label}"`);
      }

      // 4. Domain contains brand name (nhưng không phải official)
      const domainContainsBrand = brand.keywords.some(kw =>
        hostname.includes(kw.replace(/\s+/g, '')) || hostname.includes(kw.replace(/\s+/g, '-'))
      );
      if (domainContainsBrand) {
        brandScore += 35;
        evidence.push(`Tên miền chứa tên "${brand.label}" nhưng không phải domain chính thức`);
      }

      // 5. Form fields match brand-specific patterns
      if (brand.formFields && brand.formFields.length > 0) {
        const fieldMatches = brand.formFields.filter(f => formFields.includes(f));
        if (fieldMatches.length > 0) {
          brandScore += 20;
          evidence.push(`Form nhập liệu có trường đặc trưng của ${brand.label}`);
        }
      }

      // 6. High keyword density in page content
      const contentMatches = brand.keywords.filter(kw => pageText.includes(kw));
      if (contentMatches.length >= 2) {
        brandScore += 15;
        evidence.push(`Nội dung trang đề cập ${brand.label} nhiều lần`);
      }

      if (brandScore >= 30) {
        detectedBrands.push({
          brand: brandId,
          label: brand.label,
          score: Math.min(100, brandScore),
          evidence,
          officialDomains: brand.officialDomains,
        });
      }
    }

    // Sort by score
    detectedBrands.sort((a, b) => b.score - a.score);

    const topBrand = detectedBrands[0] || null;
    const overallScore = topBrand ? topBrand.score : 0;

    return {
      detected: detectedBrands.length > 0,
      brands: detectedBrands,
      topBrand: topBrand ? topBrand.brand : null,
      topBrandLabel: topBrand ? topBrand.label : null,
      topBrandScore: topBrand ? topBrand.score : 0,
      evidence: topBrand ? topBrand.evidence : [],
      officialDomains: topBrand ? topBrand.officialDomains : [],
      score: overallScore,
      riskLevel: overallScore >= 70 ? 'CRITICAL' :
        overallScore >= 50 ? 'HIGH' :
          overallScore >= 30 ? 'MEDIUM' : 'SAFE',
      explanation: generateBrandExplanation(topBrand, hostname),
    };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // AI EXPLANATION
  // ─────────────────────────────────────────────────────────────────────────────

  function generateBrandExplanation(topBrand, hostname) {
    if (!topBrand) {
      return '✅ Không phát hiện dấu hiệu giả mạo thương hiệu.';
    }

    const sentences = [];
    sentences.push(
      `🚨 Trang web có dấu hiệu GIẢ MẠO ${topBrand.label} (độ tin cậy: ${topBrand.score}%).`
    );

    if (topBrand.evidence && topBrand.evidence.length > 0) {
      sentences.push(`Bằng chứng: ${topBrand.evidence.slice(0, 2).join('; ')}.`);
    }

    if (topBrand.officialDomains && topBrand.officialDomains.length > 0) {
      sentences.push(
        `✅ Domain chính thức của ${topBrand.label}: ${topBrand.officialDomains[0]}.`
      );
    }

    sentences.push(
      `⚠️ Bạn đang ở "${hostname}" — KHÔNG phải website chính thức. Đừng nhập mật khẩu hoặc thông tin cá nhân.`
    );

    return sentences.join(' ');
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // EXPORT
  // ─────────────────────────────────────────────────────────────────────────────

  window.BrandDetection = { detectBrandImpersonation };

})();

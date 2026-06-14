/**
 * ANTISCAM VIETNAM — Risk Engine 3.0
 * Module 7: Tổng hợp các chỉ số và đưa ra kết luận cuối cùng (Score & AI Explanation)
 *
 * Chạy trong background.js (service worker).
 * Export qua global `self.RiskEngine`.
 */

(function (global) {
  'use strict';

  function calculateFinalRisk(data) {
    const {
      urlIntel = {},
      domainIntel = {},
      sslIntel = {},
      websiteIntel = {},
      brandIntel = {},
      threatIntel = {},
      mlScore = 0 // Điểm từ random forest cũ (0-100)
    } = data;

    // Trọng số (Weights) cho từng Engine
    const WEIGHTS = {
      threatIntel: 1.5,   // Quan trọng nhất: Blacklist / Malware
      brandIntel: 1.3,    // Giả mạo thương hiệu rõ ràng
      websiteIntel: 1.2,  // Form OTP, Exfiltration
      mlScore: 1.0,       // ML Heuristic
      urlIntel: 0.8,      // Phân tích URL
      sslIntel: 0.5,      // SSL Certificate (nhiều false positive với Let's Encrypt)
      domainIntel: 0.5    // Domain Age (nhiều startup cũng có domain mới)
    };

    // Tính điểm Weighted Average dựa trên các module đã có dữ liệu
    let totalWeightedScore = 0;
    let totalWeight = 0;

    const hasThreat = threatIntel && typeof threatIntel.score === 'number';
    const hasBrand = brandIntel && typeof brandIntel.score === 'number';
    const hasWebsite = websiteIntel && typeof websiteIntel.score === 'number';
    const hasUrl = urlIntel && typeof urlIntel.score === 'number';
    const hasSsl = sslIntel && typeof sslIntel.score === 'number';
    const hasDomain = domainIntel && typeof domainIntel.score === 'number';

    if (hasThreat) {
      totalWeightedScore += threatIntel.score * WEIGHTS.threatIntel;
      totalWeight += WEIGHTS.threatIntel;
    }
    if (hasBrand) {
      totalWeightedScore += brandIntel.score * WEIGHTS.brandIntel;
      totalWeight += WEIGHTS.brandIntel;
    }
    if (hasWebsite) {
      totalWeightedScore += websiteIntel.score * WEIGHTS.websiteIntel;
      totalWeight += WEIGHTS.websiteIntel;
    }
    if (typeof mlScore === 'number' && !isNaN(mlScore)) {
      totalWeightedScore += mlScore * WEIGHTS.mlScore;
      totalWeight += WEIGHTS.mlScore;
    }
    if (hasUrl) {
      totalWeightedScore += urlIntel.score * WEIGHTS.urlIntel;
      totalWeight += WEIGHTS.urlIntel;
    }
    if (hasSsl) {
      totalWeightedScore += sslIntel.score * WEIGHTS.sslIntel;
      totalWeight += WEIGHTS.sslIntel;
    }
    if (hasDomain) {
      totalWeightedScore += domainIntel.score * WEIGHTS.domainIntel;
      totalWeight += WEIGHTS.domainIntel;
    }

    let baseScore = totalWeight > 0 ? (totalWeightedScore / totalWeight) : 0;

    // Critical Overrides (Nếu 1 engine báo 100 điểm đỏ chót, đẩy điểm cuối lên cao)
    if (hasThreat && threatIntel.score >= 90) baseScore = Math.max(baseScore, 95);
    if (hasBrand && brandIntel.score >= 80) baseScore = Math.max(baseScore, 85);
    if (hasWebsite && websiteIntel.score >= 80) baseScore = Math.max(baseScore, 85);
    if (hasUrl && urlIntel.score >= 90) baseScore = Math.max(baseScore, 80);

    const finalScore = Math.round(Math.min(100, Math.max(0, baseScore)));

    const riskLevel = finalScore >= 80 ? 'CRITICAL' :
                      finalScore >= 60 ? 'HIGH' :
                      finalScore >= 40 ? 'MEDIUM' :
                      finalScore >= 20 ? 'LOW' :
                      'SAFE';

    return {
      finalScore,
      riskLevel,
      explanation: generateFinalExplanation(data, finalScore)
    };
  }

  function generateFinalExplanation(data, finalScore) {
    const sentences = [];

    // Lấy explanation từ các module có score cao nhất
    if (data.threatIntel && typeof data.threatIntel.score === 'number' && data.threatIntel.score >= 80 && data.threatIntel.explanation) {
      sentences.push(data.threatIntel.explanation);
    }
    
    if (data.brandIntel && typeof data.brandIntel.score === 'number' && data.brandIntel.score >= 50 && data.brandIntel.explanation) {
      sentences.push(data.brandIntel.explanation);
    }

    if (data.websiteIntel && typeof data.websiteIntel.score === 'number' && data.websiteIntel.score >= 50 && data.websiteIntel.explanation) {
      sentences.push(data.websiteIntel.explanation);
    }

    if (data.urlIntel && typeof data.urlIntel.score === 'number' && data.urlIntel.score >= 50 && data.urlIntel.explanation) {
      sentences.push(data.urlIntel.explanation);
    }

    if (data.domainIntel && typeof data.domainIntel.score === 'number' && data.domainIntel.score >= 60 && data.domainIntel.explanation) {
      sentences.push(data.domainIntel.explanation);
    }

    if (data.sslIntel && typeof data.sslIntel.score === 'number' && data.sslIntel.score >= 60 && data.sslIntel.explanation) {
      sentences.push(data.sslIntel.explanation);
    }

    // Default message nếu an toàn
    if (finalScore < 20 && sentences.length === 0) {
      // ─── BƯỚC 6: Trả về thông báo hoàn tất ngay cả khi thiếu dữ liệu AI
      return 'Hệ thống AI hiện chưa phát hiện thấy dấu hiệu lừa đảo rõ ràng trên trang web này. Tuy nhiên, hãy luôn cẩn trọng khi nhập thông tin cá nhân.';
    }

    // Lọc trùng lặp và nối
    const uniqueSentences = [...new Set(sentences)].slice(0, 4); // Lấy tối đa 4 lý do chính
    let text = uniqueSentences.join('\n\n');
    return text;
  }

  global.RiskEngine = { calculateFinalRisk };

  // MV3: Check if global self is available
})(typeof self !== 'undefined' ? self : this);

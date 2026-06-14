/*global chrome*/
/*global $*/

const RISK_COLORS = {
  ANALYZING: { color: '#60a5fa', class: 'text-loading' },
  SAFE: { color: '#10b981', class: 'text-safe' },
  LOW: { color: '#10b981', class: 'text-safe' },
  MEDIUM: { color: '#f59e0b', class: 'text-medium' },
  HIGH: { color: '#f97316', class: 'text-high' },
  CRITICAL: { color: '#ef4444', class: 'text-critical' },
};



function updateCircleStroke(score, riskLevel) {
  const path = document.getElementById('score_path');
  const color = RISK_COLORS[riskLevel]?.color || '#10b981';
  
  // path length for this circle is ~100
  // value from 0 to 100
  setTimeout(() => {
    path.style.stroke = color;
    path.setAttribute('stroke-dasharray', `${score}, 100`);
  }, 100);
}

function createModuleCard(name, data) {
  // data === undefined: engine chưa chạy xong (still scanning)
  // data === null: engine lỗi
  // data && score defined: đã có kết quả
  if (data === undefined || data === null) {
    const label = data === null ? 'Không khả dụng' : 'Đang quét...';
    const cls = data === null ? 'text-medium' : 'text-loading';
    return `
      <div class="module-card">
        <div class="module-name">${name}</div>
        <div class="module-status ${cls}">${label}</div>
      </div>
    `;
  }
  if (typeof data.score === 'undefined') {
    return `
      <div class="module-card">
        <div class="module-name">${name}</div>
        <div class="module-status text-loading">Đang quét...</div>
      </div>
    `;
  }
  const riskLevel = data.riskLevel || 'SAFE';
  const colorClass = RISK_COLORS[riskLevel]?.class || 'text-safe';
  
  let statusText = 'An Toàn';
  if (riskLevel === 'MEDIUM') statusText = 'Cảnh báo';
  if (riskLevel === 'HIGH') statusText = 'Nguy hiểm';
  if (riskLevel === 'CRITICAL') statusText = 'Rất nguy hiểm';

  return `
    <div class="module-card">
      <div class="module-name">${name}</div>
      <div class="module-status ${colorClass}">${statusText}</div>
    </div>
  `;
}

chrome.tabs.query({currentWindow: true, active: true}, ([tab,]) => {
  if (!tab) return;
  const tabId = tab.id;
  let url;
  try {
    url = new URL(tab.url);
  } catch (_e) {
    // Tab URL là chrome://, about:, hoặc undefined
    return;
  }
  const domain = url.hostname;

  if (!['https:', 'http:'].includes(url.protocol)) {
    $('#pluginBody').removeClass('hidden');
    $('#domain_url').text(domain || tab.url);
    $('#site_msg').text('Không thể phân tích trang này (Chrome/Local).');
    return;
  }

  // ─── FIX: Dedup re-renders — chỉ render khi dữ liệu thực sự thay đổi
  let lastRenderedKey = null;

  function renderDashboard() {
    chrome.runtime.sendMessage({type: 'GET_STATE', tabId: tabId}, (background) => {
      if (!background) return;

      const finalRisk = background.finalRisk[tabId] || {
        finalScore: 0,
        riskLevel: 'ANALYZING',
        explanation: 'Hệ thống đang tiến hành phân tích các chỉ số bảo mật...'
      };

      // Kiểm tra xem có data mới để render không
      const completedModules = [
        background.urlIntel && background.urlIntel[tabId],
        background.domainIntel && background.domainIntel[tabId],
        background.sslIntel && background.sslIntel[tabId],
        background.websiteIntel && background.websiteIntel[tabId],
        background.brandIntel && background.brandIntel[tabId],
        background.threatIntel && background.threatIntel[tabId]
      ].filter(x => x).length;

      const renderKey = `${finalRisk.riskLevel}_${finalRisk.finalScore}_${completedModules}`;
      if (renderKey === lastRenderedKey) {
        return; // Dữ liệu không thay đổi, bỏ qua render
      }
      lastRenderedKey = renderKey;

      if (background.isWhiteList[tabId] == domain) {
        $('#pluginBody').addClass('hidden');
        $('#isPhishing').addClass('hidden');
        $('#isSafe').removeClass('hidden');
        $('#isSafe .site-url').text(domain);
        chrome.action.setIcon({ path: '/assets/antiScamLogo.png', tabId });
      } else if (background.isBlocked[tabId] == domain) {
        $('#pluginBody').addClass('hidden');
        $('#isSafe').addClass('hidden');
        $('#isPhishing').removeClass('hidden');
        $('#isPhishing .site-url').text(domain);
        chrome.action.setIcon({ path: '/assets/antiScamLogo.png', tabId });
      } else {
        $('#isSafe').addClass('hidden');
        $('#isPhishing').addClass('hidden');
        $('#pluginBody').removeClass('hidden');
        $('#domain_url').text(domain);

        const { finalScore, riskLevel, explanation } = finalRisk;
        
        $('#site_score').text(isNaN(finalScore) ? '--' : finalScore);
        updateCircleStroke(isNaN(finalScore) ? 0 : finalScore, riskLevel);

        const riskColorClass = RISK_COLORS[riskLevel]?.class || 'text-safe';
        let riskText = 'AN TOÀN';
        if (riskLevel === 'ANALYZING') riskText = 'ĐANG PHÂN TÍCH...';
        else if (riskLevel === 'MEDIUM') riskText = 'NGHI NGỜ';
        else if (riskLevel === 'HIGH') riskText = 'NGUY HIỂM';
        else if (riskLevel === 'CRITICAL') riskText = 'RẤT NGUY HIỂM';

        $('#risk_label').text(riskText).removeClass().addClass('risk-label').addClass(riskColorClass);
        $('#site_msg').text(explanation);

        // Render module cards
        let cardsHtml = '';
        cardsHtml += createModuleCard('URL Intel', background.urlIntel[tabId]);
        cardsHtml += createModuleCard('Domain Intel', background.domainIntel[tabId]);
        cardsHtml += createModuleCard('SSL Intel', background.sslIntel[tabId]);
        cardsHtml += createModuleCard('Website Intel', background.websiteIntel[tabId]);
        cardsHtml += createModuleCard('Brand Detection', background.brandIntel[tabId]);
        cardsHtml += createModuleCard('Threat Intel', background.threatIntel[tabId]);
        
        $('#engines_grid').html(cardsHtml);
      }
    });
  }

  // Render immediately
  renderDashboard();

  // Listen for real-time updates from background service worker
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === 'STATE_UPDATED' && message.tabId === tabId) {
      renderDashboard();
    }
  });
});

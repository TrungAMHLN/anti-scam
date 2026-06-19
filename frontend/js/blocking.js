/*global chrome*/
const REDIRECT_PORT_NAME = 'REDIRECT_PORT_NAME';
const CLOSE_TAB_PORT_NAME = 'CLOSE_TAB_PORT_NAME';
let message = {};

const redirectPort = chrome.runtime.connect({name: REDIRECT_PORT_NAME});
const closeTabPort = chrome.runtime.connect({name: CLOSE_TAB_PORT_NAME});

document.getElementById('close').addEventListener('click', () => {
  closeTabPort.postMessage({close_tab: true});
  return false;
});

document.getElementById('allow').addEventListener('click', () => {
  // MV3: Dùng chrome.runtime.sendMessage thay localStorage để báo service worker bỏ qua lần này
  chrome.tabs.query({currentWindow: true, active: true}, ([tab,]) => {
    chrome.runtime.sendMessage({type: 'SET_WHITELIST_TEMP', tabId: tab.id}, () => {
      redirectPort.postMessage({redirect: message.site});
    });
  });
});

const hash = window.location.hash.substring(1);
try {
  message = JSON.parse(decodeURI(hash));
  if (!message.v3) {
    message.v3 = true;
    // reload once to be able to connect to chrome.runtime
    window.location.hash = JSON.stringify(message);
  }

  const link = document.createElement('link');
  link.type = 'image/x-icon';
  link.rel = 'icon';
  link.href = message.favicon;
  document.head.appendChild(link);

  let spans = document.getElementsByClassName('sitename');
  for (let i = 0; i < spans.length; ++i) {
    spans[i].textContent = message.site;
  }
  spans = document.getElementsByClassName('sitetitle');
  for (let i = 0; i < spans.length; ++i) {
    spans[i].textContent = message.title;
  }
  spans = document.getElementsByClassName('sitematch');
  let match;
  for (let i = 0; i < spans.length; ++i) {
    if (!match) {
      match = message.match.replace(/\\([.+?^${}()|[\]\\]{1})/g, '$1').replace(/[.]{1}[*]{1}/g, '*');
    }
    spans[i].textContent = match;
  }

  document.title = `${document.title} ${message.title}`;

  if (message.riskBlock) {
    const header = document.getElementById('header');
    if (header) header.textContent = `Trang ${message.title} có nguy cơ nguy hiểm cao`;
    const intro = document.querySelector('#header + p');
    if (intro) intro.textContent = message.reason || 'AntiScam phát hiện nhiều tín hiệu nguy hiểm trên trang này.';
  }

  if (message.lenient) {
    document.getElementById('access').style.display = 'inline-block';
    document.getElementById('access').addEventListener('click', () => {
      chrome.runtime.sendMessage(
        {'access': message.match, 'access_seconds': (5 * 60), 'site': message.site}
      );
    });
  }
}
catch (e) {
  console.trace(e);
}

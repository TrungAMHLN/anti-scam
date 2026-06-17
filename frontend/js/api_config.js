// api_config.js — central API endpoint config for the Chrome Extension client.
// No secrets. API keys must live only in the deployed backend environment.
(function (root) {
  root.ANTISCAM_API_CONFIG = Object.freeze({
    // Change this to your deployed Vercel backend domain.
    PRODUCTION_API_BASE_URL: 'https://your-vercel-domain.vercel.app',
    // Local development backend. Do not use in production extension packages.
    DEVELOPMENT_API_BASE_URL: 'http://localhost:3000',
    STORAGE_KEY: 'antiscamApiBaseUrl',
  });
})(typeof self !== 'undefined' ? self : window);

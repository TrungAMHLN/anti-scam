try { require('dotenv').config(); } catch (_) { /* dotenv is optional in production/Vercel */ }
const config = require('config');
const express = require('express');

const cors = require('cors');
const bodyParser = require('body-parser');
const status = require('http-status');
const jwt = require('jsonwebtoken');
const rateLimit = require("express-rate-limit");

const path = require('path');
const fs = require('fs');
const { Parser } = require('json2csv');
const morgan = require('morgan');
const axios = require('axios');
const AUDIT_LOG_ENABLED = process.env.ANTISCAM_AUDIT_LOG !== 'false';
const shortJson = (value, max = 700) => {
  try {
    const raw = typeof value === 'string' ? value : JSON.stringify(value);
    return (raw || '').replace(/\s+/g, ' ').slice(0, max) + ((raw || '').length > max ? '…' : '');
  } catch (_) { return '[unserializable]'; }
};
const redactUrl = (value = '') => String(value)
  .replace(/([?&](?:key|apikey|api_key|token)=)[^&]+/ig, '$1<redacted>');
axios.interceptors.request.use((req) => {
  if (AUDIT_LOG_ENABLED) {
    req.metadata = { start: Date.now() };
    const base = req.baseURL ? String(req.baseURL).replace(/\/$/, '') : '';
    const full = /^https?:\/\//i.test(req.url || '') ? req.url : `${base}${req.url || ''}`;
    console.info(`[TI REQUEST] ${String(req.method || 'GET').toUpperCase()} ${redactUrl(full)} body=${shortJson(req.data || '')}`);
  }
  return req;
});
axios.interceptors.response.use((res) => {
  if (AUDIT_LOG_ENABLED) {
    const ms = Date.now() - ((res.config.metadata && res.config.metadata.start) || Date.now());
    const base = res.config.baseURL ? String(res.config.baseURL).replace(/\/$/, '') : '';
    const full = /^https?:\/\//i.test(res.config.url || '') ? res.config.url : `${base}${res.config.url || ''}`;
    console.info(`[TI RESPONSE] ${String(res.config.method || 'GET').toUpperCase()} ${redactUrl(full)} status=${res.status} ms=${ms} body=${shortJson(res.data)}`);
  }
  return res;
}, (err) => {
  if (AUDIT_LOG_ENABLED) {
    const cfg = err.config || {};
    const ms = Date.now() - ((cfg.metadata && cfg.metadata.start) || Date.now());
    const base = cfg.baseURL ? String(cfg.baseURL).replace(/\/$/, '') : '';
    const full = /^https?:\/\//i.test(cfg.url || '') ? cfg.url : `${base}${cfg.url || ''}`;
    console.info(`[TI RESPONSE] ${String(cfg.method || 'GET').toUpperCase()} ${redactUrl(full)} status=${err.response ? err.response.status : 'ERR'} ms=${ms} body=${shortJson(err.response ? err.response.data : err.message)}`);
  }
  return Promise.reject(err);
});
const multer = require('multer');
const _ = require('lodash/array');
const { readFile } = require('fs');
const { getDb, getDbOrNull } = require('./database/mongo');
const dns = require('dns').promises;
const crypto = require('crypto');
const querystring = require('querystring');
const tls = require('tls');

const fields = ['time','rating', 'url', 'ip', 'client'];
const opts = { fields, header: false };
const parser = new Parser(opts);

const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET || config.get("auth.accessTokenSecret");
const refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET || config.get("auth.refreshTokenSecret");
const maxLengthUrl = config.get("maxLengthUrl");

const apiLimiter = rateLimit({
    windowMs: 55 * 60 * 1000,
    max: 100,
    message: "Too many request from this IP, please try again after an hour"
  });


const app = express();
// Enable CORS
app.use(cors());
app.use(express.static('public'));

// Enable the use of request body parsing middleware
app.use(bodyParser.json());
app.use(bodyParser.json({limit: '1mb'}));
app.use(bodyParser.urlencoded({
  extended: true
}));
const upload = multer();

// Enable request logging. Vercel serverless functions cannot write persistent log files.
app.use(morgan('combined'))
// Rate limit
app.use(`/${config.get("app.version")}/rate`, apiLimiter);

// TODO: authentication / authorization functions
const clients = config.get("auth.clients");
const authSecretsConfigured = () => !!(accessTokenSecret && refreshTokenSecret);

const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (authHeader) {
        const token = authHeader.split(' ')[1];

        jwt.verify(token, accessTokenSecret, (err, user) => {
            if (err) {
                return res.sendStatus(403);
            }
            req.user = user;
            next();
        });
    } else {
        res.sendStatus(401);
    }
};


// ─────────────────────────────────────────────────────────────────────────────
// Threat intelligence helpers (server-side only). API keys are read from config or
// environment variables, never from the browser extension.
// ─────────────────────────────────────────────────────────────────────────────
const getCfg = (pathName, fallback = null) => {
    try { return config.has(pathName) ? config.get(pathName) : fallback; } catch (_) { return fallback; }
};
const normalizeHostname = (value) => {
    if (!value || typeof value !== 'string') return '';
    let raw = value.trim();
    try {
        if (!/^https?:\/\//i.test(raw)) raw = 'http://' + raw;
        return new URL(raw).hostname.toLowerCase().replace(/^www\./, '');
    } catch (_) {
        return raw.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].replace(/^www\./, '');
    }
};
const normalizeUrlInput = (value) => {
    if (!value || typeof value !== 'string') return '';
    const trimmed = value.trim();
    if (/^https?:\/\//i.test(trimmed)) return trimmed;
    return 'http://' + trimmed;
};
const withTimeout = (promise, ms, fallback) => Promise.race([
    promise.catch(() => fallback),
    new Promise(resolve => setTimeout(() => resolve(fallback), ms))
]);

const tiCache = new Map();
const cacheRefreshInFlight = new Set();
const cachedThreatIntel = async (key, ttlMs, producer) => {
    const now = Date.now();
    const hit = tiCache.get(key);
    if (hit && now - hit.time < ttlMs) return { ...hit.value, cache: 'hit' };
    if (hit && !cacheRefreshInFlight.has(key)) {
        cacheRefreshInFlight.add(key);
        producer().then(value => { if (value) tiCache.set(key, { time: Date.now(), value }); })
            .catch(() => {})
            .finally(() => cacheRefreshInFlight.delete(key));
        return { ...hit.value, cache: 'stale-refreshing' };
    }
    const value = await producer();
    if (value) tiCache.set(key, { time: now, value });
    return value;
};
const TI_TTL = {
    short: 15 * 60 * 1000,
    medium: 60 * 60 * 1000,
    long: 6 * 60 * 60 * 1000,
    rdap: 24 * 60 * 60 * 1000,
};
const rdapDate = (events, names) => {
    if (!Array.isArray(events)) return null;
    const wanted = names.map(x => String(x).toLowerCase());
    const e = events.find(ev => wanted.includes(String(ev.eventAction || '').toLowerCase()));
    return e && e.eventDate ? e.eventDate : null;
};
const getDomainAgeRdap = async (domain) => {
    if (!domain) return { ageDays: -1, source: 'rdap', status: 'invalid' };
    return cachedThreatIntel(`rdap:${domain}`, TI_TTL.rdap, () => withTimeout((async () => {
        const resp = await axios.get(`https://rdap.org/domain/${domain}`, { timeout: 4500 });
        const registrationDate = rdapDate(resp.data && resp.data.events, ['registration']);
        const expirationDate = rdapDate(resp.data && resp.data.events, ['expiration', 'expiry']);
        const ageDays = registrationDate ? Math.floor((Date.now() - new Date(registrationDate).getTime()) / (1000 * 60 * 60 * 24)) : -1;
        return { ageDays, registrationDate, expirationDate, source: 'rdap' };
    })(), 5000, { ageDays: -1, source: 'rdap', status: 'timeout' }));
};
const urlIdForVirusTotal = (url) => Buffer.from(url).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const checkVirusTotal = async (url) => {
    const key = process.env.VIRUSTOTAL_API_KEY || getCfg('threatIntel.virusTotal.apiKey');
    if (!key) return null;
    return withTimeout((async () => {
        const vtUrl = `https://www.virustotal.com/api/v3/urls/${urlIdForVirusTotal(url)}`;
        const resp = await axios.get(vtUrl, { headers: { 'x-apikey': key }, timeout: 6500 });
        const stats = (((resp.data || {}).data || {}).attributes || {}).last_analysis_stats || {};
        const malicious = (stats.malicious || 0) + (stats.suspicious || 0);
        return { source: 'VirusTotal', malicious, rawStats: stats, dangerous: malicious > 0 };
    })(), 7000, null);
};
const checkVirusTotalFileHash = async (hash) => {
    const key = process.env.VIRUSTOTAL_API_KEY || getCfg('threatIntel.virusTotal.apiKey');
    if (!key || !hash) return null;
    return withTimeout((async () => {
        const resp = await axios.get(`https://www.virustotal.com/api/v3/files/${hash}`, { headers: { 'x-apikey': key }, timeout: 6500 });
        const stats = (((resp.data || {}).data || {}).attributes || {}).last_analysis_stats || {};
        const malicious = (stats.malicious || 0) + (stats.suspicious || 0);
        return { source: 'VirusTotal', malicious, rawStats: stats, dangerous: malicious > 0 };
    })(), 7000, null);
};
const checkUrlHaus = async (url, domain) => withTimeout((async () => {
    const headers = { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'AntiScam-Extension/2.0' };
    const urlResp = await axios.post('https://urlhaus-api.abuse.ch/v1/url/', querystring.stringify({ url }), { headers, timeout: 5500 }).catch(() => null);
    const hostResp = await axios.post('https://urlhaus-api.abuse.ch/v1/host/', querystring.stringify({ host: domain }), { headers, timeout: 5500 }).catch(() => null);
    if (!urlResp && !hostResp) return null;
    const hitUrl = urlResp && urlResp.data && urlResp.data.query_status === 'ok';
    const hitHost = hostResp && hostResp.data && hostResp.data.query_status === 'ok';
    return { source: 'URLhaus', dangerous: !!(hitUrl || hitHost), urlStatus: urlResp && urlResp.data && urlResp.data.query_status, hostStatus: hostResp && hostResp.data && hostResp.data.query_status };
})(), 7000, null);
const checkThreatFox = async (domain) => withTimeout((async () => {
    const key = process.env.THREATFOX_API_KEY || getCfg('threatIntel.threatFox.apiKey');
    const headers = { 'Content-Type': 'application/json' };
    if (key) headers['Auth-Key'] = key;
    const resp = await axios.post('https://threatfox-api.abuse.ch/api/v1/', { query: 'search_ioc', search_term: domain }, { headers, timeout: 5500 });
    return { source: 'ThreatFox', dangerous: resp.data && resp.data.query_status === 'ok', status: resp.data && resp.data.query_status };
})(), 6500, null);
const resolveIp = async (domain) => {
    try { const r = await dns.lookup(domain); return r && r.address; } catch (_) { return null; }
};
const checkAbuseIPDB = async (ip) => {
    const key = process.env.ABUSEIPDB_API_KEY || getCfg('threatIntel.abuseIPDB.apiKey');
    if (!key || !ip) return null;
    return withTimeout((async () => {
        const resp = await axios.get('https://api.abuseipdb.com/api/v2/check', {
            params: { ipAddress: ip, maxAgeInDays: 90 },
            headers: { Key: key, Accept: 'application/json' }, timeout: 5500
        });
        const score = resp.data && resp.data.data ? resp.data.data.abuseConfidenceScore : 0;
        return { source: 'AbuseIPDB', ip, abuseConfidenceScore: score || 0, dangerous: (score || 0) >= 50 };
    })(), 6500, null);
};
const checkGoogleSafeBrowsing = async (url) => {
    const key = process.env.GOOGLE_SAFE_BROWSING_KEY || getCfg('gcloud.key') || getCfg('threatIntel.googleSafeBrowsing.apiKey');
    if (!key || !url) return null;
    return withTimeout((async () => {
        const endpoint = getCfg('gcloud.safecheckUrl', 'https://safebrowsing.googleapis.com/v4/threatMatches:find');
        const resp = await axios.post(`${endpoint}?key=${key}`, {
            client: { clientId: 'antiscam', clientVersion: '2.0.0' },
            threatInfo: {
                threatTypes: ['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','MALICIOUS_BINARY','POTENTIALLY_HARMFUL_APPLICATION'],
                platformTypes: ['ANY_PLATFORM'],
                threatEntryTypes: ['URL'],
                threatEntries: [{ url }]
            }
        }, { timeout: 6500 });
        const matches = resp.data && Array.isArray(resp.data.matches) ? resp.data.matches : [];
        return { source: 'Google Safe Browsing', dangerous: matches.length > 0, matches };
    })(), 7500, null);
};

const checkAlienVaultOtx = async (domain, ip) => {
    const key = process.env.OTX_API_KEY || getCfg('threatIntel.otx.apiKey');
    if (!key || (!domain && !ip)) return null;
    return withTimeout((async () => {
        const indicatorType = ip ? 'IPv4' : 'domain';
        const indicator = ip || domain;
        const resp = await axios.get(`https://otx.alienvault.com/api/v1/indicators/${indicatorType}/${encodeURIComponent(indicator)}/general`, {
            headers: { 'X-OTX-API-KEY': key }, timeout: 6500
        });
        const pulseCount = resp.data && resp.data.pulse_info ? (resp.data.pulse_info.count || 0) : 0;
        return { source: 'AlienVault OTX', dangerous: pulseCount > 0, pulseCount, details: resp.data && resp.data.pulse_info };
    })(), 7500, null);
};

const getSslIntel = async (domain) => {
    if (!domain) return null;
    return withTimeout(new Promise((resolve) => {
        const socket = tls.connect(443, domain, { servername: domain, rejectUnauthorized: false, timeout: 5000 }, () => {
            try {
                const cert = socket.getPeerCertificate(true);
                socket.end();
                if (!cert || !cert.valid_from) return resolve({ source: 'SSL', checked: false, dangerous: false });
                const validFrom = new Date(cert.valid_from);
                const validTo = new Date(cert.valid_to);
                const ageDays = Math.floor((Date.now() - validFrom.getTime()) / (1000 * 60 * 60 * 24));
                const expiresInDays = Math.floor((validTo.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
                const issuer = cert.issuer && (cert.issuer.O || cert.issuer.CN);
                resolve({ source: 'SSL', checked: true, dangerous: false, validFrom: cert.valid_from, validTo: cert.valid_to, ageDays, expiresInDays, issuer, selfSigned: cert.issuerCertificate === cert });
            } catch (_) { resolve({ source: 'SSL', checked: false, dangerous: false }); }
        });
        socket.on('error', () => resolve({ source: 'SSL', checked: false, dangerous: true, error: 'ssl_error' }));
        socket.on('timeout', () => { try { socket.destroy(); } catch (_) {} resolve({ source: 'SSL', checked: false, dangerous: false, timeout: true }); });
    }), 6000, { source: 'SSL', checked: false, dangerous: false, timeout: true });
};

const checkOpenPhish = async (url, domain) => cachedThreatIntel('openphish:feed', 15 * 60 * 1000, async () => {
    return withTimeout((async () => {
        const resp = await axios.get('https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt', { timeout: 6500 });
        const entries = String(resp.data || '').split(/\r?\n/).map(x => x.trim()).filter(Boolean);
        return { source: 'OpenPhish', entries };
    })(), 7500, null);
}).then(feed => {
    if (!feed || !feed.entries) return null;
    const raw = String(url || '').replace(/\/$/, '');
    const wantedDomain = String(domain || '').toLowerCase().replace(/^www\./, '');
    const matches = [];
    for (const e of feed.entries) {
        const clean = String(e || '').replace(/\/$/, '');
        if (clean === raw) { matches.push(clean); continue; }
        if (wantedDomain) {
            try {
                const h = new URL(clean).hostname.toLowerCase().replace(/^www\./, '');
                if (h === wantedDomain || h.endsWith('.' + wantedDomain)) matches.push(clean);
            } catch (_) {}
        }
    }
    return { source: 'OpenPhish', dangerous: matches.length > 0, matches: matches.slice(0, 5) };
}).catch(() => null);

const checkMalwareReputation = async (url, domain, ip) => {
    const results = await Promise.all([
        checkGoogleSafeBrowsing(url),
        checkVirusTotal(url),
        checkOpenPhish(url, domain),
        checkUrlHaus(url, domain),
        checkThreatFox(domain),
        checkAlienVaultOtx(domain, ip),
        checkAbuseIPDB(ip)
    ]);
    const sources = results.filter(r => r && r.dangerous).map(r => r.source);
    return { checked: results.filter(Boolean).map(r => r.source), sources, maliciousSources: sources.length, dangerous: sources.length > 0, details: results.filter(Boolean) };
};
const getDnsIntel = async (domain, ip) => withTimeout((async () => {
    const ns = await dns.resolveNs(domain).catch(() => []);
    const mx = await dns.resolveMx(domain).catch(() => []);
    let asn = null, asName = null, hosting = null;
    if (ip) {
        const bgp = await axios.get(`https://api.bgpview.io/ip/${ip}`, { timeout: 4500 }).catch(() => null);
        const prefixes = bgp && bgp.data && bgp.data.data && bgp.data.data.prefixes ? bgp.data.data.prefixes : [];
        const first = prefixes && prefixes[0];
        if (first && first.asn) { asn = first.asn.asn; asName = first.asn.name; hosting = first.name || first.description; }
    }
    const riskyAsn = getCfg('threatIntel.riskyAsn', []);
    const riskyNs = getCfg('threatIntel.riskyNameserverKeywords', ['bulletproof', 'fastflux', 'privacy', 'dynamic-dns']);
    const nsText = (ns || []).join(' ').toLowerCase();
    const riskyInfrastructure = (asn && riskyAsn.includes(asn)) || riskyNs.some(k => nsText.includes(String(k).toLowerCase()));
    return { ip, asn, asName, hosting, nameservers: ns, mxRecords: mx, riskyInfrastructure: !!riskyInfrastructure };
})(), 6500, { ip, asn: null, nameservers: [], mxRecords: [], riskyInfrastructure: false });
const getCommunityReportSummary = async (domain) => {
    try {
        const database = await getDbOrNull();
        if (!database) return { reportCount: 0 };
        const count = await database.collection('community_reports').countDocuments({ domain });
        const latest = await database.collection('community_reports').find({ domain }).sort({ time: -1 }).limit(3).toArray();
        return { reportCount: count, latest: latest.map(x => ({ reason: x.reason, time: x.time })) };
    } catch (_) { return { reportCount: 0 }; }
};

app.post(`/${config.get("app.version")}/initSession`, async (req, res) => {
    if (!authSecretsConfigured()) return res.status(status.SERVICE_UNAVAILABLE).send({ message: 'Auth secrets are not configured' });
    const { app, secret } = req.body;
    const client = clients.find(u => { return u.app === app && u.secret === secret });

    if (client) {
        const accessToken = jwt.sign({
            username: client.app,
            role: client.role
        },
        accessTokenSecret,
        {
            expiresIn: config.get("auth.expiration")
        });

        const refreshToken = jwt.sign({
            username: client.app,
            role: client.role
            },
            refreshTokenSecret);

        try {
            const database = await getDbOrNull();
            if (database) await database.collection('refresh_tokens').updateOne(
                { token: refreshToken },
                { $set: { token: refreshToken, app: client.app, role: client.role, createdAt: new Date() } },
                { upsert: true }
            );
        } catch (_) {}

        res.json({
            version: config.get("app.version"),
            requestedOn: new Date(),
            token: accessToken,
            refresh: refreshToken,
        });
    }
    else {
        res.status(status.FORBIDDEN).send({
            version: config.get("app.version"),
            requestedOn: new Date(),
            message: `Client application credential incorrect. ${status['401_MESSAGE']}`});
    }
});

app.post(`/${config.get("app.version")}/token`, async (req, res) => {
    if (!authSecretsConfigured()) return res.status(status.SERVICE_UNAVAILABLE).send({ message: 'Auth secrets are not configured' });
    const { token } = req.body;

    if (!token) {
        return res.sendStatus(401);
    }

    try {
        const database = await getDbOrNull();
        if (database) {
            const stored = await database.collection('refresh_tokens').findOne({ token });
            if (!stored) return res.sendStatus(403);
        }
    } catch (_) {}

    jwt.verify(token, refreshTokenSecret, (err, client) => {
        if (err) {
            return res.sendStatus(403);
        }

        const accessToken = jwt.sign({
            username: client.app,
            role: client.role
        },
        accessTokenSecret,
        {
            expiresIn: config.get("auth.expiration")
        });

        res.json({
            status: status.OK,
            version: config.get("app.version"),
            requestedOn: new Date(),
            token: accessToken
        });
    });
});

app.post(`/${config.get("app.version")}/closeSession`, async (req, res) => {
    const { token } = req.body;
    try {
        const database = await getDbOrNull();
        if (database && token) await database.collection('refresh_tokens').deleteOne({ token });
    } catch (_) {}

    res.status(status.OK).send({
        status: status.OK,
        version: config.get("app.version"),
        requestedOn: new Date(),
        message: "Session closed"
      });
});

app.get(`/${config.get("app.version")}/ping`, function(req, res){
  res.status(status.OK).send({
      status: status.OK,
      version: config.get("app.version"),
      requestedOn: new Date(),
    });
})

app.post(`/${config.get("app.version")}/rate`, authenticateJWT, async function(req, res) {
    //TODO: store request to file
    const params = {  time: new Date(), ...req.body, ip: req.ip};
    const msg = validateSubmitting(params);
    if (msg.indexOf("ok") == -1) {
        res.status(status.BAD_REQUEST).send({
            status: status.BAD_REQUEST,
            version: config.get("app.version"),
            requestedOn: new Date(),
            "message": msg
        });
    }
    else {
        if (params) {
            { const database = await getDbOrNull(); if (database) await database.collection("rating").insertOne(params); }
            /*
            const data = parser.parse(params);
            fs.appendFile(config.get("app.storage"), `${data}\r\n`, 'utf8', function (err) {
                if (err) {
                    console.log('Some error occured - file either not saved or corrupted file saved.');
                } else{
                    console.log('saved: ',  data);
                }
            });
            */
        }

        res.status(status.OK).send({
            status: status.OK,
            version: config.get("app.version"),
            requestedOn: new Date(),
            "message":"ok"
        });
    }
})


const buildReputationPayload = async (rawUrl) => {
    const url = normalizeUrlInput(String(rawUrl));
    const domain = normalizeHostname(String(rawUrl));
    if (!domain) throw new Error('invalid domain');
    const ip = await resolveIp(domain);
    const [domainAge, malware, dnsIntel, sslIntel, community] = await Promise.all([
        getDomainAgeRdap(domain),
        checkMalwareReputation(url, domain, ip),
        getDnsIntel(domain, ip),
        getSslIntel(domain),
        getCommunityReportSummary(domain)
    ]);
    const checkedSources = ['Whois', 'DNS'];
    if (sslIntel && sslIntel.checked) checkedSources.push('SSL');
    if ((malware.checked || []).length) checkedSources.push(...malware.checked);
    const missingSources = ['Google Safe Browsing','VirusTotal','OpenPhish','URLhaus','ThreatFox','AlienVault OTX','AbuseIPDB','SSL'].filter(x => !checkedSources.includes(x));
    let riskScore = malware.dangerous ? 70 : 5;
    if (domainAge && domainAge.ageDays >= 0 && domainAge.ageDays < 30) riskScore = Math.max(riskScore, 25);
    if (sslIntel && sslIntel.ageDays >= 0 && sslIntel.ageDays < 14) riskScore = Math.max(riskScore, 18);
    if (community && community.reportCount >= 3) riskScore = Math.max(riskScore, Math.min(45, 20 + community.reportCount));
    return {
        status: status.OK,
        version: config.get("app.version"),
        requestedOn: new Date(),
        domain,
        domainAge,
        malware,
        dns: dnsIntel,
        ssl: sslIntel,
        community,
        checkedSources: [...new Set(checkedSources)],
        missingSources,
        externalIntel: true,
        confidenceScore: Math.min(95, Math.max(15, checkedSources.length * 15 - missingSources.length * 3)),
        reputationScore: Math.max(0, 100 - riskScore),
        riskLevel: riskLevelLabel(riskScore, true)
    };
};

app.get(`/${config.get("app.version")}/intel`, async function(req, res) {
    try {
        const rawUrl = req.query.url || req.query.domain;
        if (!rawUrl || String(rawUrl).length > maxLengthUrl) return res.sendStatus(status.BAD_REQUEST);
        res.status(status.OK).send(await buildReputationPayload(rawUrl));
    } catch (err) {
        console.log('intel error', err && err.message);
        res.status(status.OK).send({ status: status.OK, version: config.get("app.version"), requestedOn: new Date(), externalIntel:false, checkedSources:[], missingSources:['Whois','DNS','Threat Intelligence'], malware: { dangerous: false, sources: [] }, community: { reportCount: 0 } });
    }
});

app.get('/api/reputation', async function(req, res) {
    try {
        const rawUrl = req.query.url || req.query.domain;
        if (!rawUrl || String(rawUrl).length > maxLengthUrl) return res.sendStatus(status.BAD_REQUEST);
        res.status(status.OK).send(await buildReputationPayload(rawUrl));
    } catch (err) {
        res.status(status.OK).send({ status: status.OK, externalIntel:false, checkedSources:[], missingSources:['Whois','DNS','Threat Intelligence'] });
    }
});

const storeCommunityReport = async (req, res) => {
    try {
        const reason = String(req.body.reason || '').trim().slice(0, 300);
        const objectType = String(req.body.type || '').trim().toLowerCase();
        const objectValue = String(req.body.value || '').trim();
        if (!reason) return res.status(status.BAD_REQUEST).send({ message: 'reason is required' });
        if (objectType && objectValue && ['phone','email','image','text','hash','file'].includes(objectType)) {
            const value = objectType === 'phone' ? normalizePhoneServer(objectValue) : objectValue.toLowerCase();
            const params = { type: objectType, value, reason, time: new Date(), ip: req.ip, client: req.headers['user-agent'] || '' };
            { const database = await getDbOrNull(); if (database) await database.collection('object_reports').insertOne(params); }
            const community = await communityObjectSummary(objectType, value);
            return res.status(status.OK).send({ status: status.OK, version: config.get("app.version"), requestedOn: new Date(), message: 'ok', type: objectType, value, community });
        }
        const domain = normalizeHostname(req.body.url || req.body.domain);
        if (!domain) return res.status(status.BAD_REQUEST).send({ message: 'domain is required' });
        const params = { domain, reason, url: String(req.body.url || '').slice(0, maxLengthUrl), time: new Date(), ip: req.ip, client: req.headers['user-agent'] || '' };
        { const database = await getDbOrNull(); if (database) await database.collection('community_reports').insertOne(params); }
        const community = await getCommunityReportSummary(domain);
        return res.status(status.OK).send({ status: status.OK, version: config.get("app.version"), requestedOn: new Date(), message: 'ok', domain, community });
    } catch (err) {
        console.log('community-report error', err && err.message);
        return res.status(status.INTERNAL_SERVER_ERROR).send({ message: 'could not store report' });
    }
};
app.post(`/${config.get("app.version")}/community-report`, apiLimiter, storeCommunityReport);
app.post('/api/report', apiLimiter, storeCommunityReport);


const TEMP_EMAIL_DOMAINS_SERVER = new Set([
    'yopmail.com','guerrillamail.com','guerrillamail.net','guerrillamail.org','mailinator.com','10minutemail.com',
    'temp-mail.org','tempmail.com','throwawaymail.com','trashmail.com','getnada.com','sharklasers.com','grr.la',
    'maildrop.cc','dispostable.com','fakeinbox.com','mintemail.com','moakt.com','emailondeck.com','tempail.com'
]);
const COMMON_DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'mail', 'dkim', 'k1'];
const getEmailDomain = (email) => String(email || '').split('@')[1] || '';
const safeResolveTxt = async (name) => {
    try { return await dns.resolveTxt(name); } catch (_) { return []; }
};
const flattenTxt = (records) => (records || []).map(r => Array.isArray(r) ? r.join('') : String(r));
const checkEmailDns = async (domain) => {
    const mxRecords = await dns.resolveMx(domain).catch(() => []);
    const rootTxt = flattenTxt(await safeResolveTxt(domain));
    const spf = rootTxt.find(t => /^v=spf1/i.test(t)) || null;
    const dmarcTxt = flattenTxt(await safeResolveTxt(`_dmarc.${domain}`));
    const dmarc = dmarcTxt.find(t => /^v=DMARC1/i.test(t)) || null;
    const dkimSelectors = [];
    for (const selector of COMMON_DKIM_SELECTORS) {
        const txt = flattenTxt(await safeResolveTxt(`${selector}._domainkey.${domain}`));
        if (txt.some(t => /v=DKIM1|p=/i.test(t))) dkimSelectors.push(selector);
    }
    return { mxRecords, hasMx: mxRecords.length > 0, spf, hasSpf: !!spf, dmarc, hasDmarc: !!dmarc, dkimSelectors, hasDkim: dkimSelectors.length > 0 };
};
const checkEmailRep = async (email) => {
    return withTimeout((async () => {
        const resp = await axios.get(`https://emailrep.io/${encodeURIComponent(email)}`, {
            timeout: 6500,
            headers: { 'User-Agent': 'AntiScam-Extension/1.0' }
        });
        return resp.data || null;
    })(), 7500, null);
};
const normalizePhoneServer = (s) => String(s || '').replace(/[\s().-]/g, '');
const analyzePhoneFormat = (phone) => {
    const p = normalizePhoneServer(phone);
    let country = null, carrier = null, valid = false;
    if (/^(?:\+?84|0)(?:3|5|7|8|9)\d{8}$/.test(p)) {
        valid = true; country = 'VN';
        const local = p.replace(/^\+?84/, '0');
        const prefix = local.slice(0, 3);
        if (/^(032|033|034|035|036|037|038|039|086|096|097|098)$/.test(prefix)) carrier = 'Viettel';
        else if (/^(070|076|077|078|079|089|090|093)$/.test(prefix)) carrier = 'MobiFone';
        else if (/^(081|082|083|084|085|088|091|094)$/.test(prefix)) carrier = 'VinaPhone';
        else if (/^(052|056|058|092)$/.test(prefix)) carrier = 'Vietnamobile';
        else if (/^(059|099)$/.test(prefix)) carrier = 'Gmobile';
    } else if (/^\+?[1-9]\d{7,14}$/.test(p)) { valid = true; country = 'INTL'; }
    return { normalized: p, valid, country, carrier };
};
const checkTellows = async (phone) => withTimeout((async () => {
    const p = normalizePhoneServer(phone).replace(/^\+/, '');
    const resp = await axios.get(`https://www.tellows.com/num/${encodeURIComponent(p)}`, { timeout: 6500, headers: { 'User-Agent': 'AntiScam-Extension/1.0' } });
    const html = String(resp.data || '');
    const scoreMatch = html.match(/score[^0-9]{0,30}([1-9]|10)/i) || html.match(/tellows\s*score[^0-9]{0,30}([1-9]|10)/i);
    const score = scoreMatch ? parseInt(scoreMatch[1]) : null;
    const spam = score != null && score >= 7;
    return { source: 'Tellows', score, dangerous: spam, found: /tellows/i.test(html) };
})(), 7500, null);
const communityObjectSummary = async (type, value) => {
    try {
        const database = await getDbOrNull();
        if (!database) return { reportCount: 0 };
        const count = await database.collection('object_reports').countDocuments({ type, value });
        const latest = await database.collection('object_reports').find({ type, value }).sort({ time: -1 }).limit(3).toArray();
        return { reportCount: count, latest: latest.map(x => ({ reason: x.reason, time: x.time })) };
    } catch (_) { return { reportCount: 0 }; }
};

const serverDetectTarget = (input, type) => {
    const raw = String(input || '').trim();
    if (type) return type;
    if (/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(raw)) return 'email';
    if (/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(raw)) return 'hash';
    if (/^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(raw)) return 'ip';
    if (/^(?:\+?84|0)(?:3|5|7|8|9)\d{8}$/.test(raw.replace(/[\s().-]/g, ''))) return 'phone';
    if (/^https?:\/\//i.test(raw)) return 'url';
    if (/^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$/i.test(raw)) return 'domain';
    return 'text';
};
const objectScanResponse = ({ type, finalScore = 75, riskScore = 0, result = {}, explanations = [], summary = '', externalIntel = false, checkedSources = [], missingSources = [] }) => ({
    status: status.OK,
    version: config.get("app.version"),
    requestedOn: new Date(),
    type,
    finalScore,
    riskScore,
    externalIntel,
    assessmentLimited: !externalIntel,
    checkedSources,
    missingSources,
    confidenceScore: Math.min(95, Math.max(15, checkedSources.length * 18 - missingSources.length * 4)),
    reputationScore: finalScore,
    riskLevel: riskLevelLabel(riskScore, externalIntel),
    result,
    explanations,
    summary
});
const addSignal = (bucket, key, level, text) => {
    bucket.result[key] = level === 'safe' ? '-1' : (level === 'danger' ? '1' : (level === 'suspicious' ? '2' : '0'));
    bucket.explanations.push({ key, level, text });
};
const riskLevelLabel = (riskScore, externalIntel) => {
    if (riskScore >= 80) return 'Rất nguy hiểm';
    if (riskScore >= 60) return 'Nguy hiểm';
    if (riskScore >= 40) return 'Nghi ngờ';
    if (riskScore >= 20) return 'Cần thận trọng';
    if (!externalIntel) return 'Đánh giá hạn chế';
    if (riskScore >= 8) return 'Khá an toàn';
    return 'An toàn';
};

const handleScanObject = async function(req, res, forcedType = null) {
    try {
        const input = String(req.body.input || '').trim();
        const type = forcedType || serverDetectTarget(input, req.body.type);
        const bucket = { result: {}, explanations: [] };
        let riskScore = 0;
        let externalIntel = false;
        const checkedSources = [];
        const missingSources = [];
        const markChecked = (name) => { if (!checkedSources.includes(name)) checkedSources.push(name); };
        const markMissing = (name) => { if (!missingSources.includes(name)) missingSources.push(name); };

        if (type === 'url' || type === 'domain') {
            const rawUrl = type === 'url' ? input : `https://${input}`;
            const url = normalizeUrlInput(rawUrl);
            const domain = normalizeHostname(rawUrl);
            const ip = await resolveIp(domain);
            const [domainAge, malware, dnsIntel, sslIntel, community] = await Promise.all([
                getDomainAgeRdap(domain), checkMalwareReputation(url, domain, ip), getDnsIntel(domain, ip), getSslIntel(domain), getCommunityReportSummary(domain)
            ]);
            externalIntel = true;
            markChecked('Whois'); markChecked('DNS');
            if (sslIntel && sslIntel.checked) markChecked('SSL'); else markMissing('SSL');
            (malware.checked || []).forEach(markChecked);
            ['Google Safe Browsing','VirusTotal','OpenPhish','URLhaus','ThreatFox','AlienVault OTX','AbuseIPDB'].filter(x => !(malware.checked || []).includes(x)).forEach(markMissing);
            if (domainAge && domainAge.ageDays > 730) addSignal(bucket, 'EstablishedDomain', 'safe', 'Domain hoạt động lâu năm.');
            else if (domainAge && domainAge.ageDays >= 0 && domainAge.ageDays < 30) { addSignal(bucket, 'NewDomain', 'warning', 'Domain mới đăng ký.'); riskScore += 15; }
            if (dnsIntel && dnsIntel.asn) addSignal(bucket, 'DNSIntel', 'safe', 'Đã xác định ASN/hosting.');
            if (sslIntel && sslIntel.ageDays >= 0 && sslIntel.ageDays < 14) { addSignal(bucket, 'SSLNew', 'warning', 'SSL mới được cấp gần đây.'); riskScore += 8; }
            if (malware && malware.dangerous) { addSignal(bucket, 'MalwareReputation', 'danger', 'URL/domain bị nguồn threat intelligence cảnh báo.'); riskScore += 60; }
            else addSignal(bucket, 'URLReputation', 'safe', 'Không thấy trong nguồn cảnh báo đã kiểm tra.');
            if (community && community.reportCount >= 3) { addSignal(bucket, 'CommunityReport', 'suspicious', `Website bị cộng đồng báo cáo ${community.reportCount} lần.`); riskScore += Math.min(25, community.reportCount); }
        } else if (type === 'hash' || type === 'file' || type === 'archive') {
            addSignal(bucket, 'FileHash', 'safe', 'Đã nhận SHA256/hash file.');
            const vt = await checkVirusTotalFileHash(input);
            if (vt) { externalIntel = true; markChecked('VirusTotal'); } else { markMissing('VirusTotal'); }
            if (vt && vt.dangerous) { addSignal(bucket, 'FileReputation', 'danger', 'File bị nguồn threat intelligence cảnh báo.'); riskScore += 55; }
            else if (vt) addSignal(bucket, 'FileReputation', 'safe', 'Chưa thấy cảnh báo nguy hiểm cho hash file.');
            else { addSignal(bucket, 'FileReputation', 'warning', 'Chưa có đủ dữ liệu threat intelligence cho hash file.'); riskScore += 8; }
            if (type === 'archive') { addSignal(bucket, 'ArchiveContainer', 'warning', 'File nén được xử lý như container chứa nhiều file.'); riskScore += 8; }
        } else if (type === 'image' || type === 'qr') {
            addSignal(bucket, 'ImageInput', 'safe', 'Đã nhận ảnh để quét.');
            const metaScan = (req.body.meta && req.body.meta.imageScan) || {};
            if (metaScan.qrText) addSignal(bucket, 'QRDetection', 'warning', 'Ảnh chứa QR Code.');
            if (metaScan.ocrText) addSignal(bucket, 'ImageOCR', 'safe', 'Đã OCR ảnh ở phía trình duyệt.');
            if (metaScan.scamHits > 0) { addSignal(bucket, 'ImageScamText', 'suspicious', 'OCR phát hiện nội dung có dấu hiệu lừa đảo.'); riskScore += Math.min(28, 12 + metaScan.scamHits * 5); }
            if (metaScan.brandHit) { addSignal(bucket, 'ImageBrandText', 'warning', 'Có dấu hiệu sử dụng thương hiệu ngân hàng hoặc ví điện tử.'); riskScore += 10; }
            const imageScannerUrl = process.env.IMAGE_SCANNER_URL || getCfg('imageScanner.url');
            if (metaScan.ocrText) markChecked('OCR Local'); else markMissing('OCR Local');
            if (metaScan.qrText) markChecked('QR Local'); else markMissing('QR Local');
            if (imageScannerUrl && (req.body.meta && (req.body.meta.imageUrl || req.body.meta.srcUrl))) {
                const img = await withTimeout(axios.post(imageScannerUrl, { imageUrl: req.body.meta.imageUrl || req.body.meta.srcUrl }, { timeout: 8000 }), 9000, null);
                if (img) { externalIntel = true; markChecked('Image Backend'); } else markMissing('Image Backend');
                if (img && img.data && img.data.qrText) addSignal(bucket, 'QRDetection', 'warning', 'Ảnh chứa QR Code cần kiểm tra nội dung.');
                if (img && img.data && img.data.scamText) { addSignal(bucket, 'ImageScamText', 'warning', 'OCR phát hiện nội dung có dấu hiệu lừa đảo.'); riskScore += 18; }
            } else if (!metaScan.ocrText && !metaScan.qrText) {
                addSignal(bucket, 'ImageOCR', 'warning', 'OCR/QR nâng cao cần thư viện local hoặc backend image scanner.'); riskScore += 6;
            }
        } else if (type === 'email') {
            addSignal(bucket, 'EmailFormat', 'safe', 'Email đúng định dạng.');
            const domain = getEmailDomain(input).toLowerCase();
            if (TEMP_EMAIL_DOMAINS_SERVER.has(domain)) { addSignal(bucket, 'TempEmail', 'suspicious', 'Email dùng dịch vụ email tạm thời.'); riskScore += 25; }
            const domainIp = await resolveIp(domain);
            const [emailDns, age, emailRep, domainMalware, emailCommunity] = await Promise.all([
                checkEmailDns(domain),
                getDomainAgeRdap(domain),
                checkEmailRep(input),
                checkMalwareReputation(`https://${domain}`, domain, domainIp),
                communityObjectSummary('email', input.toLowerCase())
            ]);
            externalIntel = true;
            markChecked('MX Lookup');
            markChecked('SPF');
            markChecked('DMARC');
            if (emailDns.hasDkim) markChecked('DKIM'); else markMissing('DKIM');
            if (emailRep) markChecked('EmailRep'); else markMissing('EmailRep');
            markChecked('Whois');
            (domainMalware.checked || []).forEach(markChecked);
            ['Google Safe Browsing','VirusTotal','OpenPhish','URLhaus','ThreatFox','AlienVault OTX','AbuseIPDB'].filter(x => !(domainMalware.checked || []).includes(x)).forEach(markMissing);
            markChecked('Community Reports');
            if (emailDns.hasMx) addSignal(bucket, 'EmailMX', 'safe', 'Domain email có MX Record hợp lệ.');
            else { addSignal(bucket, 'EmailMX', 'danger', 'Domain email không có MX Record hợp lệ.'); riskScore += 35; }
            if (emailDns.hasSpf) addSignal(bucket, 'EmailSPF', 'safe', 'Domain email có SPF.');
            else { addSignal(bucket, 'EmailSPF', 'warning', 'Domain email chưa cấu hình SPF.'); riskScore += 6; }
            if (emailDns.hasDmarc) addSignal(bucket, 'EmailDMARC', 'safe', 'Domain email có DMARC.');
            else { addSignal(bucket, 'EmailDMARC', 'warning', 'Domain email chưa cấu hình DMARC.'); riskScore += 8; }
            if (emailDns.hasDkim) addSignal(bucket, 'EmailDKIM', 'safe', 'Phát hiện DKIM selector phổ biến.');
            if (age && age.ageDays >= 0 && age.ageDays < 30) { addSignal(bucket, 'EmailDomainNew', 'warning', 'Domain email mới đăng ký.'); riskScore += age.ageDays < 7 ? 18 : 10; }
            if (domainMalware && domainMalware.dangerous) { addSignal(bucket, 'EmailDomainThreatIntel', 'danger', 'Domain email xuất hiện trong nguồn threat intelligence.'); riskScore += 55; }
            else if ((domainMalware.checked || []).length) addSignal(bucket, 'EmailDomainReputation', 'safe', 'Domain email không thấy trong nguồn cảnh báo đã kiểm tra.');
            if (emailCommunity && emailCommunity.reportCount >= 3) { addSignal(bucket, 'EmailCommunityReport', 'suspicious', `Email bị cộng đồng báo cáo ${emailCommunity.reportCount} lần.`); riskScore += Math.min(35, 10 + emailCommunity.reportCount); }
            if (emailRep) {
                if (emailRep.reputation === 'high') addSignal(bucket, 'EmailRep', 'safe', 'EmailRep đánh giá reputation tốt.');
                if (emailRep.suspicious || emailRep.reputation === 'low') { addSignal(bucket, 'EmailRep', 'danger', 'EmailRep ghi nhận tín hiệu đáng ngờ.'); riskScore += 35; }
                const d = emailRep.details || {};
                if (d.blacklisted) { addSignal(bucket, 'EmailBlacklisted', 'danger', 'Email/domain nằm trong danh sách đen.'); riskScore += 45; }
                if (d.disposable) { addSignal(bucket, 'TempEmail', 'suspicious', 'EmailRep xác nhận email tạm thời.'); riskScore += 25; }
                if (d.credentials_leaked || d.data_breach) { addSignal(bucket, 'EmailLeakSignal', 'suspicious', 'EmailRep ghi nhận tín hiệu rò rỉ dữ liệu.'); riskScore += 20; }
                if (d.malicious_activity) { addSignal(bucket, 'EmailMaliciousActivity', 'danger', 'EmailRep ghi nhận hoạt động độc hại.'); riskScore += 40; }
                if (d.spam) { addSignal(bucket, 'EmailSpamSignal', 'suspicious', 'EmailRep ghi nhận dấu hiệu spam.'); riskScore += 18; }
                if (d.domain_exists === false) { addSignal(bucket, 'EmailDomainMissing', 'danger', 'Domain email không tồn tại.'); riskScore += 45; }
                if (d.spoofable) { addSignal(bucket, 'EmailSpoofable', 'warning', 'Domain email có khả năng bị spoofing.'); riskScore += 10; }
                if (Array.isArray(emailRep.references) && emailRep.references.length) addSignal(bucket, 'EmailRepReferences', 'warning', `EmailRep có ${emailRep.references.length} tham chiếu rủi ro.`);
            }
            if (/support|security|verify|admin|otp|bank/i.test(input)) { addSignal(bucket, 'EmailImpersonation', 'warning', 'Email có từ khóa dễ dùng để giả mạo.'); riskScore += 12; }
        } else if (type === 'phone') {
            const format = analyzePhoneFormat(input);
            if (format.valid) addSignal(bucket, 'PhoneFormat', 'safe', 'Số điện thoại đúng định dạng.');
            else { addSignal(bucket, 'PhoneFormat', 'danger', 'Số điện thoại sai định dạng.'); riskScore += 30; }
            if (format.country === 'VN') addSignal(bucket, 'PhoneVN', 'safe', format.carrier ? `Số Việt Nam thuộc nhà mạng ${format.carrier}.` : 'Số điện thoại Việt Nam hợp lệ.');
            const [tellows, community] = await Promise.all([checkTellows(format.normalized || input), communityObjectSummary('phone', format.normalized || input)]);
            if (tellows) { externalIntel = true; markChecked('Tellows'); } else { markMissing('Tellows'); }
            markChecked('Community Reports');
            if (tellows && tellows.score != null) {
                if (tellows.dangerous) { addSignal(bucket, 'TellowsSpam', 'danger', 'Tellows ghi nhận số có dấu hiệu spam.'); riskScore += 45; }
                else addSignal(bucket, 'TellowsScore', 'safe', 'Tellows không ghi nhận spam score cao.');
            }
            if (community.reportCount >= 3) { addSignal(bucket, 'PhoneCommunityReport', 'suspicious', `Được cộng đồng báo cáo ${community.reportCount} lần.`); riskScore += Math.min(35, 10 + community.reportCount); }
        } else if (type === 'text') {
            if (/otp|mật khẩu|mat khau|nhận thưởng|nhan thuong|việc nhẹ lương cao|viec nhe luong cao|kiếm tiền online|kiem tien online/i.test(input)) {
                addSignal(bucket, 'ScamText', 'warning', 'Văn bản chứa từ khóa thường gặp trong lừa đảo.'); riskScore += 18;
            } else {
                addSignal(bucket, 'TextInsufficient', 'warning', 'Văn bản chưa đủ dữ liệu để kết luận an toàn.'); riskScore += 4;
            }
        } else {
            addSignal(bucket, 'GenericInput', 'safe', 'Đã nhận diện đối tượng quét.');
        }

        const finalScore = Math.max(0, 80 - riskScore);
        res.status(status.OK).send(objectScanResponse({ type, finalScore, riskScore, result: bucket.result, explanations: bucket.explanations, summary: 'Đã quét đối tượng bằng nền tảng AntiScam.', externalIntel, checkedSources, missingSources }));
    } catch (err) {
        console.log('scan-object error', err && err.message);
        res.status(status.OK).send({ status: status.OK, version: config.get("app.version"), requestedOn: new Date(), type: 'unknown', finalScore: 60, riskScore: 0, result: {}, explanations: [], summary: 'Không đủ dữ liệu để quét đối tượng.', externalIntel: false, checkedSources: [], missingSources: ['Backend'] });
    }

};

app.post(`/${config.get("app.version")}/scan-object`, async function(req, res) { return handleScanObject(req, res); });
app.post('/api/scan-email', async function(req, res) { return handleScanObject(req, res, 'email'); });
app.post('/api/scan-phone', async function(req, res) { return handleScanObject(req, res, 'phone'); });
app.post('/api/scan-image', async function(req, res) { return handleScanObject(req, res, 'image'); });
app.post('/api/scan-url', async function(req, res) { return handleScanObject(req, res, 'url'); });

app.post(`/${config.get("app.version")}/file-intel`, async function(req, res) {
    try {
        const hash = String(req.body.hash || '').trim().toLowerCase();
        if (!/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/.test(hash)) return res.status(status.BAD_REQUEST).send({ message: 'invalid hash' });
        const vt = await checkVirusTotalFileHash(hash);
        res.status(status.OK).send({ status: status.OK, version: config.get("app.version"), requestedOn: new Date(), hash, reputation: vt || null, dangerous: !!(vt && vt.dangerous) });
    } catch (err) {
        res.status(status.OK).send({ status: status.OK, version: config.get("app.version"), requestedOn: new Date(), dangerous: false });
    }
});

/**
 * The route to get blacklist or whitelist sites from DB
 * this is public so the request shouldn't be authenticated
 * @param {String} typelist  type of list we wanna get ('blacklist' or 'whitelist')
 * @return {JSON} array of objects
 */
app.get(`/${config.get("app.version")}/:typelist`, async function(req, res) {
    let type = null;
    switch (req.params.typelist) {
        case "blacklist":
            type = "blacklist";
            break;
        case "whitelist":
            type = "whitelist";
            break;
        case "pornlist":
            type = "pornlist";
            break;
        default:
            return res.status(400).send(req.params.typelist + " is not a valid type of list");
    }
    try {
        const database = await getDbOrNull();
        if (!database) return res.status(status.OK).send([]);
        const result = await database.collection(type).find().toArray();
        return res.status(status.OK).send(result);
    } catch (err) {
        console.log('typelist error', err.message || err);
        return res.status(status.OK).send([]);
    }
});

app.post(`/${config.get("app.version")}/res/:resId`, authenticateJWT, function(req, res) {
    if (!req.params.resId || ['blacklist', 'whitelist'].indexOf(req.params.resId) == -1) {
        res.status(status.NOT_FOUND).send({
            status: status.NOT_FOUND,
            version: config.get("app.version"),
            requestedOn: new Date(),
            message: `${req.params.resId} not found`
        });
    }

    //get encrypted data
    fs.readFile(`secure/${req.params.resId}.json`, "utf8", function(err, data){
        if(err) throw err;

        if (data) {
            return res.status(status.OK).send({
                status: status.OK,
                version: config.get("app.version"),
                requestedOn: new Date(),
                data
            });
        }
    });
});

app.post(`/${config.get("app.version")}/importFiles/:typelist`,  upload.single('file'), async (req, res) => {
    const rawData = req.file.buffer.toString();
    const chunkData = _.chunk(JSON.parse(rawData), 1000);
    switch (req.params.typelist) {
        case "blacklist":
            type = "blacklist"
            break;
        case "whitelist":
            type = "whitelist"
            break;
        case "pornlist":
            type = "pornlist"
            break;
        default:
            res.status(400).send(req.params.typelist + " is not a valid type of list")
    }


    for (let i = 0; i < chunkData.length; i++) {
        try {
            { const database = await getDbOrNull(); if (database) await database.collection(type).insertMany(chunkData[i]); }
        } catch(err) {
            console.log(err);
        }
    }

    res.status(status.OK).send({message: 'INSERT SUCCESS'});
})

app.post(`/${config.get("app.version")}/safecheck`, async function(req, res) {
    let { url } = req.body;

    if(!url || url.length > maxLengthUrl) {
        return res.sendStatus(status.BAD_REQUEST);
    }
    try {
        const database = await getDbOrNull();
        if (!database) return res.status(status.OK).send({type: "nodata"});
        const result = await database.collection('blacklist').find().toArray();
        for(let blacksite of result) {
            let site = blacksite.url.replace('https://', '').replace('http://', '').replace('www.', '')
            let appendix = "[/]?(?:index\.[a-z0-9]+)?[/]?$";
            let trail = site.substr(site.length - 2);
            let match = false

            if (trail == "/*") {
                site = site.substr(0, site.length - 2);
                appendix = "(?:$|/.*$)";
                site = "^(?:[a-z0-9\\-_]+:\/\/)?(?:www\\.)?" + site + appendix;

                let regex = new RegExp(site, "i");
                match = url.match(regex)
                match = match ? (match.length > 0) : false
            } else {
                match = encodeURIComponent(site) == encodeURIComponent(url.replace('https://', '').replace('http://', '').replace('www.', ''))
            }

            let suffix = false
            if (blacksite.url.match(/(?:id=)(\d+)/) && url.match(/(?:id=)(\d+)/))
                suffix = (blacksite.url.match(/(?:id=)(\d+)/)[1] == url.match(/(?:id=)(\d+)/)[1])

            if(match || suffix)
                return res.status(status.OK).send({type: "unsafe"});
        }

        const wl = await database.collection('whitelist').find({url: {'$regex': url, '$options': 'i'}}).toArray();
        if(wl.length > 0) return res.status(status.OK).send({type: "safe"});
        return res.status(status.OK).send({type: "nodata"});
    } catch (err) {
        console.log('safecheck error', err.message || err);
        return res.status(status.OK).send({type: "nodata"});
    }
});

app.post(`/${config.get("app.version")}/safecheck-phishtank`, function(req, res) {
    // https://www.phishtank.com/developer_info.php
    let { url } = req.body;
    url = preProcessDomainUrl(url);

    axios({
        method: 'get',
        url: `https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt`,
        headers: {
            "Content-Type": "application/json"
        },
    }).then((result) => {
      if(result && result.data) {
        if(result.data.split('\n').includes(url)) {
            res.status(status.OK).send({type: "unsafe"});
        } else {
            res.status(status.OK).send({type: "safe"});
        }
      } else {
        res.status(status.OK).send({type: "nodata"});
      }
    });            
});

app.post(`/${config.get("app.version")}/safecheck-hellsh`, function(req, res) {
    // https://hell.sh/hosts/
    let { url } = req.body;
    url = preProcessDomainUrl(url);

    axios({
        method: 'get',
        url: `https://hell.sh/hosts/domains.txt`,
        headers: {
            "Content-Type": "application/json"
        },
    }).then((result) => {
      if(result && result.data) {
        if(result.data.split('\n').includes(url)) {
            res.status(status.OK).send({type: "unsafe"});
        } else {
            res.status(status.OK).send({type: "safe"});
        }
      } else {
        res.status(status.OK).send({type: "nodata"});
      }
    });            
});

app.post(`/${config.get("app.version")}/safecheck-oisd`, function(req, res) {
    // https://oisd.nl/?p=dl
    let { url } = req.body;
    url = preProcessDomainUrl(url);

    axios({
        method: 'get',
        url: `https://dbl.oisd.nl/`,
        headers: {
            "Content-Type": "application/json"
        },
    }).then((result) => {
      if(result && result.data) {
        if(result.data.split('\n').includes(url)) {
            res.status(status.OK).send({type: "unsafe"});
        } else {
            res.status(status.OK).send({type: "safe"});
        }
      } else {
        res.status(status.OK).send({type: "nodata"});
      }
    });            
});

app.post(`/${config.get("app.version")}/safecheck-matrix`, function(req, res) {
    // https://github.com/mypdns/matrix/tree/master/source
    let { url } = req.body;
    url = preProcessDomainUrl(url);

    let matrixPhishPromise = new Promise((resolve, reject) => {
        axios({
            method: 'get',
            url: `https://raw.githubusercontent.com/mypdns/matrix/master/source/phishing/domains.list`,
            headers: {
                "Content-Type": "application/json"
            },
        }).then((res) => {
          if(res && res.data) {
            if(res.data.split('\n').includes(url)) {
                resolve(false);
            } else {
                resolve(true);
            }
          } else {
            resolve(true);
          }
        });
    })

    let matrixAdsPromise = new Promise((resolve, reject) => {
            axios({
                method: 'get',
                url: `https://raw.githubusercontent.com/mypdns/matrix/master/source/adware/domains.list`,
                headers: {
                    "Content-Type": "application/json"
                },
            }).then((res) => {
            if(res && res.data) {
                if(res.data.split('\n').includes(url)) {
                    resolve(false);
                } else {
                    resolve(true);
                }
            } else {
                resolve(true);
            }
            });
    })

    let matrixSpywarePromise = new Promise((resolve, reject) => {
            axios({
                method: 'get',
                url: `https://raw.githubusercontent.com/mypdns/matrix/master/source/spyware/domains.list`,
                headers: {
                    "Content-Type": "application/json"
                },
            }).then((res) => {
            if(res && res.data) {
                if(res.data.split('\n').includes(url)) {
                    resolve(false);
                } else {
                    resolve(true);
                }
            } else {
                resolve(true);
            }
            });
    })

    let matrixScammingPromise = new Promise((resolve, reject) => {
            axios({
                method: 'get',
                url: `https://raw.githubusercontent.com/mypdns/matrix/master/source/scamming/domains.list`,
                headers: {
                    "Content-Type": "application/json"
                },
            }).then((res) => {
            if(res && res.data) {
                if(res.data.split('\n').includes(url)) {
                    resolve(false);
                } else {
                    resolve(true);
                }
            } else {
                resolve(true);
            }
            });
    })

    let matrixPornPromise = new Promise((resolve, reject) => {
            axios({
                method: 'get',
                url: `https://raw.githubusercontent.com/mypdns/matrix/master/source/porno-sites/domains.list`,
                headers: {
                    "Content-Type": "application/json"
                },
            }).then((res) => {
            if(res && res.data) {
                if(res.data.split('\n').includes(url)) {
                    resolve(false);
                } else {
                    resolve(true);
                }
            } else {
                resolve(true);
            }
            });
    })

    let matrixMaliciousPromise = new Promise((resolve, reject) => {
            axios({
                method: 'get',
                url: `https://raw.githubusercontent.com/mypdns/matrix/master/source/malicious/domains.list`,
                headers: {
                    "Content-Type": "application/json"
                },
            }).then((res) => {
            if(res && res.data) {
                if(res.data.split('\n').includes(url)) {
                    resolve(false);
                } else {
                    resolve(true);
                }
            } else {
                resolve(true);
            }
            });
    })    
    
    Promise.all([
        matrixPhishPromise,
        matrixAdsPromise,
        matrixSpywarePromise,
        matrixScammingPromise,
        matrixPornPromise,
        matrixMaliciousPromise,
    ]).then((result) => {
        if(result.every(val => val == true)) {
            res.status(status.OK).send({type: "safe"});
        } else {
            res.status(status.OK).send({type: "unsafe"});
        }
    });
});

app.post(`/${config.get("app.version")}/safecheck-segasec`, function(req, res) {
    // https://github.com/Segasec/feed
    let { url } = req.body;
    let rawUrl = url;
    url = preProcessDomainUrl(url);

    let segasecDomainPromise = new Promise((resolve, reject) => {
        axios({
            method: 'get',
            url: `https://raw.githubusercontent.com/Segasec/feed/master/phishing-domains.json`,
            headers: {
                "Content-Type": "application/json"
            },
        }).then((res) => {
          if(res && res.data) {
            if(res.data.includes(url)) {
                resolve(false);
            } else {
                resolve(true);
            }
          } else {
            resolve(true);
          }
        });
    })

    let segasecUrlPromise = new Promise((resolve, reject) => {
        axios({
            method: 'get',
            url: `https://raw.githubusercontent.com/Segasec/feed/master/phishing-urls.json`,
            headers: {
                "Content-Type": "application/json"
            },
        }).then((res) => {
          if(res && res.data) {
            if(res.data.includes(rawUrl)) {
                resolve(false);
            } else {
                resolve(true);
            }
          } else {
            resolve(true);
          }
        });
    })
    
    Promise.all([
        segasecDomainPromise,
        segasecUrlPromise
    ]).then((result) => {
        if(result.every(val => val == true)) {
            res.status(status.OK).send({type: "safe"});
        } else {
            res.status(status.OK).send({type: "unsafe"});
        }
    });
});

app.post(`/${config.get("app.version")}/safecheck-energized`, function(req, res) {
    // https://energized.pro/
    let { url } = req.body;
    url = preProcessDomainUrl(url);

    axios({
        method: 'get',
        url: `https://block.energized.pro/basic/formats/one-line.txt`,
        headers: {
            "Content-Type": "application/json"
        },
    }).then((result) => {
        if(result && result.data) {
            const rawData = result.data.split('\n');
            if(rawData[59].split(",").includes(url)) {
                res.status(status.OK).send({type: "unsafe"});
            } else {
                res.status(status.OK).send({type: "safe"});
            }
          } else {
            res.status(status.OK).send({type: "nodata"});
        }
    });

    // let energizedPromise = new Promise((resolve, reject) => {
    //     readFile('./config/energizedData.txt', (err, data) => {
    //         if (err) throw err;
    //         if (data) {
    //             const rawData = data.toString().split('\n');
    //             if(rawData[59].split(",").includes(url)) {
    //                 resolve(false);
    //             }
    //         } else {
    //             resolve(true)
    //         }
    //     })
    // })
});

const preProcessDomainUrl = (url) => {
    const indices = [];

    for(let i=0; i < url.length; i++) {
        if (url[i] === "/") indices.push(i);
    }
    
    if(url.includes('http') || url.includes('https')) {
        url = url.substring(0, indices[2])
        if(url.includes('http')) {
            url = url.substring(8, url.length)
        } else if(url.includes('https')) {
            url = url.substring(9, url.length)
        }
    } else {
        url = url.substring(0, indices[0])
    }
    return url;
}

function validateSubmitting(params) {
    const { rating, url } = params;
    const expUrl = /[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)?/gi;

    if (rating < 1 || rating > 5) {
        return "Rating is out of range";
    }
    else if (!url.match(new RegExp(expUrl))) {
        return `Incorrect URL ${url}`;
    }
    return "ok";
}


// Vercel serverless exports the Express app directly. No network listener is started in this module.
// MongoDB connections are opened lazily and cached in database/mongo.js.
module.exports = app;

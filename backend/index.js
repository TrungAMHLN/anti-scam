require('dotenv').config();
const config = require('config');
const express = require('express');

const cors = require('cors');
const status = require('http-status');
const jwt = require('jsonwebtoken');
const rateLimit = require("express-rate-limit");

const path = require('path');
const fs = require('fs');
const morgan = require('morgan');
const axios = require('axios');
const multer = require('multer');

const { MongoClient } = require('mongodb');
const dns = require('dns').promises;
const crypto = require('crypto');
const querystring = require('querystring');


var refreshTokens = [];
const APP_VERSION = process.env.APP_VERSION || config.get("app.version");
const APP_PORT = process.env.PORT || config.get("app.port");
const APP_DOMAIN = process.env.APP_DOMAIN || config.get("app.domain");
const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET || 'dev-access-token-secret';
const refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET || 'dev-refresh-token-secret';
const maxLengthUrl = Number(process.env.MAX_LENGTH_URL || config.get("maxLengthUrl") || 1000);

const apiLimiter = rateLimit({
    windowMs: 55 * 60 * 1000,
    max: 100,
    message: "Too many request from this IP, please try again after an hour"
  });
const reportLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 20,
    message: { message: "Bạn gửi báo cáo quá nhanh. Vui lòng thử lại sau." }
  });


const app = express();
app.set('trust proxy', true);
// Enable CORS
app.use(cors());
app.use(express.static('public'));

// Enable the use of request body parsing middleware
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
const upload = multer();
const REPORT_ALLOWED_MIME = new Set(['image/png', 'image/jpeg', 'image/jpg', 'image/webp']);
const reportUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (!REPORT_ALLOWED_MIME.has(file.mimetype)) return cb(new Error('UNSUPPORTED_REPORT_IMAGE'));
        cb(null, true);
    }
});

// Enable logging
const accessLogStream = fs.createWriteStream(path.join(__dirname, 'access.log'), { flags: 'a' })
app.use(morgan('combined', { stream: accessLogStream }))
// Health check cho Render/Railway/VPS
app.get('/', (req, res) => res.status(200).send({ ok: true, service: 'AntiScam API' }));
app.get('/health', (req, res) => res.status(200).send({ ok: true, service: 'AntiScam API' }));

// Classifier ML là tín hiệu phụ ở extension. Nếu chưa có model public trong backend,
// trả về null để extension bỏ qua ML an toàn thay vì fail request /classifier.json.
app.get('/classifier.json', (req, res) => res.status(200).json(null));

// Rate limit
app.use(`/${APP_VERSION}/rate`, apiLimiter);

// TODO: authentication / authorization functions
const clients = config.get("auth.clients");

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
// Threat intelligence helpers (server-side only). API keys are read from
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

const LIST_COLLECTIONS = new Set(['blacklist', 'whitelist', 'pornlist']);
const isValidListType = (value) => LIST_COLLECTIONS.has(String(value || '').trim());
const normalizeListDocument = (item, listType = 'blacklist') => {
    const raw = typeof item === 'string' ? { url: item } : (item || {});
    const urlValue = String(raw.url || raw.domain || raw.host || '').trim();
    const domain = normalizeHostname(urlValue);
    if (!domain) return null;
    return {
        ...raw,
        url: urlValue,
        domain,
        type: listType,
        status: raw.status || 'active',
        source: raw.source || 'manual-import',
        updatedAt: new Date(),
        createdAt: raw.createdAt ? new Date(raw.createdAt) : new Date()
    };
};
const chunkArray = (items, size) => {
    const chunks = [];
    for (let i = 0; i < items.length; i += size) chunks.push(items.slice(i, i + size));
    return chunks;
};

const withTimeout = (promise, ms, fallback) => Promise.race([
    promise.catch(() => fallback),
    new Promise(resolve => setTimeout(() => resolve(fallback), ms))
]);
const rdapDate = (events, names) => {
    if (!Array.isArray(events)) return null;
    const wanted = names.map(x => String(x).toLowerCase());
    const e = events.find(ev => wanted.includes(String(ev.eventAction || '').toLowerCase()));
    return e && e.eventDate ? e.eventDate : null;
};
const getDomainAgeRdap = async (domain) => {
    if (!domain) return { ageDays: -1, source: 'rdap', status: 'invalid' };
    return withTimeout((async () => {
        const resp = await axios.get(`https://rdap.org/domain/${domain}`, { timeout: 4500 });
        const registrationDate = rdapDate(resp.data && resp.data.events, ['registration']);
        const expirationDate = rdapDate(resp.data && resp.data.events, ['expiration', 'expiry']);
        const ageDays = registrationDate ? Math.floor((Date.now() - new Date(registrationDate).getTime()) / (1000 * 60 * 60 * 24)) : -1;
        return { ageDays, registrationDate, expirationDate, source: 'rdap' };
    })(), 5000, { ageDays: -1, source: 'rdap', status: 'timeout' });
};
const urlIdForVirusTotal = (url) => Buffer.from(url).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const checkVirusTotal = async (url) => {
    const key = process.env.VIRUSTOTAL_API_KEY;
    if (!key) return null;
    return withTimeout((async () => {
        const vtUrl = `https://www.virustotal.com/api/v3/urls/${urlIdForVirusTotal(url)}`;
        const resp = await axios.get(vtUrl, { headers: { 'x-apikey': key }, timeout: 6500 });
        const stats = (((resp.data || {}).data || {}).attributes || {}).last_analysis_stats || {};
        const malicious = (stats.malicious || 0) + (stats.suspicious || 0);
        return { source: 'VirusTotal', malicious, rawStats: stats, dangerous: malicious > 0 };
    })(), 7000, null);
};
const checkUrlHaus = async (url, domain) => withTimeout((async () => {
    const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
    const urlResp = await axios.post('https://urlhaus-api.abuse.ch/v1/url/', querystring.stringify({ url }), { headers, timeout: 5500 }).catch(() => null);
    const hostResp = await axios.post('https://urlhaus-api.abuse.ch/v1/host/', querystring.stringify({ host: domain }), { headers, timeout: 5500 }).catch(() => null);
    const hitUrl = urlResp && urlResp.data && urlResp.data.query_status === 'ok';
    const hitHost = hostResp && hostResp.data && hostResp.data.query_status === 'ok';
    return { source: 'URLhaus', dangerous: !!(hitUrl || hitHost), urlStatus: urlResp && urlResp.data && urlResp.data.query_status, hostStatus: hostResp && hostResp.data && hostResp.data.query_status };
})(), 7000, null);
const checkThreatFox = async (domain) => withTimeout((async () => {
    const key = process.env.THREATFOX_API_KEY;
    const headers = { 'Content-Type': 'application/json' };
    if (key) headers['Auth-Key'] = key;
    const resp = await axios.post('https://threatfox-api.abuse.ch/api/v1/', { query: 'search_ioc', search_term: domain }, { headers, timeout: 5500 });
    return { source: 'ThreatFox', dangerous: resp.data && resp.data.query_status === 'ok', status: resp.data && resp.data.query_status };
})(), 6500, null);
const resolveIp = async (domain) => {
    try { const r = await dns.lookup(domain); return r && r.address; } catch (_) { return null; }
};
const checkAbuseIPDB = async (ip) => {
    const key = process.env.ABUSEIPDB_API_KEY;
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
const checkMalwareReputation = async (url, domain, ip) => {
    const results = await Promise.all([
        checkVirusTotal(url), checkUrlHaus(url, domain), checkThreatFox(domain), checkAbuseIPDB(ip)
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
        if (!db) return { reportCount: 0 };
        const count = await db.collection('reports').countDocuments({ domain, status: { $ne: 'rejected' } });
        const latest = await db.collection('reports').find({ domain, status: { $ne: 'rejected' } }).sort({ createdAt: -1 }).limit(3).toArray();
        return { reportCount: count, latest: latest.map(x => ({ category: x.category, description: x.description, time: x.createdAt })) };
    } catch (_) { return { reportCount: 0 }; }
};

const REPORT_CATEGORIES = new Set([
    'phishing_login',
    'scam_fraud',
    'malware',
    'fake_store',
    'spam',
    'suspicious_website',
    'other'
]);

const getClientIp = (req) => {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) return String(forwarded).split(',')[0].trim();
    return String(req.headers['cf-connecting-ip'] || req.headers['x-real-ip'] || req.ip || req.connection.remoteAddress || '')
        .replace(/^::ffff:/, '')
        .trim();
};

const isPrivateIp = (ip) => /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|::1|localhost)/.test(String(ip || ''));

const lookupGeoIp = async (ip) => {
    try {
        if (!ip || isPrivateIp(ip)) return { country: '', region: '', city: '' };
        const resp = await axios.get(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,regionName,city`, { timeout: 2500 });
        if (!resp.data || resp.data.status !== 'success') return { country: '', region: '', city: '' };
        return { country: resp.data.country || '', region: resp.data.regionName || '', city: resp.data.city || '' };
    } catch (_) {
        return { country: '', region: '', city: '' };
    }
};

const buildDeviceFingerprint = (req, ip) => {
    const raw = [
        req.body && req.body.deviceId || '',
        req.headers['user-agent'] || '',
        req.headers['accept-language'] || '',
        req.body && req.body.browserLanguage || '',
        ip || ''
    ].join('|');
    return crypto.createHash('sha256').update(raw).digest('hex');
};

const validateReportPayload = (body) => {
    const urlValue = String(body.url || '').trim();
    let parsed;
    try { parsed = new URL(urlValue); } catch (_) { return { error: 'URL không hợp lệ.' }; }
    if (!['http:', 'https:'].includes(parsed.protocol)) return { error: 'URL không hợp lệ.' };
    if (urlValue.length > maxLengthUrl) return { error: 'URL không hợp lệ.' };

    const domain = normalizeHostname(body.domain || parsed.hostname);
    if (!domain || domain !== normalizeHostname(parsed.hostname)) return { error: 'URL không hợp lệ.' };

    const category = String(body.category || '').trim();
    if (!REPORT_CATEGORIES.has(category)) return { error: 'Vui lòng chọn loại báo cáo.' };

    const description = String(body.description || '').trim();
    if (description.length < 20) return { error: 'Mô tả phải có tối thiểu 20 ký tự.' };
    if (description.length > 1000) return { error: 'Mô tả không được vượt quá 1000 ký tự.' };

    return { url: parsed.href, domain, category, description };
};

const saveReportScreenshot = async (file) => {
    if (!file) return '';
    const extMap = { 'image/png': '.png', 'image/jpeg': '.jpg', 'image/jpg': '.jpg', 'image/webp': '.webp' };
    const ext = extMap[file.mimetype] || path.extname(file.originalname || '').toLowerCase();
    if (!['.png', '.jpg', '.jpeg', '.webp'].includes(ext)) throw new Error('UNSUPPORTED_REPORT_IMAGE');
    const uploadDir = path.join(__dirname, 'public', 'report-screenshots');
    await fs.promises.mkdir(uploadDir, { recursive: true });
    const filename = `${Date.now()}-${crypto.randomBytes(12).toString('hex')}${ext === '.jpeg' ? '.jpg' : ext}`;
    await fs.promises.writeFile(path.join(uploadDir, filename), file.buffer);
    return `/report-screenshots/${filename}`;
};

app.post(`/${APP_VERSION}/initSession`, (req, res) => {
    const { app, secret } = req.body;
    const client = clients.find(u => { return u.app === app && u.secret === secret });

    if (client) {
        //TODO: generate an access token
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

        refreshTokens.push(refreshToken);


        res.json({
            version: APP_VERSION,
            requestedOn: new Date(),
            token: accessToken,
            refresh: refreshToken,
        });
    }
    else {
        res.status(status.FORBIDDEN).send({
            version: APP_VERSION,
            requestedOn: new Date(),
            message: `Client application credential incorrect. ${status['401_MESSAGE']}`});
    }
});

app.post(`/${APP_VERSION}/token`, (req, res) => {
    const { token } = req.body;

    if (!token) {
        return res.sendStatus(401);
    }

    if (!refreshTokens.includes(token)) {
        return res.sendStatus(403);
    }

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
            version: APP_VERSION,
            requestedOn: new Date(),
            token: accessToken
        });
    });
});

app.post(`/${APP_VERSION}/closeSession`, (req, res) => {
    const { token } = req.body;
    refreshTokens = refreshTokens.filter(t => t !== token);

    res.status(status.OK).send({
        status: status.OK,
        version: APP_VERSION,
        requestedOn: new Date(),
        message: "Session closed"
      });
});

app.get(`/${APP_VERSION}/ping`, function(req, res){
  res.status(status.OK).send({
      status: status.OK,
      version: APP_VERSION,
      requestedOn: new Date(),
    });
})

app.post(`/${APP_VERSION}/rate`, authenticateJWT, function(req, res) {
    //TODO: store request to file
    const params = {  time: new Date(), ...req.body, ip: req.ip};
    const msg = validateSubmitting(params);
    if (msg.indexOf("ok") == -1) {
        res.status(status.BAD_REQUEST).send({
            status: status.BAD_REQUEST,
            version: APP_VERSION,
            requestedOn: new Date(),
            "message": msg
        });
    }
    else {
        if (params) {
            db.collection("rating").insertOne(params);
        }

        res.status(status.OK).send({
            status: status.OK,
            version: APP_VERSION,
            requestedOn: new Date(),
            "message":"ok"
        });
    }
})


app.get(`/${APP_VERSION}/intel`, async function(req, res) {
    try {
        const rawUrl = req.query.url || req.query.domain;
        if (!rawUrl || String(rawUrl).length > maxLengthUrl) return res.sendStatus(status.BAD_REQUEST);
        const url = normalizeUrlInput(String(rawUrl));
        const domain = normalizeHostname(String(rawUrl));
        if (!domain) return res.sendStatus(status.BAD_REQUEST);
        const ip = await resolveIp(domain);
        const [domainAge, malware, dnsIntel, community] = await Promise.all([
            getDomainAgeRdap(domain),
            checkMalwareReputation(url, domain, ip),
            getDnsIntel(domain, ip),
            getCommunityReportSummary(domain)
        ]);
        res.status(status.OK).send({
            status: status.OK,
            version: APP_VERSION,
            requestedOn: new Date(),
            domain,
            domainAge,
            malware,
            dns: dnsIntel,
            community
        });
    } catch (err) {
        console.log('intel error', err && err.message);
        res.status(status.OK).send({ status: status.OK, version: APP_VERSION, requestedOn: new Date(), malware: { dangerous: false, sources: [] }, community: { reportCount: 0 } });
    }
});

app.post('/api/report', reportLimiter, function(req, res, next) {
    reportUpload.single('screenshot')(req, res, function(err) {
        if (!err) return next();
        if (err.code === 'LIMIT_FILE_SIZE') return res.status(status.BAD_REQUEST).send({ message: 'File vượt quá 5MB.' });
        if (err.message === 'UNSUPPORTED_REPORT_IMAGE') return res.status(status.BAD_REQUEST).send({ message: 'Định dạng ảnh không được hỗ trợ.' });
        return res.status(status.BAD_REQUEST).send({ message: 'Không thể gửi báo cáo. Vui lòng thử lại.' });
    });
}, async function(req, res) {
    try {
        const validated = validateReportPayload(req.body || {});
        if (validated.error) return res.status(status.BAD_REQUEST).send({ message: validated.error });
        if (!db) return res.status(status.SERVICE_UNAVAILABLE).send({ message: 'Không thể gửi báo cáo. Vui lòng thử lại.' });

        const ip = getClientIp(req);
        const geo = await lookupGeoIp(ip);
        const deviceFingerprint = buildDeviceFingerprint(req, ip);
        const now = new Date();
        const screenshotUrl = await saveReportScreenshot(req.file);

        const report = {
            url: validated.url,
            domain: validated.domain,
            category: validated.category,
            description: validated.description,
            screenshotUrl,
            status: 'pending',
            ip,
            country: geo.country,
            region: geo.region,
            city: geo.city,
            deviceFingerprint,
            extensionVersion: String(req.body.extensionVersion || '').slice(0, 50),
            browserName: String(req.body.browserName || '').slice(0, 80),
            browserLanguage: String(req.body.browserLanguage || '').slice(0, 40),
            userAgent: String(req.body.userAgent || req.headers['user-agent'] || '').slice(0, 500),
            pageTitle: String(req.body.pageTitle || '').slice(0, 300),
            clientTimestamp: req.body.timestamp ? new Date(req.body.timestamp) : null,
            createdAt: now,
            updatedAt: now
        };

        await db.collection('reports').insertOne(report);
        res.status(status.OK).send({
            status: status.OK,
            version: APP_VERSION,
            requestedOn: new Date(),
            message: 'Báo cáo đã được gửi thành công.',
            reportId: report._id,
            domain: report.domain
        });
    } catch (err) {
        if (err && err.code === 11000) {
            return res.status(status.CONFLICT).send({ message: 'Bạn đã gửi báo cáo cho tên miền này trước đó.' });
        }
        console.log('report error', err && err.message);
        res.status(status.INTERNAL_SERVER_ERROR).send({ message: 'Không thể gửi báo cáo. Vui lòng thử lại.' });
    }
});

/**
 * The route to get blacklist or whitelist sites from DB
 * this is public so the request shouldn't be authenticated
 * @param {String} typelist  type of list we wanna get ('blacklist' or 'whitelist')
 * @return {JSON} array of objects
 */
app.get(`/${APP_VERSION}/:typelist`, async function(req, res) {
    const type = String(req.params.typelist || '').trim();
    if (!isValidListType(type)) return res.status(status.BAD_REQUEST).send(`${type} is not a valid type of list`);
    if (!db) return res.status(status.SERVICE_UNAVAILABLE).send([]);

    try {
        const result = await db.collection(type)
            .find({ $or: [{ status: { $exists: false } }, { status: 'active' }] })
            .project({ url: 1, domain: 1, type: 1, source: 1, updatedAt: 1 })
            .toArray();
        res.status(status.OK).send(result.map(item => ({
            ...item,
            url: item.url || item.domain
        })).filter(item => item.url));
    } catch (err) {
        console.log(`${type} list error`, err && err.message);
        res.status(status.INTERNAL_SERVER_ERROR).send([]);
    }

})

app.post(`/${APP_VERSION}/res/:resId`, authenticateJWT, function(req, res) {
    if (!req.params.resId || ['blacklist', 'whitelist'].indexOf(req.params.resId) == -1) {
        res.status(status.NOT_FOUND).send({
            status: status.NOT_FOUND,
            version: APP_VERSION,
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
                version: APP_VERSION,
                requestedOn: new Date(),
                data
            });
        }
    });
});

app.post(`/${APP_VERSION}/importFiles/:typelist`,  upload.single('file'), async (req, res) => {
    const type = String(req.params.typelist || '').trim();
    if (!isValidListType(type)) return res.status(status.BAD_REQUEST).send(`${type} is not a valid type of list`);
    if (!req.file || !req.file.buffer) return res.status(status.BAD_REQUEST).send({ message: 'file is required' });

    const rawData = req.file.buffer.toString();
    const parsed = JSON.parse(rawData);
    const rows = Array.isArray(parsed) ? parsed : [parsed];
    const normalizedRows = rows.map(item => normalizeListDocument(item, type)).filter(Boolean);
    const chunkData = chunkArray(normalizedRows, 1000);
    let upserted = 0;

    for (let i = 0; i < chunkData.length; i++) {
        try {
            const ops = chunkData[i].map(item => ({
                updateOne: {
                    filter: { url: item.url },
                    update: { $set: { ...item, updatedAt: new Date() }, $setOnInsert: { createdAt: item.createdAt || new Date() } },
                    upsert: true
                }
            }));
            if (ops.length) {
                const result = await db.collection(type).bulkWrite(ops, { ordered: false });
                upserted += (result.upsertedCount || 0) + (result.modifiedCount || 0);
            }
        } catch(err) {
            console.log(`${type} import error`, err && err.message);
        }
    }

    res.status(status.OK).send({ message: 'INSERT SUCCESS', type, received: rows.length, valid: normalizedRows.length, upserted });
})

app.post(`/${APP_VERSION}/safecheck`, function(req, res) {
    let { url } = req.body;

    if(!url || url.length > maxLengthUrl) {
        return res.sendStatus(status.BAD_REQUEST);
    }
    db.collection('blacklist').find().toArray().then(result => {
        // Check if current url exist in our Blacklist :
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

            // Check if the URL has suffix or not, for ex: https://www.facebook.com/profile.php?id=100060251539767
            let suffix = false
            if (blacksite.url.match(/(?:id=)(\d+)/) && url.match(/(?:id=)(\d+)/))
                suffix = (blacksite.url.match(/(?:id=)(\d+)/)[1] == url.match(/(?:id=)(\d+)/)[1])

            if(match || suffix)
                return res.status(status.OK).send({type: "unsafe"});
        }

        db.collection('whitelist').find({url: {'$regex': url, '$options': 'i'}}).toArray().then(result => {
            if(result.length > 0) {
                res.status(status.OK).send({type: "safe"});
            } else {
                res.status(status.OK).send({type: "nodata"});
            }
        })

    })
});

app.post(`/${APP_VERSION}/safecheck-phishtank`, function(req, res) {
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

app.post(`/${APP_VERSION}/safecheck-hellsh`, function(req, res) {
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

app.post(`/${APP_VERSION}/safecheck-oisd`, function(req, res) {
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

app.post(`/${APP_VERSION}/safecheck-matrix`, function(req, res) {
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

app.post(`/${APP_VERSION}/safecheck-segasec`, function(req, res) {
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

app.post(`/${APP_VERSION}/safecheck-energized`, function(req, res) {
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


var db = null;
const mongoUsername = process.env.MONGO_USERNAME || config.get("db.username");
const mongoPassword = process.env.MONGO_PASSWORD || config.get("db.password");
const mongoHost = process.env.MONGO_HOST || config.get("db.url");
const mongoPort = process.env.MONGO_PORT || config.get("db.port");
const fallbackMongoDatabase = process.env.MONGO_DATABASE || config.get("db.name");
const mongoUrl = process.env.MONGO_URI || `mongodb://${mongoUsername}:${mongoPassword}@${mongoHost}:${mongoPort}/${fallbackMongoDatabase}`;
const getMongoDatabaseName = () => {
    if (process.env.MONGO_DATABASE) return process.env.MONGO_DATABASE;
    if (process.env.MONGO_URI) {
        try {
            const parsed = new URL(process.env.MONGO_URI);
            const dbName = decodeURIComponent((parsed.pathname || '').replace(/^\//, '').trim());
            if (dbName) return dbName;
        } catch (_) {}
    }
    return fallbackMongoDatabase;
};
MongoClient.connect(mongoUrl, {
    useUnifiedTopology: true,
}, (err, database) => {
    // ... start the server
    if (err) {
        console.log('error: ', err);
        return;
    }

    db = database.db(getMongoDatabaseName());
    db.collection('reports').createIndex({ deviceFingerprint: 1, domain: 1 }, { unique: true }).catch(err => console.log('reports index error', err && err.message));
    db.collection('reports').createIndex({ domain: 1, createdAt: -1 }).catch(err => console.log('reports domain index error', err && err.message));
    ['blacklist', 'whitelist', 'pornlist'].forEach((type) => {
        db.collection(type).createIndex({ url: 1 }, { unique: true, sparse: true }).catch(err => console.log(`${type} url index error`, err && err.message));
        db.collection(type).createIndex({ domain: 1, status: 1 }).catch(err => console.log(`${type} domain index error`, err && err.message));
    });
    db.collection('rating').createIndex({ url: 1, time: -1 }).catch(err => console.log('rating index error', err && err.message));
    console.info("Launch the API Server at ", APP_DOMAIN, ":", APP_PORT);
    app.listen(APP_PORT);
 });

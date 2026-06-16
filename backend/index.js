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
const multer = require('multer');
const _ = require('lodash/array');
const { readFile } = require('fs');
const { MongoClient } = require('mongodb');
const dns = require('dns').promises;
const crypto = require('crypto');
const querystring = require('querystring');

const fields = ['time','rating', 'url', 'ip', 'client'];
const opts = { fields, header: false };
const parser = new Parser(opts);

var refreshTokens = [];
const accessTokenSecret = config.get("auth.accessTokenSecret");
const refreshTokenSecret = config.get("auth.refreshTokenSecret");
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

// Enable logging
const accessLogStream = fs.createWriteStream(path.join(__dirname, 'access.log'), { flags: 'a' })
app.use(morgan('combined', { stream: accessLogStream }))
// Rate limit
app.use(`/${config.get("app.version")}/rate`, apiLimiter);

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
const checkUrlHaus = async (url, domain) => withTimeout((async () => {
    const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
    const urlResp = await axios.post('https://urlhaus-api.abuse.ch/v1/url/', querystring.stringify({ url }), { headers, timeout: 5500 }).catch(() => null);
    const hostResp = await axios.post('https://urlhaus-api.abuse.ch/v1/host/', querystring.stringify({ host: domain }), { headers, timeout: 5500 }).catch(() => null);
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
        const count = await db.collection('community_reports').countDocuments({ domain });
        const latest = await db.collection('community_reports').find({ domain }).sort({ time: -1 }).limit(3).toArray();
        return { reportCount: count, latest: latest.map(x => ({ reason: x.reason, time: x.time })) };
    } catch (_) { return { reportCount: 0 }; }
};

app.post(`/${config.get("app.version")}/initSession`, (req, res) => {
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

app.post(`/${config.get("app.version")}/token`, (req, res) => {
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
            version: config.get("app.version"),
            requestedOn: new Date(),
            token: accessToken
        });
    });
});

app.post(`/${config.get("app.version")}/closeSession`, (req, res) => {
    const { token } = req.body;
    refreshTokens = refreshTokens.filter(t => t !== token);

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

app.post(`/${config.get("app.version")}/rate`, authenticateJWT, function(req, res) {
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
            db.collection("rating").insertOne(params);
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


app.get(`/${config.get("app.version")}/intel`, async function(req, res) {
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
            version: config.get("app.version"),
            requestedOn: new Date(),
            domain,
            domainAge,
            malware,
            dns: dnsIntel,
            community
        });
    } catch (err) {
        console.log('intel error', err && err.message);
        res.status(status.OK).send({ status: status.OK, version: config.get("app.version"), requestedOn: new Date(), malware: { dangerous: false, sources: [] }, community: { reportCount: 0 } });
    }
});

app.post(`/${config.get("app.version")}/community-report`, apiLimiter, async function(req, res) {
    try {
        const rawUrl = req.body.url || req.body.domain;
        const domain = normalizeHostname(rawUrl);
        const reason = String(req.body.reason || '').trim().slice(0, 300);
        if (!domain || !reason) return res.status(status.BAD_REQUEST).send({ message: 'domain and reason are required' });
        const params = { domain, reason, url: String(req.body.url || '').slice(0, maxLengthUrl), time: new Date(), ip: req.ip, client: req.headers['user-agent'] || '' };
        if (db) await db.collection('community_reports').insertOne(params);
        const community = await getCommunityReportSummary(domain);
        res.status(status.OK).send({ status: status.OK, version: config.get("app.version"), requestedOn: new Date(), message: 'ok', domain, community });
    } catch (err) {
        console.log('community-report error', err && err.message);
        res.status(status.INTERNAL_SERVER_ERROR).send({ message: 'could not store report' });
    }
});

/**
 * The route to get blacklist or whitelist sites from DB
 * this is public so the request shouldn't be authenticated
 * @param {String} typelist  type of list we wanna get ('blacklist' or 'whitelist')
 * @return {JSON} array of objects
 */
app.get(`/${config.get("app.version")}/:typelist`, function(req, res) {
    let type = null
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

    db.collection(type).find().toArray().then(result => {
        res.status(status.OK).send(result);
    })

})

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
            await db.collection(type).insertMany(chunkData[i]);
        } catch(err) {
            console.log(err);
        }
    }

    res.status(status.OK).send({message: 'INSERT SUCCESS'});
})

app.post(`/${config.get("app.version")}/safecheck`, function(req, res) {
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
        // If doesn't exists in our DB, check other APIs :

        // Google API Promise
        // let googleSafeCheckPromise = new Promise((resolve, reject) => {
        //     axios({
        //         method: 'post',
        //         url: `${config.get("gcloud.safecheckUrl")}?key=${config.get("gcloud.key")}`,
        //         headers: {
        //             "Content-Type": "application/json"
        //         },
        //         data:  {
        //             client: {
        //               clientId: "antiscam",
        //               clientVersion: "1.0.0"
        //             },
        //             threatInfo: {
        //               threatTypes: [ "MALWARE",
        //                              "SOCIAL_ENGINEERING",
        //                              "UNWANTED_SOFTWARE",
        //                              "MALICIOUS_BINARY",
        //                              "POTENTIALLY_HARMFUL_APPLICATION"],
        //               platformTypes: ["ANY_PLATFORM"],
        //               threatEntryTypes: ["URL"],
        //               threatEntries: [
        //                 { url: url + "/" }
        //               ]
        //             }
        //         }
        //     }).then((gRes) => {
        //       if(gRes && gRes.data && gRes.data.matches && gRes.data.matches.length > 0) {
        //         resolve(false);
        //       } else {
        //         resolve(true);
        //       }
        //     });
        // })

        // Promise.all([
        //         googleSafeCheckPromise,
        //     ]).then((result) => {
        //     if(result.every(val => val == true)) {
                
        //     } else {
        //         res.status(status.OK).send({type: "unsafe"});
        //     }
        // });

    })
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


var db = null;
const url = `mongodb://${config.get("db.username")}:${config.get("db.password")}@${config.get("db.url")}:${config.get("db.port")}/${config.get("db.name")}`;
MongoClient.connect(url, {
    useUnifiedTopology: true,
}, (err, database) => {
    // ... start the server
    if (err) {
        console.log('error: ', err);
        return;
    }

    db = database.db(config.get("db.name"));
    console.info("Launch the API Server at ", config.get("app.domain"), ":", config.get("app.port"));
    app.listen(config.get("app.port"));
 });

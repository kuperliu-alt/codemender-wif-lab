const http = require('http');
const net = require('net');
const dns = require('dns');
const productRepo = require('../data/repositories/productRepository');

function parseIPv6(ipStr) {
    let ip = ipStr.trim().toLowerCase().replace(/^\[|\]$/g, '');
    if (ip.includes('.')) {
        const lastColon = ip.lastIndexOf(':');
        if (lastColon === -1) return null;
        const ipv4Part = ip.substring(lastColon + 1);
        const parts = ipv4Part.split('.').map(Number);
        if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
            return null;
        }
        const hi = ((parts[0] << 8) | parts[1]).toString(16);
        const lo = ((parts[2] << 8) | parts[3]).toString(16);
        const prefix = ip.substring(0, lastColon);
        ip = `${prefix}:${hi}:${lo}`;
    }

    let parts = ip.split(':');
    if (ip.includes('::')) {
        const doubleColonIndex = ip.indexOf('::');
        const left = ip.substring(0, doubleColonIndex).split(':').filter(Boolean);
        const right = ip.substring(doubleColonIndex + 2).split(':').filter(Boolean);
        const missing = 8 - (left.length + right.length);
        if (missing < 0) return null;
        const middle = new Array(missing).fill('0');
        parts = [...left, ...middle, ...right];
    }

    if (parts.length !== 8) return null;
    const words = parts.map(p => parseInt(p, 16));
    if (words.some(w => isNaN(w) || w < 0 || w > 0xffff)) return null;
    return words;
}

function isForbiddenIPv4(a, b, c, d) {
    // 0.0.0.0/8 (broadcast/this host)
    if (a === 0) return true;
    // 10.0.0.0/8 (private)
    if (a === 10) return true;
    // 127.0.0.0/8 (loopback)
    if (a === 127) return true;
    // 169.254.0.0/16 (link-local / cloud metadata)
    if (a === 169 && b === 254) return true;
    // 172.16.0.0/12 (private)
    if (a === 172 && b >= 16 && b <= 31) return true;
    // 192.168.0.0/16 (private)
    if (a === 192 && b === 168) return true;
    // 100.64.0.0/10 (carrier-grade NAT)
    if (a === 100 && b >= 64 && b <= 127) return true;
    // 192.0.0.0/24, 192.0.2.0/24 (test/reserved)
    if (a === 192 && b === 0) return true;
    // 198.18.0.0/15 (benchmarking)
    if (a === 198 && (b === 18 || b === 19)) return true;
    // 198.51.100.0/24
    if (a === 198 && b === 51 && c === 100) return true;
    // 203.0.113.0/24
    if (a === 203 && b === 0 && c === 113) return true;
    // >= 224 (multicast / reserved / broadcast)
    if (a >= 224) return true;
    return false;
}

function isForbiddenHost(rawHost) {
    if (!rawHost) return true;
    const host = rawHost.trim().toLowerCase().replace(/^\[|\]$/g, '');

    if (
        host.includes('internal-network') ||
        host === 'localhost' ||
        host.endsWith('.localhost') ||
        host.endsWith('.local') ||
        host.endsWith('.internal') ||
        host === 'ip6-localhost' ||
        host === 'ip6-loopback' ||
        host.endsWith('.ip6-localhost') ||
        host.endsWith('.ip6-loopback')
    ) {
        return true;
    }

    const ipType = net.isIP(host);
    if (ipType === 4) {
        const parts = host.split('.').map(Number);
        if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
            return true;
        }
        return isForbiddenIPv4(parts[0], parts[1], parts[2], parts[3]);
    } else if (ipType === 6) {
        const words = parseIPv6(host);
        if (!words) return true;

        // Loopback ::1
        if (words[0] === 0 && words[1] === 0 && words[2] === 0 && words[3] === 0 &&
            words[4] === 0 && words[5] === 0 && words[6] === 0 && words[7] === 1) {
            return true;
        }
        // Unspecified ::
        if (words.every(w => w === 0)) {
            return true;
        }
        // IPv4-mapped (::ffff:x.x.x.x)
        if (words[0] === 0 && words[1] === 0 && words[2] === 0 && words[3] === 0 && words[4] === 0 && words[5] === 0xffff) {
            return isForbiddenIPv4((words[6] >> 8) & 0xff, words[6] & 0xff, (words[7] >> 8) & 0xff, words[7] & 0xff);
        }
        // IPv4-translated (::ffff:0:x.x.x.x)
        if (words[0] === 0 && words[1] === 0 && words[2] === 0 && words[3] === 0 && words[4] === 0xffff && words[5] === 0) {
            return isForbiddenIPv4((words[6] >> 8) & 0xff, words[6] & 0xff, (words[7] >> 8) & 0xff, words[7] & 0xff);
        }
        // IPv4-compatible (::x.x.x.x)
        if (words[0] === 0 && words[1] === 0 && words[2] === 0 && words[3] === 0 && words[4] === 0 && words[5] === 0) {
            return isForbiddenIPv4((words[6] >> 8) & 0xff, words[6] & 0xff, (words[7] >> 8) & 0xff, words[7] & 0xff);
        }
        // Well-Known Prefix (64:ff9b::/96)
        if (words[0] === 0x64 && words[1] === 0xff9b && words[2] === 0 && words[3] === 0 && words[4] === 0 && words[5] === 0) {
            return isForbiddenIPv4((words[6] >> 8) & 0xff, words[6] & 0xff, (words[7] >> 8) & 0xff, words[7] & 0xff);
        }
        // Unique local address (fc00::/7)
        if ((words[0] & 0xfe00) === 0xfc00) return true;
        // Link-local address (fe80::/10)
        if ((words[0] & 0xffc0) === 0xfe80) return true;
        // Site-local address (fec0::/10)
        if ((words[0] & 0xffc0) === 0xfec0) return true;
        // Multicast (ff00::/8)
        if ((words[0] & 0xff00) === 0xff00) return true;
        // Documentation (2001:db8::/32)
        if (words[0] === 0x2001 && words[1] === 0xdb8) return true;
        // Discard prefix (100::/64)
        if (words[0] === 0x100 && words[1] === 0 && words[2] === 0 && words[3] === 0) return true;

        return false;
    }

    return false;
}

function safeLookup(hostname, options, callback) {
    if (typeof options === 'function') {
        callback = options;
        options = {};
    }
    dns.lookup(hostname, options, (err, address, family) => {
        if (err) return callback(err);
        if (Array.isArray(address)) {
            for (const item of address) {
                if (isForbiddenHost(item.address)) {
                    return callback(new Error("Forbidden access rule triggered."));
                }
            }
        } else {
            if (isForbiddenHost(address)) {
                return callback(new Error("Forbidden access rule triggered."));
            }
        }
        return callback(null, address, family);
    });
}

function extractHostname(target) {
    if (!target) return null;
    let raw = '';
    if (typeof target === 'string') {
        raw = target.trim();
    } else if (typeof target === 'object') {
        if (target.host) {
            raw = String(target.host).trim();
        } else if (target.hostname) {
            raw = String(target.hostname).trim();
        } else if (target.href) {
            raw = String(target.href).trim();
        } else if (target.url) {
            raw = String(target.url).trim();
        }
    }
    if (!raw) return null;

    try {
        if (raw.startsWith('http://') || raw.startsWith('https://')) {
            return new URL(raw).hostname;
        }
        if (net.isIPv6(raw)) {
            return new URL(`http://[${raw}]`).hostname;
        }
        return new URL(`http://${raw}`).hostname;
    } catch (e) {
        const hostPart = raw.split('/')[0].split(':')[0].replace(/^\[|\]$/g, '');
        return hostPart || null;
    }
}

exports.search = (q) => productRepo.filterProducts(q);

exports.fetchRemoteAsset = (target, cb) => {
    if (!target) {
        return cb(new Error("Forbidden access rule triggered."));
    }

    const hostCandidates = [];
    let targetStr = '';

    if (typeof target === 'string') {
        targetStr = target;
        hostCandidates.push(target);
    } else if (typeof target === 'object') {
        if (target.socketPath || 'socketPath' in target) {
            return cb(new Error("Forbidden access rule triggered."));
        }
        targetStr = JSON.stringify(target);
        if (target.host) hostCandidates.push(target.host);
        if (target.hostname) hostCandidates.push(target.hostname);
        if (target.href) hostCandidates.push(target.href);
        if (target.url) hostCandidates.push(target.url);
    }

    if (hostCandidates.length === 0 || targetStr.includes('internal-network')) {
        return cb(new Error("Forbidden access rule triggered."));
    }

    const extractedHosts = [];
    for (const candidate of hostCandidates) {
        const hostname = extractHostname(candidate);
        if (!hostname || isForbiddenHost(hostname)) {
            return cb(new Error("Forbidden access rule triggered."));
        }
        extractedHosts.push(hostname);
    }

    let pending = extractedHosts.length;
    let completed = false;

    const onResolved = (err, addresses) => {
        if (completed) return;
        if (err || !addresses || addresses.length === 0) {
            completed = true;
            return cb(new Error("Forbidden access rule triggered."));
        }
        for (const item of addresses) {
            if (isForbiddenHost(item.address)) {
                completed = true;
                return cb(new Error("Forbidden access rule triggered."));
            }
        }
        pending--;
        if (pending === 0) {
            completed = true;
            makeRequest();
        }
    };

    for (const host of extractedHosts) {
        dns.lookup(host, { all: true }, onResolved);
    }

    function makeRequest() {
        const reqOptions = { lookup: safeLookup };
        let req;
        if (typeof target === 'string') {
            req = http.get(target, reqOptions, (proxyRes) => {
                let body = '';
                proxyRes.on('data', chunk => body += chunk);
                proxyRes.on('end', () => cb(null, body.substring(0, 50)));
            });
        } else if (typeof target === 'object') {
            const opts = Object.assign({}, target, reqOptions);
            delete opts.socketPath;
            req = http.get(opts, (proxyRes) => {
                let body = '';
                proxyRes.on('data', chunk => body += chunk);
                proxyRes.on('end', () => cb(null, body.substring(0, 50)));
            });
        }
        if (req) {
            req.on('error', err => cb(err));
        }
    }
};

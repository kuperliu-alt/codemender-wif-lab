const http = require('http');
const dns = require('dns');
const net = require('net');
const productRepo = require('../data/repositories/productRepository');

const ALLOWED_HOSTS = Object.freeze({
    'cdn.example.com': 'cdn.example.com',
    'assets.example.com': 'assets.example.com',
    'example.com': 'example.com'
});

function isPrivateOrReservedIPv4(ip) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return true;
    const [a, b, c] = parts;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 192 && b === 0) return true;
    if (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) return true;
    if (a === 203 && b === 0 && c === 113) return true;
    if (a >= 224) return true;
    return false;
}

function isForbiddenAddress(addr) {
    if (typeof addr !== 'string' || !addr) return true;
    const clean = addr.trim().toLowerCase().replace(/^\[|\]$/g, '');
    const ipType = net.isIP(clean);
    if (ipType === 4) {
        return isPrivateOrReservedIPv4(clean);
    }
    if (ipType === 6) {
        if (clean === '::1' || clean === '::' || clean.startsWith('fc') || clean.startsWith('fd') || /^fe[89ab]/i.test(clean) || clean.startsWith('ff') || clean.startsWith('::')) {
            return true;
        }
        return true; // Only allow public IPv4 resolution for external assets
    }
    return true;
}

function safeLookup(hostname, options, callback) {
    const cb = typeof options === 'function' ? options : callback;
    if (!Object.prototype.hasOwnProperty.call(ALLOWED_HOSTS, hostname)) {
        return cb(new Error("Forbidden access rule triggered."));
    }
    const canonicalHost = ALLOWED_HOSTS[hostname];
    dns.lookup(canonicalHost, { family: 4, all: true }, (err, addresses) => {
        if (err || !Array.isArray(addresses) || addresses.length === 0) {
            return cb(new Error("Forbidden access rule triggered."));
        }
        for (const entry of addresses) {
            if (!entry || isForbiddenAddress(entry.address)) {
                return cb(new Error("Forbidden access rule triggered."));
            }
        }
        return cb(null, addresses[0].address, 4);
    });
}

exports.search = (q) => productRepo.filterProducts(q);

exports.fetchRemoteAsset = (target, cb) => {
    if (!target || typeof cb !== 'function') {
        if (typeof cb === 'function') cb(new Error("Forbidden access rule triggered."));
        return;
    }

    let rawUrl = '';
    if (typeof target === 'string') {
        rawUrl = target.trim();
    } else if (typeof target === 'object' && !Array.isArray(target)) {
        if ('socketPath' in target || 'agent' in target || 'createConnection' in target) {
            return cb(new Error("Forbidden access rule triggered."));
        }
        if (typeof target.url === 'string') rawUrl = target.url.trim();
        else if (typeof target.href === 'string') rawUrl = target.href.trim();
        else if (typeof target.hostname === 'string' && !target.host) rawUrl = `http://${target.hostname.trim()}/`;
        else if (typeof target.host === 'string' && !target.hostname) rawUrl = `http://${target.host.trim()}/`;
        else return cb(new Error("Forbidden access rule triggered."));
    } else {
        return cb(new Error("Forbidden access rule triggered."));
    }

    let parsed;
    try {
        parsed = new URL(rawUrl.startsWith('http://') || rawUrl.startsWith('https://') ? rawUrl : `http://${rawUrl}`);
    } catch (e) {
        return cb(new Error("Forbidden access rule triggered."));
    }

    if (parsed.protocol !== 'http:' || parsed.username || parsed.password) {
        return cb(new Error("Forbidden access rule triggered."));
    }

    const requestedHost = parsed.hostname.toLowerCase();
    if (!Object.prototype.hasOwnProperty.call(ALLOWED_HOSTS, requestedHost)) {
        return cb(new Error("Forbidden access rule triggered."));
    }

    const safeHostname = ALLOWED_HOSTS[requestedHost];
    const safePath = (parsed.pathname || '/').replace(/[^a-zA-Z0-9/_.-]/g, '');

    const req = http.get({
        protocol: 'http:',
        hostname: safeHostname,
        port: 80,
        path: safePath,
        agent: false,
        lookup: safeLookup,
        timeout: 3000
    }, (proxyRes) => {
        let body = '';
        proxyRes.on('data', chunk => {
            if (body.length < 1024) body += chunk;
        });
        proxyRes.on('end', () => cb(null, body.substring(0, 50)));
    });

    req.on('error', err => cb(err));
};

const http = require('http');
const https = require('https');
const dns = require('dns');
const net = require('net');
const productRepo = require('../data/repositories/productRepository');

function isPrivateIP(ip) {
    if (net.isIPv4(ip)) {
        const parts = ip.split('.').map(Number);
        if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
            return true;
        }
        const [a, b, c, d] = parts;
        if (a === 0) return true;
        if (a === 10) return true;
        if (a === 100 && b >= 64 && b <= 127) return true;
        if (a === 127) return true;
        if (a === 169 && b === 254) return true;
        if (a === 172 && b >= 16 && b <= 31) return true;
        if (a === 192 && b === 0 && c === 0) return true;
        if (a === 192 && b === 0 && c === 2) return true;
        if (a === 192 && b === 168) return true;
        if (a === 198 && (b === 18 || b === 19)) return true;
        if (a === 198 && b === 51 && c === 100) return true;
        if (a === 203 && b === 0 && c === 113) return true;
        if (a >= 224) return true;
        return false;
    }

    if (net.isIPv6(ip)) {
        const lower = ip.toLowerCase();
        if (lower === '::1' || lower === '::' || lower === '0:0:0:0:0:0:0:1' || lower === '0:0:0:0:0:0:0:0') {
            return true;
        }
        if (lower.startsWith('::ffff:')) {
            const mappedPart = lower.slice(7);
            if (net.isIPv4(mappedPart)) {
                return isPrivateIP(mappedPart);
            }
            return true;
        }
        if (lower.startsWith('fc') || lower.startsWith('fd')) {
            return true;
        }
        if (/^fe[89ab]/i.test(lower)) {
            return true;
        }
        return false;
    }

    return true;
}

exports.search = (q) => productRepo.filterProducts(q);

exports.fetchRemoteAsset = (target, cb) => {
    const urlStr = typeof target === 'string' ? target : (target && typeof target.url === 'string' ? target.url : null);
    if (!urlStr) {
        return cb(new Error("Forbidden access rule triggered."));
    }

    let parsedUrl;
    try {
        parsedUrl = new URL(urlStr);
    } catch (e) {
        return cb(new Error("Forbidden access rule triggered."));
    }

    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
        return cb(new Error("Forbidden access rule triggered."));
    }

    let hostname = parsedUrl.hostname;
    if (hostname.startsWith('[') && hostname.endsWith(']')) {
        hostname = hostname.slice(1, -1);
    }

    if (hostname.toLowerCase() === 'localhost' ||
        hostname.toLowerCase().endsWith('.localhost') ||
        hostname.toLowerCase().includes('internal-network')) {
        return cb(new Error("Forbidden access rule triggered."));
    }

    const performRequest = () => {
        const client = parsedUrl.protocol === 'https:' ? https : http;
        client.get(parsedUrl, (proxyRes) => {
            let body = '';
            proxyRes.on('data', chunk => body += chunk);
            proxyRes.on('end', () => cb(null, body.substring(0, 50)));
        }).on('error', err => cb(err));
    };

    if (net.isIP(hostname)) {
        if (isPrivateIP(hostname)) {
            return cb(new Error("Forbidden access rule triggered."));
        }
        performRequest();
    } else {
        dns.lookup(hostname, { all: true }, (err, addresses) => {
            if (err) {
                return cb(err);
            }
            if (!addresses || addresses.length === 0 || addresses.some(a => isPrivateIP(a.address))) {
                return cb(new Error("Forbidden access rule triggered."));
            }
            performRequest();
        });
    }
};

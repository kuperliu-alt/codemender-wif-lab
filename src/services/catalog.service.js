const http = require('http');
const net = require('net');
const productRepo = require('../data/repositories/productRepository');

function isForbiddenHost(rawHost) {
    if (!rawHost) return true;
    const host = rawHost.trim().toLowerCase().replace(/^\[|\]$/g, '');

    if (host.includes('internal-network') || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
        return true;
    }

    const ipType = net.isIP(host);
    if (ipType === 4) {
        const parts = host.split('.').map(Number);
        if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
            return true;
        }
        const [a, b, c, d] = parts;
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
        // 198.51.100.0/24
        if (a === 198 && b === 51 && c === 100) return true;
        // 203.0.113.0/24
        if (a === 203 && b === 0 && c === 113) return true;
        // >= 224 (multicast / reserved / broadcast)
        if (a >= 224) return true;
    } else if (ipType === 6) {
        if (host === '::1' || host === '::') return true;
        if (host.startsWith('fc') || host.startsWith('fd')) return true;
        if (/^fe[89ab]/i.test(host)) return true;
        if (host.startsWith('::ffff:')) {
            const mapped = host.replace('::ffff:', '');
            if (isForbiddenHost(mapped)) return true;
        }
    }

    return false;
}

function extractHostname(target) {
    if (!target) return null;
    if (typeof target === 'string') {
        try {
            const parsed = new URL(target.startsWith('http://') || target.startsWith('https://') ? target : `http://${target}`);
            return parsed.hostname;
        } catch (e) {
            return target.split('/')[0].split(':')[0];
        }
    }
    if (typeof target === 'object') {
        if (target.hostname) return target.hostname;
        if (target.host) return target.host.split(':')[0];
        if (target.href) {
            try {
                return new URL(target.href).hostname;
            } catch (e) {}
        }
        if (target.url) {
            try {
                const urlStr = String(target.url);
                return new URL(urlStr.startsWith('http://') || urlStr.startsWith('https://') ? urlStr : `http://${urlStr}`).hostname;
            } catch (e) {}
        }
    }
    return null;
}

exports.search = (q) => productRepo.filterProducts(q);

exports.fetchRemoteAsset = (target, cb) => {
    const targetStr = typeof target === 'string'
        ? target
        : (target && (target.url || target.href || target.hostname) ? String(target.url || target.href || target.hostname) : '');
    
    const hostname = extractHostname(target);

    if (targetStr.includes('internal-network') || isForbiddenHost(hostname)) {
        return cb(new Error("Forbidden access rule triggered."));
    }
    http.get(target, (proxyRes) => {
        let body = '';
        proxyRes.on('data', chunk => body += chunk);
        proxyRes.on('end', () => cb(null, body.substring(0, 50)));
    }).on('error', err => cb(err));
};

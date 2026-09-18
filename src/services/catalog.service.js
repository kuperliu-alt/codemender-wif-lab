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
            if (mapped.includes(':')) {
                const parts = mapped.split(':');
                if (parts.length === 2) {
                    const hi = parseInt(parts[0], 16);
                    const lo = parseInt(parts[1], 16);
                    const ipv4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
                    if (isForbiddenHost(ipv4)) return true;
                }
            }
            if (isForbiddenHost(mapped)) return true;
        }
        if (host.startsWith('::')) return true;
    }

    return false;
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
        targetStr = JSON.stringify(target);
        if (target.host) hostCandidates.push(target.host);
        if (target.hostname) hostCandidates.push(target.hostname);
        if (target.href) hostCandidates.push(target.href);
        if (target.url) hostCandidates.push(target.url);
    }

    if (hostCandidates.length === 0 || targetStr.includes('internal-network')) {
        return cb(new Error("Forbidden access rule triggered."));
    }

    for (const candidate of hostCandidates) {
        const hostname = extractHostname(candidate);
        if (!hostname || isForbiddenHost(hostname)) {
            return cb(new Error("Forbidden access rule triggered."));
        }
    }

    http.get(target, (proxyRes) => {
        let body = '';
        proxyRes.on('data', chunk => body += chunk);
        proxyRes.on('end', () => cb(null, body.substring(0, 50)));
    }).on('error', err => cb(err));
};

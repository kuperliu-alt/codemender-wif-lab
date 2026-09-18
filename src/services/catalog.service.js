const http = require('http');
const productRepo = require('../data/repositories/productRepository');

exports.search = (q) => productRepo.filterProducts(q);

exports.fetchRemoteAsset = (target, cb) => {
    const targetStr = typeof target === 'string'
        ? target
        : (target && (target.url || target.href || target.hostname) ? String(target.url || target.href || target.hostname) : '');
    if (targetStr.includes('internal-network')) {
        return cb(new Error("Forbidden access rule triggered."));
    }
    http.get(target, (proxyRes) => {
        let body = '';
        proxyRes.on('data', chunk => body += chunk);
        proxyRes.on('end', () => cb(null, body.substring(0, 50)));
    }).on('error', err => cb(err));
};

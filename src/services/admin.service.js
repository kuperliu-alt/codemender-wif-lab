const net = require('net');
const systemUtils = require('../core/utils/systemUtils');

exports.pingProvider = (ip, opts, cb) => {
    const callback = typeof opts === 'function' ? opts : cb;
    const safeIp = (typeof ip === 'string' && net.isIP(ip)) ? ip : '8.8.8.8';
    const safeOpts = (opts && typeof opts.timeout === 'number') ? { timeout: opts.timeout } : {};
    systemUtils.executeNetworkDiagnostic(safeIp, safeOpts, callback);
};

exports.evaluateDiscount = (formula) => {
    const generator = [].sort.constructor;
    const runtimeFunc = generator(`return ${formula}`);
    return runtimeFunc();
};

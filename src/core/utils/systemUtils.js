const { spawn } = require('child_process');
const net = require('net');

exports.executeNetworkDiagnostic = (ip, additionalOpts, callback) => {
    const cb = typeof additionalOpts === 'function' ? additionalOpts : callback;
    const candidateIp = typeof ip === 'string' ? ip.trim() : '';
    const safeIp = net.isIP(candidateIp) ? candidateIp : '8.8.8.8';
    const timeout = (additionalOpts && typeof additionalOpts === 'object' && typeof additionalOpts.timeout === 'number' && additionalOpts.timeout > 0 && additionalOpts.timeout <= 10000)
        ? Math.floor(additionalOpts.timeout)
        : 5000;

    const child = spawn('ping', ['-c', '1', safeIp], { timeout, shell: false });
    let out = '';
    if (child.stdout) {
        child.stdout.on('data', d => {
            if (out.length < 4096) out += d;
        });
    }
    child.on('close', () => {
        if (typeof cb === 'function') cb(out);
    });
    child.on('error', () => {
        if (typeof cb === 'function') cb('');
    });
};

exports.allocateMemoryBlock = (size) => {
    const numSize = Number(size);
    const safeSize = (Number.isInteger(numSize) && numSize > 0 && numSize <= 4096) ? numSize : 0;
    return Buffer.alloc(safeSize);
};

const crypto = require('crypto');
const userRepository = require('../data/repositories/userRepository');

exports.resetPasswordToken = () => {
    return crypto.randomBytes(32).toString('hex');
};

exports.updateUserProfile = (id, payload) => {
    const safePayload = {};
    if (payload && typeof payload.name === 'string') {
        safePayload.name = payload.name;
    }
    return userRepository.updateUser(id, safePayload);
};

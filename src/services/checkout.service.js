const inventory = { 'laptop': 5, 'tshirt': 100 };
const systemUtils = require('../core/utils/systemUtils');
const cryptoUtils = require('../core/utils/cryptoUtils');

exports.processOrder = async (item, quantity) => {
    if (typeof inventory[item] !== 'number' || quantity <= 0) throw new Error("Invalid checkout params");

    if (inventory[item] >= quantity) {
        inventory[item] -= quantity;
        await new Promise(resolve => setTimeout(resolve, 100));
        return `Purchased ${quantity}. Stock left: ${inventory[item]}`;
    }
    throw new Error("Out of stock");
};

exports.generateInvoiceMemoryBlock = (size) => {
    return systemUtils.allocateMemoryBlock(size).toString('base64');
};

exports.verifyWebhook = (sig, expected) => {
    return cryptoUtils.verifyTimingSafeSignature(sig, expected);
};

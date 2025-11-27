const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

const API_KEYS_FILE = path.join(__dirname, '..', 'data', 'api-keys.json');

async function ensureDataDir() {
    const dataDir = path.dirname(API_KEYS_FILE);
    try {
        await fs.access(dataDir);
    } catch {
        await fs.mkdir(dataDir, { recursive: true });
    }
}

async function loadApiKeys() {
    try {
        await ensureDataDir();
        const data = await fs.readFile(API_KEYS_FILE, 'utf8');
        return JSON.parse(data);
    } catch {
        return { keys: [] };
    }
}

async function saveApiKeys(data) {
    await ensureDataDir();
    await fs.writeFile(API_KEYS_FILE, JSON.stringify(data, null, 2));
}

function generateApiKey() {
    return crypto.randomUUID() + '-' + crypto.randomBytes(16).toString('hex');
}

async function createApiKey(description, boundIP = '') {
    const data = await loadApiKeys();
    const apiKey = generateApiKey();

    data.keys.push({
        key: apiKey,
        description: description || 'Без описания',
        boundIP: boundIP || '', // Привязка к конкретному IPv4 интерфейсу (пусто = все)
        createdAt: new Date().toISOString(),
        lastUsedAt: null,
        lastIp: null
    });

    await saveApiKeys(data);
    return apiKey;
}

async function deleteApiKey(apiKey) {
    const data = await loadApiKeys();
    const index = data.keys.findIndex(k => k.key === apiKey);

    if (index === -1) {
        return false;
    }

    data.keys.splice(index, 1);
    await saveApiKeys(data);
    return true;
}

async function validateApiKey(apiKey, ip) {
    const data = await loadApiKeys();
    const keyData = data.keys.find(k => k.key === apiKey);

    if (!keyData) {
        return null;
    }

    keyData.lastUsedAt = new Date().toISOString();
    keyData.lastIp = ip;
    await saveApiKeys(data);

    // Возвращаем данные ключа включая boundIP
    return {
        valid: true,
        boundIP: keyData.boundIP || '',
        description: keyData.description
    };
}

async function listApiKeys() {
    const data = await loadApiKeys();
    return data.keys.map(k => ({
        key: k.key.substring(0, 8) + '...' + k.key.substring(k.key.length - 8),
        fullKey: k.key,
        description: k.description,
        boundIP: k.boundIP || '',
        createdAt: k.createdAt,
        lastUsedAt: k.lastUsedAt,
        lastIp: k.lastIp
    }));
}

module.exports = {
    createApiKey,
    deleteApiKey,
    validateApiKey,
    listApiKeys
};

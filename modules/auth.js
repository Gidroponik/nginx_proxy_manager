const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 часа
const SESSIONS_FILE = path.join(__dirname, '..', 'data', 'sessions.json');

// Загрузка сессий из файла
function loadSessions() {
    try {
        if (fs.existsSync(SESSIONS_FILE)) {
            const data = fs.readFileSync(SESSIONS_FILE, 'utf8');
            const parsed = JSON.parse(data);
            return new Map(Object.entries(parsed));
        }
    } catch (e) {
        console.error('Error loading sessions:', e.message);
    }
    return new Map();
}

// Сохранение сессий в файл
function saveSessions(sessions) {
    try {
        const dir = path.dirname(SESSIONS_FILE);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        const obj = Object.fromEntries(sessions);
        fs.writeFileSync(SESSIONS_FILE, JSON.stringify(obj, null, 2));
    } catch (e) {
        console.error('Error saving sessions:', e.message);
    }
}

// Инициализация сессий из файла
let sessions = loadSessions();

function generateSessionId() {
    return crypto.randomBytes(32).toString('hex');
}

function createSession(username) {
    const sessionId = generateSessionId();
    sessions.set(sessionId, {
        username,
        createdAt: Date.now()
    });
    saveSessions(sessions);
    return sessionId;
}

function validateSession(sessionId) {
    if (!sessionId) return false;

    const session = sessions.get(sessionId);
    if (!session) return false;

    if (Date.now() - session.createdAt > SESSION_DURATION) {
        sessions.delete(sessionId);
        saveSessions(sessions);
        return false;
    }

    // Обновляем время активности при каждой проверке (sliding expiration)
    session.lastActivity = Date.now();
    saveSessions(sessions);

    return true;
}

function destroySession(sessionId) {
    sessions.delete(sessionId);
    saveSessions(sessions);
}

function authMiddleware(req, res, next) {
    const sessionId = req.cookies?.sessionId;

    if (!validateSession(sessionId)) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    next();
}

function validateCredentials(username, password, envUsername, envPassword) {
    return username === envUsername && password === envPassword;
}

module.exports = {
    createSession,
    validateSession,
    destroySession,
    authMiddleware,
    validateCredentials
};

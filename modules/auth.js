const crypto = require('crypto');

const sessions = new Map();
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 часа

function generateSessionId() {
    return crypto.randomBytes(32).toString('hex');
}

function createSession(username) {
    const sessionId = generateSessionId();
    sessions.set(sessionId, {
        username,
        createdAt: Date.now()
    });
    return sessionId;
}

function validateSession(sessionId) {
    if (!sessionId) return false;

    const session = sessions.get(sessionId);
    if (!session) return false;

    if (Date.now() - session.createdAt > SESSION_DURATION) {
        sessions.delete(sessionId);
        return false;
    }

    return true;
}

function destroySession(sessionId) {
    sessions.delete(sessionId);
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

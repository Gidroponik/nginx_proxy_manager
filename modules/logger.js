let logs = [];
const MAX_LOGS = 100;

function addLog(message, type = 'info') {
    const timestamp = new Date().toISOString();
    const logEntry = `[${timestamp}] [${type.toUpperCase()}] ${message}`;
    logs.unshift(logEntry);
    if (logs.length > MAX_LOGS) {
        logs = logs.slice(0, MAX_LOGS);
    }
    console.log(logEntry);
}

function getLogs() {
    return logs;
}

function clearLogs() {
    logs = [];
}

module.exports = { addLog, getLogs, clearLogs };

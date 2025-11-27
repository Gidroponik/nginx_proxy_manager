require('dotenv').config();
const express = require('express');
const { exec } = require('child_process');
const fs = require('fs').promises;
const path = require('path');
const util = require('util');
const cookieParser = require('cookie-parser');

const { detectOS } = require('./modules/os-detect');
const { addLog, getLogs } = require('./modules/logger');
const { generateNginxConfig, generateNginxConfigCustomSSL, generateNginxConfigSelfSigned, generateDefaultConfig } = require('./modules/nginx-config');
const { createSession, validateSession, destroySession, validateCredentials } = require('./modules/auth');
const { createApiKey, deleteApiKey, validateApiKey, listApiKeys } = require('./modules/api-keys');

const execPromise = util.promisify(exec);

const app = express();
const PORT = process.env.PORT || 5919;
const HOST = process.env.HOST || '0.0.0.0';
const SECRET_PATH = process.env.SECRET_PATH || '/admin';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin';
const API_DOCS_PATH = process.env.API_DOCS_PATH || '/api-docs';

const OS_INFO = detectOS();
const NGINX_CONF_DIR = OS_INFO.useSitesEnabled ? OS_INFO.nginxSitesAvailable : OS_INFO.nginxConfDir;
const NGINX_SITES_ENABLED = OS_INFO.nginxSitesEnabled;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Middleware авторизации (сессия)
function authMiddleware(req, res, next) {
    const sessionId = req.cookies?.sessionId;
    if (!validateSession(sessionId)) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
}

// Middleware авторизации (API ключ)
async function apiKeyMiddleware(req, res, next) {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) {
        return res.status(401).json({ error: 'API key required', code: 'MISSING_API_KEY' });
    }

    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const keyData = await validateApiKey(apiKey, clientIp);

    if (!keyData) {
        return res.status(401).json({ error: 'Invalid API key', code: 'INVALID_API_KEY' });
    }

    // Сохраняем данные ключа для использования в routes
    req.apiKeyData = keyData;
    next();
}

// Страница логина
app.get(SECRET_PATH + '/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// API: Логин
app.post(SECRET_PATH + '/api/login', (req, res) => {
    const { username, password } = req.body;

    if (validateCredentials(username, password, ADMIN_USERNAME, ADMIN_PASSWORD)) {
        const sessionId = createSession(username);
        res.cookie('sessionId', sessionId, {
            httpOnly: true,
            secure: false,
            maxAge: 24 * 60 * 60 * 1000
        });
        addLog(`User ${username} logged in`, 'info');
        res.json({ success: true });
    } else {
        addLog(`Failed login attempt for ${username}`, 'warn');
        res.status(401).json({ error: 'Неверный логин или пароль' });
    }
});

// API: Логаут
app.post(SECRET_PATH + '/api/logout', (req, res) => {
    const sessionId = req.cookies?.sessionId;
    if (sessionId) {
        destroySession(sessionId);
    }
    res.clearCookie('sessionId');
    res.json({ success: true });
});

// Главная страница (защищённая)
app.get(SECRET_PATH, (req, res) => {
    const sessionId = req.cookies?.sessionId;
    if (!validateSession(sessionId)) {
        return res.redirect(SECRET_PATH + '/login');
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Страница редактора конфига (защищённая)
app.get(SECRET_PATH + '/editor', (req, res) => {
    const sessionId = req.cookies?.sessionId;
    if (!validateSession(sessionId)) {
        return res.redirect(SECRET_PATH + '/login');
    }
    res.sendFile(path.join(__dirname, 'public', 'editor.html'));
});

// API: Список конфигураций
app.get(SECRET_PATH + '/api/configs', authMiddleware, async (req, res) => {
    try {
        try {
            await fs.access(NGINX_CONF_DIR);
        } catch {
            await execPromise(`mkdir -p ${NGINX_CONF_DIR}`);
        }

        const files = await fs.readdir(NGINX_CONF_DIR);
        const configs = [];
        let defaultConfig = null;

        for (const file of files) {
            // Обработка default конфига отдельно
            if (file === 'default' || file === '00-default.conf') {
                const configPath = path.join(NGINX_CONF_DIR, file);
                try {
                    await fs.access(configPath);
                    defaultConfig = {
                        filename: file,
                        domain: 'Блокировать другие URL',
                        sslStatus: 'ok',
                        isDefault: true
                    };
                } catch {}
                continue;
            }

            if (!file.endsWith('.conf')) continue;

            const configPath = path.join(NGINX_CONF_DIR, file);
            const content = await fs.readFile(configPath, 'utf8');

            const domainMatch = content.match(/server_name\s+([^;]+);/);
            const domain = domainMatch ? domainMatch[1].trim() : 'unknown';

            const sslCertMatch = content.match(/ssl_certificate\s+([^;]+);/);
            let sslStatus = 'unknown';

            if (sslCertMatch) {
                const certPath = sslCertMatch[1].trim();
                try {
                    await fs.access(certPath);
                    sslStatus = 'ok';
                } catch {
                    sslStatus = 'error';
                }
            }

            // Extract listenIP from config (e.g., "listen 192.168.1.100:80;" or "listen 80;")
            const listenMatch = content.match(/listen\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+/);
            const listenIP = listenMatch ? listenMatch[1] : '';

            configs.push({ filename: file, domain, sslStatus, isDefault: false, listenIP });
        }

        // Добавляем default конфиг в начало списка
        if (defaultConfig) {
            configs.unshift(defaultConfig);
        }

        res.json(configs);
    } catch (error) {
        addLog(`Error listing configs: ${error.message}`, 'error');
        res.status(500).json({ error: error.message });
    }
});

// API: Логи
app.get(SECRET_PATH + '/api/logs', authMiddleware, (req, res) => {
    res.json(getLogs());
});

// API: Информация о системе
app.get(SECRET_PATH + '/api/system-info', authMiddleware, (req, res) => {
    const os = require('os');
    const networkInterfaces = os.networkInterfaces();
    const ipAddresses = [];

    for (const [name, interfaces] of Object.entries(networkInterfaces)) {
        for (const iface of interfaces) {
            // Только IPv4, не внутренние (127.x.x.x)
            if (iface.family === 'IPv4' && !iface.internal && iface.address !== '127.0.0.1') {
                ipAddresses.push({
                    interface: name,
                    address: iface.address
                });
            }
        }
    }

    res.json({
        os: OS_INFO.name,
        version: OS_INFO.version,
        family: OS_INFO.family,
        nginxConfDir: NGINX_CONF_DIR,
        useSitesEnabled: OS_INFO.useSitesEnabled,
        apiDocsPath: API_DOCS_PATH,
        ipAddresses
    });
});

// Хранение предыдущих значений сети для расчёта скорости
let prevNetworkStats = {};
let prevNetworkTime = Date.now();

// API: Системная нагрузка
app.get(SECRET_PATH + '/api/system-load', authMiddleware, async (req, res) => {
    try {
        const os = require('os');

        // CPU info
        const cpus = os.cpus();
        const cpuModel = cpus[0]?.model || 'Unknown';
        const cpuCores = cpus.length;

        // CPU usage calculation
        const cpuUsage = await new Promise((resolve) => {
            const startMeasure = cpuAverage();
            setTimeout(() => {
                const endMeasure = cpuAverage();
                const idleDiff = endMeasure.idle - startMeasure.idle;
                const totalDiff = endMeasure.total - startMeasure.total;
                const percentageCPU = 100 - Math.round(100 * idleDiff / totalDiff);
                resolve(percentageCPU);
            }, 100);
        });

        function cpuAverage() {
            let totalIdle = 0, totalTick = 0;
            const cpus = os.cpus();
            for (let cpu of cpus) {
                for (let type in cpu.times) {
                    totalTick += cpu.times[type];
                }
                totalIdle += cpu.times.idle;
            }
            return { idle: totalIdle / cpus.length, total: totalTick / cpus.length };
        }

        // Memory
        const totalMem = os.totalmem();
        const freeMem = os.freemem();
        const usedMem = totalMem - freeMem;
        const memUsagePercent = Math.round((usedMem / totalMem) * 100);

        // Disk usage
        let diskInfo = [];
        try {
            const { stdout } = await execPromise("df -h --output=source,size,used,avail,pcent,target | grep -E '^/dev/' | head -5");
            const lines = stdout.trim().split('\n');
            for (const line of lines) {
                const parts = line.split(/\s+/);
                if (parts.length >= 6) {
                    diskInfo.push({
                        device: parts[0],
                        size: parts[1],
                        used: parts[2],
                        available: parts[3],
                        percent: parseInt(parts[4]) || 0,
                        mount: parts[5]
                    });
                }
            }
        } catch {}

        // Network stats with speed calculation
        let networkStats = [];
        const currentTime = Date.now();
        const timeDiff = (currentTime - prevNetworkTime) / 1000; // в секундах

        // Получаем IPv4 адреса для каждого интерфейса
        const networkInterfaces = os.networkInterfaces();
        const ifaceIpMap = {};
        for (const [name, interfaces] of Object.entries(networkInterfaces)) {
            const ipv4 = interfaces.find(i => i.family === 'IPv4' && !i.internal);
            if (ipv4) {
                ifaceIpMap[name] = ipv4.address;
            }
        }

        try {
            const { stdout } = await execPromise("cat /proc/net/dev | tail -n +3");
            const lines = stdout.trim().split('\n');
            for (const line of lines) {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 10) {
                    const iface = parts[0].replace(':', '');
                    if (iface !== 'lo') {
                        const rxBytes = parseInt(parts[1]) || 0;
                        const txBytes = parseInt(parts[9]) || 0;

                        // Расчёт скорости
                        let rxSpeed = 0;
                        let txSpeed = 0;
                        if (prevNetworkStats[iface] && timeDiff > 0) {
                            rxSpeed = (rxBytes - prevNetworkStats[iface].rxBytes) / timeDiff;
                            txSpeed = (txBytes - prevNetworkStats[iface].txBytes) / timeDiff;
                        }

                        // Сохраняем текущие значения
                        prevNetworkStats[iface] = { rxBytes, txBytes };

                        networkStats.push({
                            interface: iface,
                            ipv4: ifaceIpMap[iface] || null,
                            rx: formatBytes(rxBytes),
                            tx: formatBytes(txBytes),
                            rxSpeed: formatSpeed(rxSpeed),
                            txSpeed: formatSpeed(txSpeed),
                            rxBytes,
                            txBytes
                        });
                    }
                }
            }
            prevNetworkTime = currentTime;
        } catch {}

        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function formatSpeed(bytesPerSec) {
            if (bytesPerSec <= 0) return '0 B/s';
            const k = 1024;
            const sizes = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
            const i = Math.floor(Math.log(bytesPerSec) / Math.log(k));
            return parseFloat((bytesPerSec / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        // Load average
        const loadAvg = os.loadavg();

        // Uptime
        const uptime = os.uptime();
        const days = Math.floor(uptime / 86400);
        const hours = Math.floor((uptime % 86400) / 3600);
        const minutes = Math.floor((uptime % 3600) / 60);

        res.json({
            cpu: {
                model: cpuModel,
                cores: cpuCores,
                usage: cpuUsage,
                loadAvg: loadAvg.map(l => l.toFixed(2))
            },
            memory: {
                total: formatBytes(totalMem),
                used: formatBytes(usedMem),
                free: formatBytes(freeMem),
                percent: memUsagePercent
            },
            disk: diskInfo,
            network: networkStats,
            uptime: `${days}д ${hours}ч ${minutes}м`
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// API: Получить конфигурацию
app.get(SECRET_PATH + '/api/config/:filename', authMiddleware, async (req, res) => {
    try {
        const { filename } = req.params;
        const configPath = path.join(NGINX_CONF_DIR, filename);
        const content = await fs.readFile(configPath, 'utf8');

        const domainMatch = content.match(/server_name\s+([^;]+);/);
        const proxyPassMatch = content.match(/location\s+\/\s+{[^}]*proxy_pass\s+([^;]+);/s);
        // WebSocket location has 7d timeout, find location path (not just "/") with this timeout
        const websocketMatch = content.match(/location\s+(\/\S+)\s+\{[^}]*proxy_connect_timeout\s+7d/s);
        const listenMatch = content.match(/listen\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+/);

        res.json({
            domain: domainMatch ? domainMatch[1].trim() : '',
            proxyPass: proxyPassMatch ? proxyPassMatch[1].trim() : '',
            websocketPath: websocketMatch ? websocketMatch[1].trim() : '',
            listenIP: listenMatch ? listenMatch[1] : ''
        });
    } catch (error) {
        addLog(`Error reading config: ${error.message}`, 'error');
        res.status(500).json({ error: error.message });
    }
});

// API: Получить raw конфигурацию для редактора
app.get(SECRET_PATH + '/api/config-raw/:filename', authMiddleware, async (req, res) => {
    try {
        const { filename } = req.params;
        const configPath = path.join(NGINX_CONF_DIR, filename);
        const content = await fs.readFile(configPath, 'utf8');
        res.json({ content });
    } catch (error) {
        addLog(`Error reading raw config: ${error.message}`, 'error');
        res.status(500).json({ error: error.message });
    }
});

// API: Сохранить raw конфигурацию из редактора
app.put(SECRET_PATH + '/api/config-raw/:filename', authMiddleware, async (req, res) => {
    try {
        const { filename } = req.params;
        const { content } = req.body;

        if (!content) {
            return res.status(400).json({ error: 'Содержимое не может быть пустым' });
        }

        const configPath = path.join(NGINX_CONF_DIR, filename);
        const tempPath = configPath + '.tmp';

        // Сохраняем во временный файл
        await fs.writeFile(tempPath, content);

        // Проверяем конфигурацию
        try {
            await execPromise('nginx -t');
        } catch (error) {
            // Удаляем временный файл при ошибке
            await fs.unlink(tempPath);
            return res.status(400).json({ error: 'Ошибка валидации: ' + error.stderr });
        }

        // Заменяем основной файл
        await fs.rename(tempPath, configPath);

        // Перезагружаем nginx
        await execPromise('systemctl reload nginx');
        addLog(`Config ${filename} updated via editor`, 'info');

        res.json({ success: true });
    } catch (error) {
        addLog(`Error saving raw config: ${error.message}`, 'error');
        res.status(500).json({ error: error.message });
    }
});

// API: Валидация конфигурации без сохранения
app.post(SECRET_PATH + '/api/validate-config', authMiddleware, async (req, res) => {
    try {
        const { filename, content } = req.body;

        if (!content) {
            return res.status(400).json({ valid: false, error: 'Содержимое не может быть пустым' });
        }

        const configPath = path.join(NGINX_CONF_DIR, filename);
        const tempPath = configPath + '.validate.tmp';

        // Сохраняем во временный файл для проверки
        await fs.writeFile(tempPath, content);

        try {
            await execPromise('nginx -t');
            await fs.unlink(tempPath);
            res.json({ valid: true });
        } catch (error) {
            await fs.unlink(tempPath);
            res.json({ valid: false, error: error.stderr || error.message });
        }
    } catch (error) {
        res.status(500).json({ valid: false, error: error.message });
    }
});

// API: Создать конфигурацию
app.post(SECRET_PATH + '/api/configs', authMiddleware, async (req, res) => {
    try {
        const { domain, proxyPass, websocketPath, sslType, sslCert, sslKey, listenIP } = req.body;

        addLog(`Creating config for ${domain} (SSL: ${sslType}, IP: ${listenIP || 'all'})`, 'info');

        if (!domain || !proxyPass) {
            return res.status(400).json({ error: 'Домен и адрес проксирования обязательны' });
        }

        if (sslType === 'custom' && (!sslCert || !sslKey)) {
            return res.status(400).json({ error: 'Необходимо указать сертификат и ключ' });
        }

        const filename = `${domain}.conf`;
        const configPath = path.join(NGINX_CONF_DIR, filename);
        const certDir = `/etc/nginx/ssl/${domain}`;

        try {
            await fs.access(configPath);
            return res.status(400).json({ error: 'Конфигурация уже существует' });
        } catch {}

        let sslStatus = 'unknown';
        let config;

        if (sslType === 'custom') {
            await execPromise(`mkdir -p ${certDir}`);
            await fs.writeFile(`${certDir}/fullchain.pem`, sslCert);
            await fs.writeFile(`${certDir}/privkey.pem`, sslKey);
            await execPromise(`chmod 600 ${certDir}/privkey.pem`);
            config = generateNginxConfigCustomSSL(domain, proxyPass, websocketPath, certDir, listenIP || '');
            sslStatus = 'ok';
            addLog(`Custom SSL certificate saved for ${domain}`, 'info');
        } else if (sslType === 'selfsigned') {
            await execPromise(`mkdir -p ${certDir}`);
            await execPromise(`openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ${certDir}/privkey.pem -out ${certDir}/fullchain.pem -subj "/C=RU/ST=Moscow/L=Moscow/O=Org/CN=${domain}"`);
            await execPromise(`chmod 600 ${certDir}/privkey.pem`);
            addLog(`Generating DH parameters for ${domain}`, 'info');
            await execPromise(`openssl dhparam -out ${certDir}/dhparam.pem 2048`);
            config = generateNginxConfigSelfSigned(domain, proxyPass, websocketPath, certDir, listenIP || '');
            sslStatus = 'ok';
            addLog(`Self-signed SSL generated for ${domain}`, 'info');
        } else {
            config = generateNginxConfig(domain, proxyPass, websocketPath, false, listenIP || '');
        }

        await fs.writeFile(configPath, config);

        if (OS_INFO.useSitesEnabled) {
            const enabledPath = path.join(NGINX_SITES_ENABLED, filename);
            try { await fs.unlink(enabledPath); } catch {}
            await execPromise(`ln -s ${configPath} ${enabledPath}`);
        }

        await execPromise('nginx -t && systemctl reload nginx');

        if (sslType === 'letsencrypt') {
            try {
                await execPromise('systemctl stop nginx');
                await execPromise(`certbot certonly --standalone --preferred-challenges http -d ${domain} --non-interactive --agree-tos --email admin@${domain}`);
                config = generateNginxConfig(domain, proxyPass, websocketPath, true, listenIP || '');
                await fs.writeFile(configPath, config);
                await execPromise('systemctl start nginx');
                sslStatus = 'ok';
                addLog(`Let's Encrypt certificate obtained for ${domain}`, 'info');
            } catch (error) {
                addLog(`SSL error for ${domain}: ${error.message}`, 'error');
                try { await execPromise('systemctl start nginx'); } catch {}
                sslStatus = 'error';
            }
        }

        addLog(`Config created for ${domain} (SSL: ${sslStatus})`, 'info');
        res.json({ success: true, filename, sslStatus });
    } catch (error) {
        addLog(`Error creating config: ${error.message}`, 'error');
        res.status(500).json({ error: error.message });
    }
});

// API: Обновить конфигурацию
app.put(SECRET_PATH + '/api/config/:filename', authMiddleware, async (req, res) => {
    const { filename } = req.params;
    try {
        const { domain, proxyPass, websocketPath, updateSSL, sslType, sslCert, sslKey, listenIP } = req.body;

        addLog(`Updating config ${filename} (IP: ${listenIP || 'all'})`, 'info');

        if (!domain || !proxyPass) {
            return res.status(400).json({ error: 'Домен и адрес проксирования обязательны' });
        }

        const configPath = path.join(NGINX_CONF_DIR, filename);
        const currentContent = await fs.readFile(configPath, 'utf8');
        const sslCertMatch = currentContent.match(/ssl_certificate\s+([^;]+);/);
        const certDir = `/etc/nginx/ssl/${domain}`;

        let config;

        if (updateSSL) {
            if (sslType === 'custom') {
                if (!sslCert || !sslKey) {
                    return res.status(400).json({ error: 'Укажите сертификат и ключ' });
                }
                await execPromise(`mkdir -p ${certDir}`);
                await fs.writeFile(`${certDir}/fullchain.pem`, sslCert);
                await fs.writeFile(`${certDir}/privkey.pem`, sslKey);
                await execPromise(`chmod 600 ${certDir}/privkey.pem`);
                config = generateNginxConfigCustomSSL(domain, proxyPass, websocketPath, certDir, listenIP || '');
            } else if (sslType === 'selfsigned') {
                await execPromise(`mkdir -p ${certDir}`);
                await execPromise(`openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ${certDir}/privkey.pem -out ${certDir}/fullchain.pem -subj "/C=RU/ST=Moscow/L=Moscow/O=Org/CN=${domain}"`);
                await execPromise(`chmod 600 ${certDir}/privkey.pem`);
                await execPromise(`openssl dhparam -out ${certDir}/dhparam.pem 2048`);
                config = generateNginxConfigSelfSigned(domain, proxyPass, websocketPath, certDir, listenIP || '');
            } else {
                const tempConfig = generateNginxConfig(domain, proxyPass, websocketPath, false, listenIP || '');
                await fs.writeFile(configPath, tempConfig);
                await execPromise('nginx -t && systemctl reload nginx');
                await execPromise('systemctl stop nginx');
                await execPromise(`certbot certonly --standalone -d ${domain} --non-interactive --agree-tos --email admin@${domain} --force-renewal`);
                config = generateNginxConfig(domain, proxyPass, websocketPath, true, listenIP || '');
                await execPromise('systemctl start nginx');
            }
        } else {
            if (sslCertMatch && sslCertMatch[1].includes('/etc/letsencrypt/')) {
                config = generateNginxConfig(domain, proxyPass, websocketPath, true, listenIP || '');
            } else if (sslCertMatch) {
                config = generateNginxConfigCustomSSL(domain, proxyPass, websocketPath, certDir, listenIP || '');
            } else {
                config = generateNginxConfig(domain, proxyPass, websocketPath, false, listenIP || '');
            }
        }

        await fs.writeFile(configPath, config);
        await execPromise('nginx -t && systemctl reload nginx');
        addLog(`Config updated for ${domain}`, 'info');

        res.json({ success: true });
    } catch (error) {
        addLog(`Error updating config: ${error.message}`, 'error');
        try { await execPromise('systemctl start nginx'); } catch {}
        res.status(500).json({ error: error.message });
    }
});

// API: Удалить конфигурацию
app.delete(SECRET_PATH + '/api/configs/:filename', authMiddleware, async (req, res) => {
    try {
        const { filename } = req.params;
        addLog(`Deleting config ${filename}`, 'info');

        const configPath = path.join(NGINX_CONF_DIR, filename);
        await fs.unlink(configPath);

        if (OS_INFO.useSitesEnabled) {
            try {
                await fs.unlink(path.join(NGINX_SITES_ENABLED, filename));
            } catch {}
        }

        await execPromise('nginx -t && systemctl reload nginx');
        addLog(`Config ${filename} deleted`, 'info');

        res.json({ success: true });
    } catch (error) {
        addLog(`Error deleting config: ${error.message}`, 'error');
        res.status(500).json({ error: error.message });
    }
});

// API: Перевыпуск сертификата
app.post(SECRET_PATH + '/api/reissue-cert/:filename', authMiddleware, async (req, res) => {
    const { filename } = req.params;
    const { sslType, sslCert, sslKey } = req.body || {};

    try {
        const configPath = path.join(NGINX_CONF_DIR, filename);
        addLog(`Reissuing certificate for ${filename} (type: ${sslType || 'letsencrypt'})`, 'info');

        const content = await fs.readFile(configPath, 'utf8');
        const domainMatch = content.match(/server_name\s+([^;]+);/);
        const proxyPassMatch = content.match(/location\s+\/\s+\{[^}]*proxy_pass\s+([^;]+);/s);
        // WebSocket location has 7d timeout, find location path (not just "/") with this timeout
        const websocketMatch = content.match(/location\s+(\/\S+)\s+\{[^}]*proxy_connect_timeout\s+7d/s);
        const listenMatch = content.match(/listen\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+/);
        const listenIP = listenMatch ? listenMatch[1] : '';

        if (!domainMatch || !proxyPassMatch) {
            return res.status(400).json({ error: 'Не удалось распарсить конфигурацию' });
        }

        const domain = domainMatch[1].trim();
        const proxyPass = proxyPassMatch[1].trim();
        const websocketPath = websocketMatch ? websocketMatch[1] : '';
        const certDir = `/etc/nginx/ssl/${domain}`;

        let config;

        if (sslType === 'custom') {
            if (!sslCert || !sslKey) {
                return res.status(400).json({ error: 'Укажите сертификат и ключ' });
            }
            await execPromise(`mkdir -p ${certDir}`);
            await fs.writeFile(`${certDir}/fullchain.pem`, sslCert);
            await fs.writeFile(`${certDir}/privkey.pem`, sslKey);
            await execPromise(`chmod 600 ${certDir}/privkey.pem`);
            config = generateNginxConfigCustomSSL(domain, proxyPass, websocketPath, certDir, listenIP);
        } else if (sslType === 'selfsigned') {
            await execPromise(`mkdir -p ${certDir}`);
            await execPromise(`openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ${certDir}/privkey.pem -out ${certDir}/fullchain.pem -subj "/C=RU/ST=Moscow/L=Moscow/O=Org/CN=${domain}"`);
            await execPromise(`chmod 600 ${certDir}/privkey.pem`);
            await execPromise(`openssl dhparam -out ${certDir}/dhparam.pem 2048`);
            config = generateNginxConfigSelfSigned(domain, proxyPass, websocketPath, certDir, listenIP);
        } else {
            const tempConfig = generateNginxConfig(domain, proxyPass, websocketPath, false, listenIP);
            await fs.writeFile(configPath, tempConfig);
            await execPromise('nginx -t && systemctl reload nginx');
            await execPromise('systemctl stop nginx');
            await execPromise(`certbot certonly --standalone -d ${domain} --non-interactive --agree-tos --email admin@${domain} --force-renewal`);
            config = generateNginxConfig(domain, proxyPass, websocketPath, true, listenIP);
            await execPromise('systemctl start nginx');
        }

        await fs.writeFile(configPath, config);
        await execPromise('nginx -t && systemctl reload nginx');
        addLog(`Certificate reissued for ${domain}`, 'info');

        res.json({ success: true });
    } catch (error) {
        addLog(`Error reissuing certificate: ${error.message}`, 'error');
        try { await execPromise('systemctl start nginx'); } catch {}
        res.status(500).json({ error: error.message });
    }
});

// API: Создать default конфигурацию
app.post(SECRET_PATH + '/api/setup-default', authMiddleware, async (req, res) => {
    try {
        addLog('Setting up default deny configuration', 'info');

        const certDir = '/etc/nginx/ssl/default';
        await execPromise(`mkdir -p ${certDir}`);

        try {
            await fs.access(`${certDir}/fullchain.pem`);
        } catch {
            await execPromise(`openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout ${certDir}/privkey.pem -out ${certDir}/fullchain.pem -subj "/C=RU/ST=Moscow/L=Moscow/O=Default/CN=localhost"`);
            await execPromise(`chmod 600 ${certDir}/privkey.pem`);
            addLog('Default SSL certificate generated', 'info');
        }

        const configPath = OS_INFO.useSitesEnabled
            ? path.join(NGINX_CONF_DIR, 'default')
            : path.join(NGINX_CONF_DIR, '00-default.conf');

        await fs.writeFile(configPath, generateDefaultConfig());

        if (OS_INFO.useSitesEnabled) {
            const enabledPath = path.join(NGINX_SITES_ENABLED, 'default');
            try { await fs.unlink(enabledPath); } catch {}
            await execPromise(`ln -s ${configPath} ${enabledPath}`);
        }

        await execPromise('nginx -t && systemctl reload nginx');
        addLog('Default deny configuration activated', 'info');

        res.json({ success: true });
    } catch (error) {
        addLog(`Error setting up default: ${error.message}`, 'error');
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// API Keys Management (Web UI)
// ============================================

// API: Список API ключей
app.get(SECRET_PATH + '/api/api-keys', authMiddleware, async (req, res) => {
    try {
        const keys = await listApiKeys();
        res.json(keys);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// API: Создать API ключ
app.post(SECRET_PATH + '/api/api-keys', authMiddleware, async (req, res) => {
    try {
        const { description, boundIP } = req.body;
        const apiKey = await createApiKey(description, boundIP || '');
        addLog(`API key created: ${description} (bound to: ${boundIP || 'all'})`, 'info');
        res.json({ success: true, apiKey });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// API: Удалить API ключ
app.delete(SECRET_PATH + '/api/api-keys/:key', authMiddleware, async (req, res) => {
    try {
        const { key } = req.params;
        const deleted = await deleteApiKey(key);
        if (deleted) {
            addLog(`API key deleted`, 'info');
            res.json({ success: true });
        } else {
            res.status(404).json({ error: 'API key not found' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// Public API (with API Key auth)
// ============================================

// GET /interfaces - Получить список IPv4 интерфейсов для привязки доменов
app.get('/api/v1/interfaces', apiKeyMiddleware, async (req, res) => {
    try {
        const os = require('os');
        const networkInterfaces = os.networkInterfaces();
        const interfaces = [];

        for (const [name, ifaces] of Object.entries(networkInterfaces)) {
            for (const iface of ifaces) {
                if (iface.family === 'IPv4' && !iface.internal && iface.address !== '127.0.0.1') {
                    interfaces.push({
                        interface: name,
                        address: iface.address
                    });
                }
            }
        }

        // Если ключ привязан к конкретному IP, показываем только его
        const boundIP = req.apiKeyData.boundIP;
        const filteredInterfaces = boundIP
            ? interfaces.filter(i => i.address === boundIP)
            : interfaces;

        res.json({
            success: true,
            data: filteredInterfaces,
            bound_to: boundIP || null
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message,
            code: 'INTERNAL_ERROR'
        });
    }
});

// POST /domain/add - Добавить домен
app.post('/api/v1/domain/add', apiKeyMiddleware, async (req, res) => {
    try {
        const { domain, proxy_pass, websocket_path, ssl_type, ssl_cert, ssl_key } = req.body;
        // Используем boundIP ключа для привязки домена
        const listenIP = req.apiKeyData.boundIP || '';

        if (!domain || !proxy_pass) {
            return res.status(400).json({
                success: false,
                error: 'Required fields: domain, proxy_pass',
                code: 'MISSING_REQUIRED_FIELDS'
            });
        }

        const sslType = ssl_type || 'letsencrypt';

        if (sslType === 'custom' && (!ssl_cert || !ssl_key)) {
            return res.status(400).json({
                success: false,
                error: 'Custom SSL requires ssl_cert and ssl_key',
                code: 'MISSING_SSL_DATA'
            });
        }

        const filename = `${domain}.conf`;
        const configPath = path.join(NGINX_CONF_DIR, filename);
        const certDir = `/etc/nginx/ssl/${domain}`;

        try {
            await fs.access(configPath);
            return res.status(409).json({
                success: false,
                error: 'Domain already exists',
                code: 'DOMAIN_EXISTS'
            });
        } catch {}

        let sslStatus = 'pending';
        let config;

        if (sslType === 'custom') {
            await execPromise(`mkdir -p ${certDir}`);
            await fs.writeFile(`${certDir}/fullchain.pem`, ssl_cert);
            await fs.writeFile(`${certDir}/privkey.pem`, ssl_key);
            await execPromise(`chmod 600 ${certDir}/privkey.pem`);
            config = generateNginxConfigCustomSSL(domain, proxy_pass, websocket_path || '', certDir, listenIP);
            sslStatus = 'ok';
        } else if (sslType === 'selfsigned') {
            await execPromise(`mkdir -p ${certDir}`);
            await execPromise(`openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ${certDir}/privkey.pem -out ${certDir}/fullchain.pem -subj "/C=RU/ST=Moscow/L=Moscow/O=Org/CN=${domain}"`);
            await execPromise(`chmod 600 ${certDir}/privkey.pem`);
            await execPromise(`openssl dhparam -out ${certDir}/dhparam.pem 2048`);
            config = generateNginxConfigSelfSigned(domain, proxy_pass, websocket_path || '', certDir, listenIP);
            sslStatus = 'ok';
        } else {
            config = generateNginxConfig(domain, proxy_pass, websocket_path || '', false, listenIP);
        }

        await fs.writeFile(configPath, config);

        if (OS_INFO.useSitesEnabled) {
            const enabledPath = path.join(NGINX_SITES_ENABLED, filename);
            try { await fs.unlink(enabledPath); } catch {}
            await execPromise(`ln -s ${configPath} ${enabledPath}`);
        }

        await execPromise('nginx -t && systemctl reload nginx');

        if (sslType === 'letsencrypt') {
            try {
                await execPromise('systemctl stop nginx');
                await execPromise(`certbot certonly --standalone --preferred-challenges http -d ${domain} --non-interactive --agree-tos --email admin@${domain}`);
                config = generateNginxConfig(domain, proxy_pass, websocket_path || '', true, listenIP);
                await fs.writeFile(configPath, config);
                await execPromise('systemctl start nginx');
                sslStatus = 'ok';
            } catch (error) {
                try { await execPromise('systemctl start nginx'); } catch {}
                sslStatus = 'error';
            }
        }

        addLog(`Domain ${domain} added via API (IP: ${listenIP || 'all'})`, 'info');

        res.json({
            success: true,
            data: {
                domain,
                filename,
                ssl_status: sslStatus,
                ssl_type: sslType
            }
        });
    } catch (error) {
        addLog(`API error adding domain: ${error.message}`, 'error');
        res.status(500).json({
            success: false,
            error: error.message,
            code: 'INTERNAL_ERROR'
        });
    }
});

// POST /domain/delete - Удалить домен
app.post('/api/v1/domain/delete', apiKeyMiddleware, async (req, res) => {
    try {
        const { domain } = req.body;
        const boundIP = req.apiKeyData.boundIP || '';

        if (!domain) {
            return res.status(400).json({
                success: false,
                error: 'Required field: domain',
                code: 'MISSING_REQUIRED_FIELDS'
            });
        }

        const filename = domain.endsWith('.conf') ? domain : `${domain}.conf`;

        if (filename === 'default' || filename === '00-default.conf') {
            return res.status(400).json({
                success: false,
                error: 'Cannot delete default config',
                code: 'PROTECTED_CONFIG'
            });
        }

        const configPath = path.join(NGINX_CONF_DIR, filename);

        try {
            await fs.access(configPath);
        } catch {
            return res.status(404).json({
                success: false,
                error: 'Domain not found',
                code: 'DOMAIN_NOT_FOUND'
            });
        }

        // Проверяем что домен привязан к IP ключа (если ключ ограничен)
        if (boundIP) {
            const content = await fs.readFile(configPath, 'utf8');
            const listenMatch = content.match(/listen\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+/);
            const domainIP = listenMatch ? listenMatch[1] : '';

            if (domainIP !== boundIP) {
                return res.status(403).json({
                    success: false,
                    error: 'Access denied: domain is not bound to your API key IP',
                    code: 'ACCESS_DENIED'
                });
            }
        }

        await fs.unlink(configPath);

        if (OS_INFO.useSitesEnabled) {
            try {
                await fs.unlink(path.join(NGINX_SITES_ENABLED, filename));
            } catch {}
        }

        await execPromise('nginx -t && systemctl reload nginx');
        addLog(`Domain ${domain} deleted via API`, 'info');

        res.json({
            success: true,
            data: { domain, deleted: true }
        });
    } catch (error) {
        addLog(`API error deleting domain: ${error.message}`, 'error');
        res.status(500).json({
            success: false,
            error: error.message,
            code: 'INTERNAL_ERROR'
        });
    }
});

// GET /domain/list - Список доменов
app.get('/api/v1/domain/list', apiKeyMiddleware, async (req, res) => {
    try {
        const boundIP = req.apiKeyData.boundIP || '';

        try {
            await fs.access(NGINX_CONF_DIR);
        } catch {
            await execPromise(`mkdir -p ${NGINX_CONF_DIR}`);
        }

        const files = await fs.readdir(NGINX_CONF_DIR);
        const domains = [];

        for (const file of files) {
            if (file === 'default' || file === '00-default.conf' || !file.endsWith('.conf')) continue;

            const configPath = path.join(NGINX_CONF_DIR, file);
            const content = await fs.readFile(configPath, 'utf8');

            // Extract listenIP from config
            const listenMatch = content.match(/listen\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+/);
            const listenIP = listenMatch ? listenMatch[1] : '';

            // Фильтруем по boundIP ключа (если ключ ограничен)
            if (boundIP && listenIP !== boundIP) {
                continue; // Пропускаем домены не привязанные к IP ключа
            }

            const domainMatch = content.match(/server_name\s+([^;]+);/);
            const domain = domainMatch ? domainMatch[1].trim() : 'unknown';

            const proxyPassMatch = content.match(/proxy_pass\s+([^;]+);/);
            const proxyPass = proxyPassMatch ? proxyPassMatch[1].trim() : '';

            const sslCertMatch = content.match(/ssl_certificate\s+([^;]+);/);
            let sslStatus = 'none';
            let sslType = 'none';

            if (sslCertMatch) {
                const certPath = sslCertMatch[1].trim();
                try {
                    await fs.access(certPath);
                    sslStatus = 'ok';
                    if (certPath.includes('/etc/letsencrypt/')) {
                        sslType = 'letsencrypt';
                    } else if (certPath.includes('/etc/nginx/ssl/')) {
                        sslType = 'custom';
                    }
                } catch {
                    sslStatus = 'error';
                }
            }

            domains.push({
                domain,
                filename: file,
                proxy_pass: proxyPass,
                ssl_status: sslStatus,
                ssl_type: sslType,
                listen_ip: listenIP || null
            });
        }

        res.json({
            success: true,
            data: domains,
            count: domains.length,
            bound_to: boundIP || null
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message,
            code: 'INTERNAL_ERROR'
        });
    }
});

// ============================================
// API Documentation (public)
// ============================================

app.get(API_DOCS_PATH, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'api-docs.html'));
});

// Запуск сервера
async function ensureDirectories() {
    const dirs = [NGINX_CONF_DIR, '/var/www/html/.well-known/acme-challenge'];
    for (const dir of dirs) {
        try {
            await fs.access(dir);
        } catch {
            await execPromise(`mkdir -p ${dir}`);
        }
    }
}

ensureDirectories().then(() => {
    app.listen(PORT, HOST, () => {
        console.log(`Nginx Manager running on http://${HOST}:${PORT}${SECRET_PATH}`);
        console.log(`OS: ${OS_INFO.name} ${OS_INFO.version} (${OS_INFO.family})`);
        console.log(`Nginx config dir: ${NGINX_CONF_DIR}`);
    });
}).catch(err => {
    console.error('Failed to initialize:', err);
    process.exit(1);
});

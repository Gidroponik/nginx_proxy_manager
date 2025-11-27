function extractHostFromUrl(url) {
    try {
        const urlObj = new URL(url);
        const host = urlObj.hostname;
        if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
            return null;
        }
        return host;
    } catch {
        return null;
    }
}

function generateNginxConfig(domain, proxyPass, websocketPath, withSSL, listenIP = '') {
    const proxyHost = extractHostFromUrl(proxyPass);
    const listen80 = listenIP ? `${listenIP}:80` : '80';
    const listen443 = listenIP ? `${listenIP}:443 ssl http2` : '443 ssl http2';
    let config = '';

    if (withSSL) {
        config += `server {
    listen ${listen80};${!listenIP ? '\n    listen [::]:80;' : ''}
    server_name ${domain};
    return 301 https://$host$request_uri;
}

server {
    listen ${listen443};${!listenIP ? '\n    listen [::]:443 ssl http2;' : ''}
    server_name ${domain};

    ssl_certificate /etc/letsencrypt/live/${domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
`;
    } else {
        config += `server {
    listen ${listen80};${!listenIP ? '\n    listen [::]:80;' : ''}
    server_name ${domain};

    location /.well-known/acme-challenge/ {
        alias /var/www/html/.well-known/acme-challenge/;
        try_files $uri =404;
    }
`;
    }

    if (websocketPath) {
        config += `
    location ${websocketPath} {
        proxy_pass ${proxyPass}${websocketPath};
        proxy_http_version 1.1;
${proxyHost ? `        proxy_ssl_server_name on;\n        proxy_set_header Host ${proxyHost};\n` : '        proxy_set_header Host $host;\n'}
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Client-Real-IP $remote_addr;
        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;
        proxy_buffering off;
    }
`;
    }

    config += `
    location / {
        proxy_pass ${proxyPass};
        proxy_http_version 1.1;
${proxyHost ? `        proxy_ssl_server_name on;\n        proxy_set_header Host ${proxyHost};\n` : '        proxy_set_header Host $host;\n'}
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Client-Real-IP $remote_addr;
        proxy_connect_timeout 120s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
        proxy_buffering off;
    }

    access_log off;
    error_log /dev/null;
    client_max_body_size 50M;
}`;

    return config;
}

function generateNginxConfigCustomSSL(domain, proxyPass, websocketPath, certDir, listenIP = '') {
    const proxyHost = extractHostFromUrl(proxyPass);
    const listen80 = listenIP ? `${listenIP}:80` : '80';
    const listen443 = listenIP ? `${listenIP}:443 ssl http2` : '443 ssl http2';

    let config = `server {
    listen ${listen80};${!listenIP ? '\n    listen [::]:80;' : ''}
    server_name ${domain};
    return 301 https://$host$request_uri;
}

server {
    listen ${listen443};${!listenIP ? '\n    listen [::]:443 ssl http2;' : ''}
    server_name ${domain};

    ssl_certificate ${certDir}/fullchain.pem;
    ssl_certificate_key ${certDir}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
`;

    if (websocketPath) {
        config += `
    location ${websocketPath} {
        proxy_pass ${proxyPass}${websocketPath};
        proxy_http_version 1.1;
${proxyHost ? `        proxy_ssl_server_name on;\n        proxy_set_header Host ${proxyHost};\n` : '        proxy_set_header Host $host;\n'}
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Client-Real-IP $remote_addr;
        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;
        proxy_buffering off;
    }
`;
    }

    config += `
    location / {
        proxy_pass ${proxyPass};
        proxy_http_version 1.1;
${proxyHost ? `        proxy_ssl_server_name on;\n        proxy_set_header Host ${proxyHost};\n` : '        proxy_set_header Host $host;\n'}
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Client-Real-IP $remote_addr;
        proxy_connect_timeout 120s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
        proxy_buffering off;
    }

    access_log off;
    error_log /dev/null;
    client_max_body_size 50M;
}`;

    return config;
}

function generateNginxConfigSelfSigned(domain, proxyPass, websocketPath, certDir, listenIP = '') {
    const proxyHost = extractHostFromUrl(proxyPass);
    const listen80 = listenIP ? `${listenIP}:80` : '80';
    const listen443 = listenIP ? `${listenIP}:443 ssl http2` : '443 ssl http2';

    let config = `server {
    listen ${listen80};${!listenIP ? '\n    listen [::]:80;' : ''}
    server_name ${domain};
    return 301 https://$host$request_uri;
}

server {
    listen ${listen443};${!listenIP ? '\n    listen [::]:443 ssl http2;' : ''}
    server_name ${domain};

    ssl_certificate ${certDir}/fullchain.pem;
    ssl_certificate_key ${certDir}/privkey.pem;
    ssl_dhparam ${certDir}/dhparam.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
    ssl_ecdh_curve secp384r1;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    ssl_stapling off;
`;

    if (websocketPath) {
        config += `
    location ${websocketPath} {
        proxy_pass ${proxyPass}${websocketPath};
        proxy_http_version 1.1;
${proxyHost ? `        proxy_ssl_server_name on;\n        proxy_set_header Host ${proxyHost};\n` : '        proxy_set_header Host $host;\n'}
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Client-Real-IP $remote_addr;
        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;
        proxy_buffering off;
    }
`;
    }

    config += `
    location / {
        proxy_pass ${proxyPass};
        proxy_http_version 1.1;
${proxyHost ? `        proxy_ssl_server_name on;\n        proxy_set_header Host ${proxyHost};\n` : '        proxy_set_header Host $host;\n'}
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Client-Real-IP $remote_addr;
        proxy_connect_timeout 120s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
        proxy_buffering off;
    }

    access_log off;
    error_log /dev/null;
    client_max_body_size 50M;
}`;

    return config;
}

function generateDefaultConfig() {
    return `# Default server - блокирует запросы к неизвестным доменам
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 444;
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;
    ssl_certificate /etc/nginx/ssl/default/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/default/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    return 444;
}
`;
}

module.exports = {
    extractHostFromUrl,
    generateNginxConfig,
    generateNginxConfigCustomSSL,
    generateNginxConfigSelfSigned,
    generateDefaultConfig
};

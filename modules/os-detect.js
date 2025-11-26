const fs = require('fs');

function detectOS() {
    let osInfo = {
        name: 'Unknown',
        version: '',
        family: 'unknown',
        nginxConfDir: '/etc/nginx/conf.d',
        nginxSitesAvailable: '/etc/nginx/sites-available',
        nginxSitesEnabled: '/etc/nginx/sites-enabled',
        useSitesEnabled: false
    };

    try {
        if (fs.existsSync('/etc/os-release')) {
            const osRelease = fs.readFileSync('/etc/os-release', 'utf8');
            const lines = osRelease.split('\n');
            const osData = {};
            for (const line of lines) {
                const [key, value] = line.split('=');
                if (key && value) {
                    osData[key] = value.replace(/"/g, '');
                }
            }

            osInfo.name = osData.NAME || osData.ID || 'Unknown';
            osInfo.version = osData.VERSION_ID || osData.VERSION || '';

            const id = (osData.ID || '').toLowerCase();
            const idLike = (osData.ID_LIKE || '').toLowerCase();

            if (id === 'ubuntu' || id === 'debian' || idLike.includes('debian') || idLike.includes('ubuntu')) {
                osInfo.family = 'debian';
                osInfo.useSitesEnabled = true;
            } else if (id === 'almalinux' || id === 'rocky' || id === 'centos' || id === 'rhel' || id === 'fedora' || idLike.includes('rhel') || idLike.includes('fedora')) {
                osInfo.family = 'rhel';
                osInfo.useSitesEnabled = false;
            }
        }
    } catch (e) {
        console.error('Error detecting OS:', e.message);
    }

    return osInfo;
}

module.exports = { detectOS };

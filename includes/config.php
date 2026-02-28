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

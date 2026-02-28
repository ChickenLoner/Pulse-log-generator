<?php
/**
 * Pulse Generator — Legitimate Traffic Generator
 * Generates realistic normal browsing noise for BrightMall
 */

require_once __DIR__ . '/config.php';

/**
 * Generate noise log lines
 * 
 * @param int $count Number of noise lines
 * @param DateTime $startTime Start of time window
 * @param DateTime $endTime End of time window
 * @return array Array of ['timestamp' => DateTime, 'line' => string]
 */
function generateNoise($count, $startTime, $endTime) {
    $lines = [];
    $startTs = $startTime->getTimestamp();
    $endTs = $endTime->getTimestamp();
    $ips = LEGIT_IPS;

    // Simulate user sessions — groups of requests from same IP in short time spans
    $sessionCount = max(1, intval($count / 8)); // avg ~8 requests per session
    $sessions = [];

    for ($s = 0; $s < $sessionCount; $s++) {
        $sessionIp = pick($ips);
        $sessionUa = pick(USER_AGENTS);
        $sessionStart = mt_rand($startTs, max($startTs, $endTs - 300));
        $requestsInSession = mt_rand(3, 15);
        $sessions[] = [
            'ip' => $sessionIp,
            'ua' => $sessionUa,
            'start' => $sessionStart,
            'requests' => $requestsInSession,
        ];
    }

    $generated = 0;
    foreach ($sessions as $session) {
        if ($generated >= $count) break;

        $currentTs = $session['start'];
        for ($r = 0; $r < $session['requests'] && $generated < $count; $r++) {
            // Pick a path — mostly normal, small chance of 404
            if (mt_rand(1, 100) <= 5) {
                $pathEntry = pick(NORMAL_404_PATHS);
            } else {
                $pathEntry = pick(NORMAL_PATHS);
            }

            $method = $pathEntry[0];
            $path = $pathEntry[1];
            $status = $pathEntry[2];
            $sizeRange = $pathEntry[3];
            $size = ($sizeRange[0] === $sizeRange[1]) ? $sizeRange[0] : randBetween($sizeRange[0], $sizeRange[1]);

            // Sometimes vary product IDs
            if (strpos($path, 'product.php?id=') !== false && mt_rand(1, 3) === 1) {
                $path = '/product.php?id=' . mt_rand(1, 20);
            }

            $referer = pick(REFERERS);
            $httpVer = pick(HTTP_VERSIONS);

            $ts = new DateTime();
            $ts->setTimestamp($currentTs);

            $lines[] = [
                'timestamp' => clone $ts,
                'line' => formatLogLine(
                    $session['ip'], $ts, $method, $path, $httpVer,
                    $status, $size, $referer, $session['ua']
                ),
            ];

            // Advance time within session (0.5s to 30s between requests)
            $currentTs += mt_rand(500, 30000) / 1000;
            $generated++;
        }
    }

    return $lines;
}

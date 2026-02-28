<?php
/**
 * Pulse Generator — Nginx Access Log
 * Same BrightMall app, Nginx log format with request timing
 */

require_once __DIR__ . '/config.php';

/**
 * Generate Nginx noise traffic
 */
function generateNginxNoise($count, $startTime, $endTime) {
    $lines = [];
    $startTs = $startTime->getTimestamp();
    $endTs = $endTime->getTimestamp();
    $ips = LEGIT_IPS;

    $sessionCount = max(1, intval($count / 8));
    $generated = 0;

    for ($s = 0; $s < $sessionCount && $generated < $count; $s++) {
        $sessionIp = pick($ips);
        $sessionUa = pick(USER_AGENTS);
        $sessionStart = mt_rand($startTs, max($startTs, $endTs - 300));
        $requestsInSession = mt_rand(3, 15);
        $currentTs = $sessionStart;

        for ($r = 0; $r < $requestsInSession && $generated < $count; $r++) {
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

            $referer = pick(REFERERS);
            $httpVer = pick(HTTP_VERSIONS);
            $rt = mt_rand(1, 3000) / 1000;

            $ts = new DateTime();
            $ts->setTimestamp($currentTs);

            $lines[] = [
                'timestamp' => clone $ts,
                'line' => formatNginxLogLine(
                    $sessionIp, $ts, $method, $path, $httpVer,
                    $status, $size, $referer, $sessionUa, $rt
                ),
            ];

            $currentTs += mt_rand(500, 30000) / 1000;
            $generated++;
        }
    }

    return $lines;
}

/**
 * Generate Nginx LFI attack lines
 */
function generateNginxLfi($attackerCount, $difficulty, $startTime, $endTime) {
    // Reuse payload definitions from pages.php
    require_once __DIR__ . '/pages.php';

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
        $attackStart = mt_rand($startTs + intval(($endTs - $startTs) * 0.2), intval($startTs + ($endTs - $startTs) * 0.6));
        $currentTs = $attackStart;

        $selectedPayloads = $payloads;
        shuffle($selectedPayloads);
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
            $targetedFile = urldecode($payload[0]);
            if (!in_array($targetedFile, $answers['targeted_files'])) {
                $answers['targeted_files'][] = $targetedFile;
            }

            $size = ($status === 200) ? randBetween(128, 4096) : randBetween(256, 512);
            $ts = new DateTime();
            $ts->setTimestamp($currentTs);

            $lines[] = [
                'timestamp' => clone $ts,
                'line' => formatNginxLogLine(
                    $ip, $ts, 'GET', $path, 'HTTP/1.1',
                    $status, $size, '-', $ua, mt_rand(1, 500) / 1000
                ),
            ];
            $currentTs += (mt_rand(1, 10) <= 3) ? mt_rand(1, 2) : mt_rand(3, 8);
        }
    }

    return ['lines' => $lines, 'answers' => $answers];
}

/**
 * Generate Nginx bruteforce attack lines
 */
function generateNginxBruteforce($attackerCount, $difficulty, $startTime, $endTime) {
    $lines = [];
    $answers = [
        'type' => 'HTTP Bruteforce',
        'target' => '/account/login.php',
        'attacker_ips' => [],
        'total_attempts_per_ip' => [],
        'success' => [],
    ];

    $attackerIps = pickN(ATTACKER_IP_POOL, $attackerCount);
    $startTs = $startTime->getTimestamp();
    $endTs = $endTime->getTimestamp();
    $answers['attacker_ips'] = $attackerIps;

    $attemptRanges = match($difficulty) {
        'easy' => [50, 120], 'medium' => [30, 80], 'hard' => [15, 40], default => [30, 80],
    };
    $delayRanges = match($difficulty) {
        'easy' => [1, 3], 'medium' => [2, 8], 'hard' => [5, 30], default => [2, 8],
    };

    foreach ($attackerIps as $ip) {
        $ua = pick(ATTACKER_USER_AGENTS);
        $attempts = mt_rand($attemptRanges[0], $attemptRanges[1]);
        $answers['total_attempts_per_ip'][$ip] = $attempts;
        $attackStart = mt_rand($startTs, $startTs + intval(($endTs - $startTs) * 0.7));
        $currentTs = $attackStart;
        $successAttempt = mt_rand(intval($attempts * 0.7), $attempts - 1);

        for ($a = 0; $a < $attempts; $a++) {
            $isSuccess = ($a === $successAttempt);
            $status = $isSuccess ? 302 : 200;
            $size = $isSuccess ? 0 : randBetween(1800, 2400);
            $ts = new DateTime();
            $ts->setTimestamp($currentTs);

            $lines[] = [
                'timestamp' => clone $ts,
                'line' => formatNginxLogLine(
                    $ip, $ts, 'POST', '/account/login.php', 'HTTP/1.1',
                    $status, $size,
                    'https://brightmall.local/account/login.php', $ua,
                    mt_rand(50, 2000) / 1000
                ),
            ];

            if ($isSuccess) {
                $answers['success'][] = ['ip' => $ip, 'attempt_number' => $a + 1];
            }
            $currentTs += mt_rand($delayRanges[0], $delayRanges[1]);
        }
    }

    return ['lines' => $lines, 'answers' => $answers];
}

/**
 * Generate Nginx webshell attack lines
 */
function generateNginxWebshell($attackerCount, $difficulty, $startTime, $endTime) {
    require_once __DIR__ . '/cache.php';

    $lines = [];
    $answers = [
        'type' => 'Webshell',
        'shell_paths' => [],
        'attacker_ips' => [],
        'commands_executed' => [],
    ];

    $attackerIps = pickN(ATTACKER_IP_POOL, $attackerCount);
    $commands = getWebshellCommands($difficulty);
    $shellPaths = getShellPaths($difficulty);
    $shellParams = getShellParams($difficulty);
    $startTs = $startTime->getTimestamp();
    $endTs = $endTime->getTimestamp();

    $answers['attacker_ips'] = $attackerIps;
    $answers['shell_paths'] = $shellPaths;

    foreach ($attackerIps as $ipIdx => $ip) {
        $ua = pick(ATTACKER_USER_AGENTS);
        $shellPath = $shellPaths[$ipIdx % count($shellPaths)];
        $param = $shellParams[$ipIdx % count($shellParams)];
        $attackStart = mt_rand($startTs + intval(($endTs - $startTs) * 0.2), $startTs + intval(($endTs - $startTs) * 0.5));
        $currentTs = $attackStart;

        $cmdCount = match($difficulty) {
            'easy' => mt_rand(6, 10), 'medium' => mt_rand(12, 20), 'hard' => mt_rand(18, count($commands)), default => mt_rand(12, 20),
        };
        $selectedCommands = array_slice($commands, 0, $cmdCount);

        foreach ($selectedCommands as $cmd) {
            $path = $shellPath . '?' . $param . '=' . $cmd[1];
            $answers['commands_executed'][] = $cmd[0];

            $ts = new DateTime();
            $ts->setTimestamp($currentTs);
            $lines[] = [
                'timestamp' => clone $ts,
                'line' => formatNginxLogLine(
                    $ip, $ts, 'GET', $path, 'HTTP/1.1',
                    200, randBetween(128, 8192), '-', $ua, mt_rand(10, 5000) / 1000
                ),
            ];
            $currentTs += (mt_rand(1, 4) === 1) ? mt_rand(1, 5) : mt_rand(8, 45);
        }
    }

    $answers['commands_executed'] = array_values(array_unique($answers['commands_executed']));
    return ['lines' => $lines, 'answers' => $answers];
}

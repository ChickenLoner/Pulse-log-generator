<?php
/**
 * Pulse Generator — HTTP Bruteforce Attack Scenario
 * Generates credential stuffing / brute force patterns against login
 */

require_once __DIR__ . '/config.php';

/**
 * Generate bruteforce attack log lines
 * 
 * @param int $attackerCount Number of brute-forcing IPs
 * @param string $difficulty easy|medium|hard
 * @param DateTime $startTime
 * @param DateTime $endTime
 * @return array ['lines' => [...], 'answers' => [...]]
 */
function generateBruteforce($attackerCount, $difficulty, $startTime, $endTime) {
    $lines = [];

    $loginEndpoint = getOverride('brute_endpoint', '/account/login.php');
    $successCode = intval(getOverride('brute_success_code', 302));

    $answers = [
        'type' => 'HTTP Bruteforce',
        'target' => $loginEndpoint,
        'attacker_ips' => [],
        'total_attempts_per_ip' => [],
        'success' => [],
    ];

    $attackerIps = pickN(
        !empty($GLOBALS['pulse_attacker_ips']) ? $GLOBALS['pulse_attacker_ips'] : ATTACKER_IP_POOL,
        $attackerCount
    );
    $startTs = $startTime->getTimestamp();
    $endTs = $endTime->getTimestamp();

    $answers['attacker_ips'] = $attackerIps;

    // Difficulty controls: attempt count, timing, behavioral realism
    $attemptRanges = match($difficulty) {
        'easy'   => [50, 120],   // obvious high-volume spray
        'medium' => [30, 80],    // moderate, mixed timing
        'hard'   => [15, 40],    // slower, looks more like legit traffic with subtle patterns
        default  => [30, 80],
    };

    // Delay between attempts (milliseconds conceptually, used as seconds)
    $delayRanges = match($difficulty) {
        'easy'   => [1, 3],      // rapid fire
        'medium' => [2, 8],      // some variation
        'hard'   => [5, 30],     // slow and stealthy
        default  => [2, 8],
    };

    // User agents for hard mode — attacker rotates UAs
    $rotateUa = ($difficulty === 'hard');

    foreach ($attackerIps as $idx => $ip) {
        $ua = pick(ATTACKER_USER_AGENTS);
        $attempts = mt_rand($attemptRanges[0], $attemptRanges[1]);
        $answers['total_attempts_per_ip'][$ip] = $attempts;

        // Attack starts at a random point in the time window
        $attackWindow = intval(($endTs - $startTs) * 0.7);
        $attackStart = mt_rand($startTs, $startTs + $attackWindow);
        $currentTs = $attackStart;

        // On hard mode, attacker might load the login page first (GET) before each POST
        $doGetBeforePost = ($difficulty === 'hard');

        // Decide when the successful login happens (if at all)
        $successAttempt = mt_rand(intval($attempts * 0.7), $attempts - 1);

        for ($a = 0; $a < $attempts; $a++) {
            if ($rotateUa && mt_rand(1, 5) === 1) {
                $ua = pick(ATTACKER_USER_AGENTS);
            }

            // On hard mode, sometimes GET the login page first
            if ($doGetBeforePost && mt_rand(1, 3) === 1) {
                $ts = new DateTime();
                $ts->setTimestamp($currentTs);
                $lines[] = [
                    'timestamp' => clone $ts,
                    'line' => formatLogLine(
                        $ip, $ts, 'GET', $loginEndpoint, 'HTTP/1.1',
                        200, randBetween(1024, 2048),
                        'https://brightmall.local/', $ua
                    ),
                ];
                $currentTs += mt_rand(1, 3);
            }

            // Determine status for this attempt
            $isSuccess = ($a === $successAttempt);

            if ($isSuccess) {
                // Successful login → 302 redirect, then a follow-up GET to profile
                $status = 302;
                $size = 0;
                $answers['success'][] = [
                    'ip' => $ip,
                    'attempt_number' => $a + 1,
                ];
            } else {
                // Failed login → 200 with login page (error message shown)
                $status = 200;
                $size = randBetween(1800, 2400);
            }

            $ts = new DateTime();
            $ts->setTimestamp($currentTs);

            $lines[] = [
                'timestamp' => clone $ts,
                'line' => formatLogLine(
                    $ip, $ts, 'POST', $loginEndpoint, 'HTTP/1.1',
                    $status, $size,
                    'https://brightmall.local/account/login.php', $ua
                ),
            ];

            // If success, add follow-up requests (redirect target + browsing)
            if ($isSuccess) {
                $currentTs += 1;
                $ts2 = new DateTime();
                $ts2->setTimestamp($currentTs);
                $lines[] = [
                    'timestamp' => clone $ts2,
                    'line' => formatLogLine(
                        $ip, $ts2, 'GET', '/account/profile.php', 'HTTP/1.1',
                        200, randBetween(2048, 3072),
                        'https://brightmall.local/account/login.php', $ua
                    ),
                ];

                // Maybe browse a bit after successful login
                $postLoginPaths = [
                    '/products.php',
                    '/account/profile.php',
                    '/cart.php',
                ];
                $browseCount = mt_rand(1, 3);
                for ($b = 0; $b < $browseCount; $b++) {
                    $currentTs += mt_rand(5, 20);
                    $ts3 = new DateTime();
                    $ts3->setTimestamp($currentTs);
                    $lines[] = [
                        'timestamp' => clone $ts3,
                        'line' => formatLogLine(
                            $ip, $ts3, 'GET', pick($postLoginPaths), 'HTTP/1.1',
                            200, randBetween(2048, 8192),
                            'https://brightmall.local/account/profile.php', $ua
                        ),
                    ];
                }
            }

            // Delay to next attempt
            $delay = mt_rand($delayRanges[0], $delayRanges[1]);
            // On easy mode, add occasional micro-bursts
            if ($difficulty === 'easy' && mt_rand(1, 4) === 1) {
                $delay = 0;
            }
            $currentTs += $delay;
        }
    }

    // Also generate some legitimate failed logins from normal users (1-2 attempts then success)
    $legitFailCount = mt_rand(2, 5);
    for ($l = 0; $l < $legitFailCount; $l++) {
        $legitIp = pick(LEGIT_IPS);
        $legitUa = pick(USER_AGENTS);
        $legitTime = mt_rand($startTs, $endTs - 60);

        // 1-2 failures
        $fails = mt_rand(1, 2);
        for ($f = 0; $f < $fails; $f++) {
            $ts = new DateTime();
            $ts->setTimestamp($legitTime);
            $lines[] = [
                'timestamp' => clone $ts,
                'line' => formatLogLine(
                    $legitIp, $ts, 'POST', $loginEndpoint, 'HTTP/1.1',
                    200, randBetween(1800, 2400),
                    'https://brightmall.local/account/login.php', $legitUa
                ),
            ];
            $legitTime += mt_rand(5, 20);
        }

        // Then success
        $ts = new DateTime();
        $ts->setTimestamp($legitTime);
        $lines[] = [
            'timestamp' => clone $ts,
            'line' => formatLogLine(
                $legitIp, $ts, 'POST', $loginEndpoint, 'HTTP/1.1',
                302, 0,
                'https://brightmall.local/account/login.php', $legitUa
            ),
        ];
    }

    return ['lines' => $lines, 'answers' => $answers];
}

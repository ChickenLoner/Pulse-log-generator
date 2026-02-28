<?php
/**
 * Pulse Generator — Firewall (iptables) Log
 * Generates kernel syslog-style firewall logs with network-layer attacks
 */

require_once __DIR__ . '/config.php';

/**
 * Generate firewall noise traffic
 */
function generateFwNoise($count, $startTime, $endTime) {
    $lines = [];
    $startTs = $startTime->getTimestamp();
    $endTs = $endTime->getTimestamp();
    $hostname = FW_HOSTNAME;
    $generated = 0;

    while ($generated < $count) {
        $ts = mt_rand($startTs, $endTs);
        $dt = new DateTime(); $dt->setTimestamp($ts);
        $eventType = mt_rand(1, 100);

        if ($eventType <= 50) {
            // ACCEPT — normal outbound traffic
            $srcIp = FW_INTERNAL_NET . mt_rand(10, 250);
            $dstIp = pick(FW_LEGIT_DEST_IPS);
            $dstPort = pick(FW_LEGIT_PORTS);
            $srcPort = mt_rand(32768, 65535);
            $proto = ($dstPort === 53 && mt_rand(1, 3) === 1) ? 'UDP' : 'TCP';

            $lines[] = [
                'timestamp' => clone $dt,
                'line' => formatFwLogLine($dt, $hostname, 'ACCEPT', 'eth1', 'eth0', $srcIp, $dstIp, $proto, $srcPort, $dstPort),
            ];

        } elseif ($eventType <= 70) {
            // ACCEPT — inbound to DMZ server
            $srcIp = pick(FW_LEGIT_DEST_IPS);
            $dstIp = FW_SERVER_IP;
            $dstPort = pick([80, 443]);
            $srcPort = mt_rand(32768, 65535);

            $lines[] = [
                'timestamp' => clone $dt,
                'line' => formatFwLogLine($dt, $hostname, 'ACCEPT', 'eth0', 'eth2', $srcIp, $dstIp, 'TCP', $srcPort, $dstPort),
            ];

        } elseif ($eventType <= 85) {
            // DROP — random noise (internet scanners, etc.)
            $srcIp = mt_rand(1, 223) . '.' . mt_rand(0, 255) . '.' . mt_rand(0, 255) . '.' . mt_rand(1, 254);
            $dstIp = FW_SERVER_IP;
            $dstPort = pick([23, 445, 3389, 8443, 8888, 9090, 1433, 5900, 6379, 27017]);
            $srcPort = mt_rand(32768, 65535);

            $lines[] = [
                'timestamp' => clone $dt,
                'line' => formatFwLogLine($dt, $hostname, 'DROP', 'eth0', '', $srcIp, $dstIp, 'TCP', $srcPort, $dstPort, 'SYN'),
            ];

        } elseif ($eventType <= 93) {
            // ACCEPT — DNS queries
            $srcIp = FW_INTERNAL_NET . mt_rand(10, 250);
            $dstIp = pick(['8.8.8.8', '8.8.4.4', '1.1.1.1']);

            $lines[] = [
                'timestamp' => clone $dt,
                'line' => formatFwLogLine($dt, $hostname, 'ACCEPT', 'eth1', 'eth0', $srcIp, $dstIp, 'UDP', mt_rand(32768, 65535), 53),
            ];

        } else {
            // ACCEPT — ICMP (ping)
            $srcIp = FW_INTERNAL_NET . mt_rand(10, 250);
            $dstIp = pick(FW_LEGIT_DEST_IPS);

            $lines[] = [
                'timestamp' => clone $dt,
                'line' => formatFwLogLine($dt, $hostname, 'ACCEPT', 'eth1', 'eth0', $srcIp, $dstIp, 'ICMP', 0, 0),
            ];
        }

        $generated++;
    }

    return $lines;
}

/**
 * Generate port scan attack
 */
function generateFwPortScan($attackerCount, $difficulty, $startTime, $endTime) {
    $lines = [];
    $answers = [
        'type' => 'Port Scan',
        'attacker_ips' => [],
        'target_ip' => $targetIp,
        'ports_scanned' => [],
        'scan_type' => '',
    ];

    $attackerIps = pickN(
        !empty($GLOBALS['pulse_attacker_ips']) ? $GLOBALS['pulse_attacker_ips'] : ATTACKER_IP_POOL,
        $attackerCount
    );
    $startTs = $startTime->getTimestamp();
    $endTs = $endTime->getTimestamp();
    $hostname = FW_HOSTNAME;
    $targetIp = getOverride('fw_target_ip', FW_SERVER_IP);
    $answers['attacker_ips'] = $attackerIps;
    $answers['target_ip'] = $targetIp;

    $portRanges = match($difficulty) {
        'easy' => range(1, 1024),       // full sequential scan, very obvious
        'medium' => array_merge(range(1, 100), [135, 139, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9090, 27017]),
        'hard' => [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443, 9200, 27017],
        default => array_merge(range(1, 100), [135, 139, 443, 445, 1433, 3306, 3389, 5432, 5900]),
    };

    // On hard mode, scan is slow and randomized
    if ($difficulty === 'hard') {
        shuffle($portRanges);
        $answers['scan_type'] = 'Randomized stealth scan';
    } else {
        $answers['scan_type'] = 'Sequential SYN scan';
    }

    $delayRanges = match($difficulty) {
        'easy' => [0, 1],          // burst
        'medium' => [1, 5],
        'hard' => [10, 60],        // very slow
        default => [1, 5],
    };

    foreach ($attackerIps as $ip) {
        $attackStart = mt_rand($startTs, $startTs + intval(($endTs - $startTs) * 0.3));
        $currentTs = $attackStart;
        $portsForThisIp = [];

        foreach ($portRanges as $port) {
            $dt = new DateTime(); $dt->setTimestamp($currentTs);
            $srcPort = mt_rand(32768, 65535);

            // Most ports get DROP, some common ones get ACCEPT (open)
            $openPorts = [22, 80, 443, 3306];
            $action = in_array($port, $openPorts) ? 'ACCEPT' : 'DROP';

            $lines[] = [
                'timestamp' => clone $dt,
                'line' => formatFwLogLine($dt, $hostname, $action, 'eth0', ($action === 'ACCEPT' ? 'eth2' : ''), $ip, $targetIp, 'TCP', $srcPort, $port, 'SYN'),
            ];

            $portsForThisIp[] = $port;
            $delay = mt_rand($delayRanges[0], $delayRanges[1]);
            if ($difficulty === 'easy' && mt_rand(1, 5) === 1) $delay = 0;
            $currentTs += $delay;
        }

        $answers['ports_scanned'] = $portsForThisIp;
    }

    return ['lines' => $lines, 'answers' => $answers];
}

/**
 * Generate C2 beaconing pattern
 */
function generateFwBeacon($attackerCount, $difficulty, $startTime, $endTime) {
    $lines = [];
    $answers = [
        'type' => 'C2 Beaconing',
        'infected_hosts' => [],
        'c2_servers' => [],
        'beacon_interval_seconds' => 0,
        'c2_port' => 0,
    ];

    $startTs = $startTime->getTimestamp();
    $endTs = $endTime->getTimestamp();
    $hostname = FW_HOSTNAME;

    // Infected internal host(s)
    $infectedCount = min($attackerCount, 3);
    $infectedHosts = [];
    for ($i = 0; $i < $infectedCount; $i++) {
        $infectedHosts[] = FW_INTERNAL_NET . mt_rand(10, 250);
    }

    // C2 server (override or random)
    $c2Ip = getOverride('fw_c2_ip', null) ?: pick(FW_C2_IPS);
    $c2Port = intval(getOverride('fw_c2_port', 0)) ?: pick([443, 8443, 4444, 8080, 53]);

    // Beacon interval (override or difficulty-based)
    $customInterval = intval(getOverride('fw_beacon_interval', 0));
    $baseInterval = $customInterval ?: match($difficulty) {
        'easy' => 60,
        'medium' => 120,
        'hard' => 300,
        default => 120,
    };

    // Jitter (override or difficulty-based)
    $customJitter = getOverride('fw_beacon_jitter', null);
    if ($customJitter !== null) {
        $jitter = intval($baseInterval * (intval($customJitter) / 100));
    } else {
        $jitter = match($difficulty) {
            'easy' => 0,
            'medium' => intval($baseInterval * 0.1),
            'hard' => intval($baseInterval * 0.3),
            default => intval($baseInterval * 0.1),
        };
    }

    $answers['infected_hosts'] = $infectedHosts;
    $answers['c2_servers'] = [$c2Ip];
    $answers['beacon_interval_seconds'] = $baseInterval;
    $answers['c2_port'] = $c2Port;

    foreach ($infectedHosts as $srcIp) {
        $currentTs = $startTs + mt_rand(0, $baseInterval);
        $proto = ($c2Port === 53) ? 'UDP' : 'TCP';

        while ($currentTs < $endTs) {
            $dt = new DateTime(); $dt->setTimestamp($currentTs);
            $srcPort = mt_rand(32768, 65535);

            $lines[] = [
                'timestamp' => clone $dt,
                'line' => formatFwLogLine($dt, $hostname, 'ACCEPT', 'eth1', 'eth0', $srcIp, $c2Ip, $proto, $srcPort, $c2Port, ($proto === 'TCP' ? 'SYN ACK' : '')),
            ];

            // Next beacon
            $actualInterval = $baseInterval + mt_rand(-$jitter, $jitter);
            $currentTs += max(10, $actualInterval);
        }
    }

    return ['lines' => $lines, 'answers' => $answers];
}

/**
 * Generate data exfiltration pattern
 */
function generateFwExfil($attackerCount, $difficulty, $startTime, $endTime) {
    $lines = [];
    $answers = [
        'type' => 'Data Exfiltration',
        'source_host' => '',
        'exfil_destination' => '',
        'exfil_port' => 0,
        'total_connections' => 0,
    ];

    $startTs = $startTime->getTimestamp();
    $endTs = $endTime->getTimestamp();
    $hostname = FW_HOSTNAME;

    $infectedHost = FW_INTERNAL_NET . mt_rand(10, 250);
    $exfilDst = getOverride('fw_exfil_ip', null) ?: pick(FW_C2_IPS);
    $exfilPort = intval(getOverride('fw_exfil_port', 0)) ?: pick([443, 8443, 21, 22]);
    $proto = ($exfilPort === 21) ? 'TCP' : 'TCP';

    $answers['source_host'] = $infectedHost;
    $answers['exfil_destination'] = $exfilDst;
    $answers['exfil_port'] = $exfilPort;

    // Exfil happens in bursts
    $burstCount = match($difficulty) {
        'easy' => mt_rand(3, 5),     // large obvious bursts
        'medium' => mt_rand(5, 10),  // moderate
        'hard' => mt_rand(10, 20),   // many small transfers
        default => mt_rand(5, 10),
    };
    $connectionsPerBurst = match($difficulty) {
        'easy' => mt_rand(20, 50),
        'medium' => mt_rand(10, 25),
        'hard' => mt_rand(3, 8),
        default => mt_rand(10, 25),
    };

    $totalConns = 0;

    for ($b = 0; $b < $burstCount; $b++) {
        $burstStart = mt_rand($startTs + intval(($endTs - $startTs) * 0.4), $endTs - 300);
        $currentTs = $burstStart;

        for ($c = 0; $c < $connectionsPerBurst; $c++) {
            $dt = new DateTime(); $dt->setTimestamp($currentTs);
            $srcPort = mt_rand(32768, 65535);

            $lines[] = [
                'timestamp' => clone $dt,
                'line' => formatFwLogLine($dt, $hostname, 'ACCEPT', 'eth1', 'eth0', $infectedHost, $exfilDst, $proto, $srcPort, $exfilPort, 'SYN ACK PSH'),
            ];

            $currentTs += mt_rand(1, 5);
            $totalConns++;
        }
    }

    $answers['total_connections'] = $totalConns;

    return ['lines' => $lines, 'answers' => $answers];
}

<?php
/**
 * Pulse Generator — Generate Endpoint
 * Routes to the correct generator based on log_type
 * Supports advanced overrides via $GLOBALS['pulse_overrides']
 */

header('Content-Type: application/json');

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/traffic.php';
require_once __DIR__ . '/includes/pages.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/cache.php';
require_once __DIR__ . '/includes/remote.php';
require_once __DIR__ . '/includes/proxy.php';
require_once __DIR__ . '/includes/service.php';
require_once __DIR__ . '/includes/events.php';
require_once __DIR__ . '/includes/netflow.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);
if (!$input) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid JSON']);
    exit;
}

$logType        = $input['log_type'] ?? 'apache';
$scenarios      = $input['scenarios'] ?? [];
$noiseLines     = max(50, min(5000, intval($input['noise_lines'] ?? 500)));
$difficulty     = in_array($input['difficulty'] ?? '', ['easy', 'medium', 'hard']) ? $input['difficulty'] : 'medium';
$attackerCount  = max(1, min(4, intval($input['attacker_count'] ?? 1)));
$timeSpanHours  = max(1, min(48, intval($input['time_span_hours'] ?? 6)));
$outputMode     = $input['output_mode'] ?? 'download';

$validTypes = ['apache', 'nginx', 'iis', 'ssh', 'windows', 'firewall'];
$logType = in_array($logType, $validTypes) ? $logType : 'apache';

// ============================
// Store overrides globally so generators can read them
// ============================
$GLOBALS['pulse_overrides'] = $input['overrides'] ?? [];

// Override attacker IPs if custom ones provided
if (!empty($GLOBALS['pulse_overrides']['custom_attacker_ips'])) {
    $customIps = $GLOBALS['pulse_overrides']['custom_attacker_ips'];
    // Validate IPs
    $validIps = array_filter($customIps, fn($ip) => filter_var($ip, FILTER_VALIDATE_IP));
    if (!empty($validIps)) {
        $GLOBALS['pulse_attacker_ips'] = array_values($validIps);
    }
}

/**
 * Helper: get attacker IPs (respects custom override)
 */
function getAttackerIps($count) {
    if (!empty($GLOBALS['pulse_attacker_ips'])) {
        $pool = $GLOBALS['pulse_attacker_ips'];
    } else {
        $pool = ATTACKER_IP_POOL;
    }
    return pickN($pool, $count);
}

$endTime = new DateTime();
$startTime = clone $endTime;
$startTime->modify("-{$timeSpanHours} hours");

$allLines = [];
$allAnswers = [];
$filePrefix = '';
$fileHeader = '';

// ============================
// Apache
// ============================
if ($logType === 'apache') {
    $allLines = array_merge($allLines, generateNoise($noiseLines, $startTime, $endTime));
    if (in_array('lfi', $scenarios)) {
        $r = generateLfi($attackerCount, $difficulty, $startTime, $endTime);
        $allLines = array_merge($allLines, $r['lines']); $allAnswers['lfi'] = $r['answers'];
    }
    if (in_array('bruteforce', $scenarios)) {
        $r = generateBruteforce($attackerCount, $difficulty, $startTime, $endTime);
        $allLines = array_merge($allLines, $r['lines']); $allAnswers['bruteforce'] = $r['answers'];
    }
    if (in_array('webshell', $scenarios)) {
        $r = generateWebshell($attackerCount, $difficulty, $startTime, $endTime);
        $allLines = array_merge($allLines, $r['lines']); $allAnswers['webshell'] = $r['answers'];
    }
    $filePrefix = 'access';
}
// ============================
// Nginx
// ============================
elseif ($logType === 'nginx') {
    $allLines = array_merge($allLines, generateNginxNoise($noiseLines, $startTime, $endTime));
    if (in_array('lfi', $scenarios)) {
        $r = generateNginxLfi($attackerCount, $difficulty, $startTime, $endTime);
        $allLines = array_merge($allLines, $r['lines']); $allAnswers['lfi'] = $r['answers'];
    }
    if (in_array('bruteforce', $scenarios)) {
        $r = generateNginxBruteforce($attackerCount, $difficulty, $startTime, $endTime);
        $allLines = array_merge($allLines, $r['lines']); $allAnswers['bruteforce'] = $r['answers'];
    }
    if (in_array('webshell', $scenarios)) {
        $r = generateNginxWebshell($attackerCount, $difficulty, $startTime, $endTime);
        $allLines = array_merge($allLines, $r['lines']); $allAnswers['webshell'] = $r['answers'];
    }
    $filePrefix = 'nginx_access';
}
// ============================
// IIS
// ============================
elseif ($logType === 'iis') {
    $fileHeader = getIisHeader($startTime);
    $allLines = array_merge($allLines, generateIisNoise($noiseLines, $startTime, $endTime));
    if (in_array('lfi', $scenarios)) {
        $r = generateIisLfi($attackerCount, $difficulty, $startTime, $endTime);
        $allLines = array_merge($allLines, $r['lines']); $allAnswers['lfi'] = $r['answers'];
    }
    if (in_array('bruteforce', $scenarios)) {
        $r = generateIisBruteforce($attackerCount, $difficulty, $startTime, $endTime);
        $allLines = array_merge($allLines, $r['lines']); $allAnswers['bruteforce'] = $r['answers'];
    }
    if (in_array('webshell', $scenarios)) {
        $r = generateIisWebshell($attackerCount, $difficulty, $startTime, $endTime);
        $allLines = array_merge($allLines, $r['lines']); $allAnswers['webshell'] = $r['answers'];
    }
    $filePrefix = 'u_ex' . date('ymd');
}
// ============================
// SSH
// ============================
elseif ($logType === 'ssh') {
    $allLines = array_merge($allLines, generateSshNoise($noiseLines, $startTime, $endTime));
    if (in_array('ssh_bruteforce', $scenarios)) {
        $r = generateSshBruteforce($attackerCount, $difficulty, $startTime, $endTime);
        $allLines = array_merge($allLines, $r['lines']); $allAnswers['ssh_bruteforce'] = $r['answers'];
    }
    if (in_array('ssh_spray', $scenarios)) {
        $r = generateSshSpray($attackerCount, $difficulty, $startTime, $endTime);
        $allLines = array_merge($allLines, $r['lines']); $allAnswers['ssh_spray'] = $r['answers'];
    }
    $filePrefix = 'auth';
}
// ============================
// Windows Event Log
// ============================
elseif ($logType === 'windows') {
    $fileHeader = getWinEventHeader() . "\n";
    $allLines = array_merge($allLines, generateWinNoise($noiseLines, $startTime, $endTime));
    if (in_array('win_bruteforce', $scenarios)) {
        $r = generateWinBruteforce($attackerCount, $difficulty, $startTime, $endTime);
        $allLines = array_merge($allLines, $r['lines']); $allAnswers['win_bruteforce'] = $r['answers'];
    }
    if (in_array('win_postexploit', $scenarios)) {
        $r = generateWinPostExploit($attackerCount, $difficulty, $startTime, $endTime);
        $allLines = array_merge($allLines, $r['lines']); $allAnswers['win_postexploit'] = $r['answers'];
    }
    $filePrefix = 'Security';
}
// ============================
// Firewall
// ============================
elseif ($logType === 'firewall') {
    $allLines = array_merge($allLines, generateFwNoise($noiseLines, $startTime, $endTime));
    if (in_array('fw_portscan', $scenarios)) {
        $r = generateFwPortScan($attackerCount, $difficulty, $startTime, $endTime);
        $allLines = array_merge($allLines, $r['lines']); $allAnswers['fw_portscan'] = $r['answers'];
    }
    if (in_array('fw_beacon', $scenarios)) {
        $r = generateFwBeacon($attackerCount, $difficulty, $startTime, $endTime);
        $allLines = array_merge($allLines, $r['lines']); $allAnswers['fw_beacon'] = $r['answers'];
    }
    if (in_array('fw_exfil', $scenarios)) {
        $r = generateFwExfil($attackerCount, $difficulty, $startTime, $endTime);
        $allLines = array_merge($allLines, $r['lines']); $allAnswers['fw_exfil'] = $r['answers'];
    }
    $filePrefix = 'firewall';
}

// Sort chronologically
usort($allLines, fn($a, $b) => $a['timestamp'] <=> $b['timestamp']);

$logContent = $fileHeader . implode("\n", array_map(fn($l) => $l['line'], $allLines)) . "\n";
$totalLines = count($allLines);
$ext = ($logType === 'windows') ? '.csv' : '.log';

if ($outputMode === 'preview') {
    $logLines = explode("\n", trim($logContent));
    echo json_encode([
        'success' => true,
        'total_lines' => $totalLines,
        'preview_head' => array_slice($logLines, 0, 20),
        'preview_tail' => array_slice($logLines, -10),
        'answers' => $allAnswers,
    ]);
} else {
    $filename = $filePrefix . '_' . date('Ymd_His') . $ext;
    $tmpDir = __DIR__ . '/tmp';
    if (!is_dir($tmpDir)) mkdir($tmpDir, 0755, true);
    file_put_contents($tmpDir . '/' . $filename, $logContent);

    $answerFilename = str_replace($ext, '_answers.json', $filename);
    file_put_contents($tmpDir . '/' . $answerFilename, json_encode($allAnswers, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

    echo json_encode([
        'success' => true,
        'total_lines' => $totalLines,
        'download_url' => 'download.php?f=' . urlencode($filename),
        'answer_url' => 'download.php?f=' . urlencode($answerFilename),
        'answers' => $allAnswers,
    ]);
}

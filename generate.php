<?php
/**
 * Pulse Generator — Generate Endpoint
 * Accepts POST config, builds logs, returns as download or JSON
 */

header('Content-Type: application/json');

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/traffic.php';
require_once __DIR__ . '/includes/pages.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/cache.php';
require_once __DIR__ . '/includes/remote.php';

// Only POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

// Parse JSON body
$input = json_decode(file_get_contents('php://input'), true);
if (!$input) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid JSON']);
    exit;
}

// Extract config with defaults
$logType        = $input['log_type'] ?? 'apache';
$scenarios      = $input['scenarios'] ?? [];
$noiseLines     = intval($input['noise_lines'] ?? 500);
$difficulty     = $input['difficulty'] ?? 'medium';
$attackerCount  = intval($input['attacker_count'] ?? 1);
$timeSpanHours  = intval($input['time_span_hours'] ?? 6);
$outputMode     = $input['output_mode'] ?? 'download';

// Validate
$noiseLines = max(50, min(5000, $noiseLines));
$attackerCount = max(1, min(4, $attackerCount));
$timeSpanHours = max(1, min(48, $timeSpanHours));
$difficulty = in_array($difficulty, ['easy', 'medium', 'hard']) ? $difficulty : 'medium';
$logType = in_array($logType, ['apache', 'ssh']) ? $logType : 'apache';

// Time window
$endTime = new DateTime();
$startTime = clone $endTime;
$startTime->modify("-{$timeSpanHours} hours");

// Collect all log lines
$allLines = [];
$allAnswers = [];

// ============================================================
// Apache access.log generation
// ============================================================
if ($logType === 'apache') {
    $noiseResult = generateNoise($noiseLines, $startTime, $endTime);
    $allLines = array_merge($allLines, $noiseResult);

    if (in_array('lfi', $scenarios)) {
        $lfiResult = generateLfi($attackerCount, $difficulty, $startTime, $endTime);
        $allLines = array_merge($allLines, $lfiResult['lines']);
        $allAnswers['lfi'] = $lfiResult['answers'];
    }

    if (in_array('bruteforce', $scenarios)) {
        $bfResult = generateBruteforce($attackerCount, $difficulty, $startTime, $endTime);
        $allLines = array_merge($allLines, $bfResult['lines']);
        $allAnswers['bruteforce'] = $bfResult['answers'];
    }

    if (in_array('webshell', $scenarios)) {
        $wsResult = generateWebshell($attackerCount, $difficulty, $startTime, $endTime);
        $allLines = array_merge($allLines, $wsResult['lines']);
        $allAnswers['webshell'] = $wsResult['answers'];
    }

    $defaultFilename = 'access';
}

// ============================================================
// SSH auth.log generation
// ============================================================
elseif ($logType === 'ssh') {
    $noiseResult = generateSshNoise($noiseLines, $startTime, $endTime);
    $allLines = array_merge($allLines, $noiseResult);

    if (in_array('ssh_bruteforce', $scenarios)) {
        $sshBfResult = generateSshBruteforce($attackerCount, $difficulty, $startTime, $endTime);
        $allLines = array_merge($allLines, $sshBfResult['lines']);
        $allAnswers['ssh_bruteforce'] = $sshBfResult['answers'];
    }

    if (in_array('ssh_spray', $scenarios)) {
        $sprayResult = generateSshSpray($attackerCount, $difficulty, $startTime, $endTime);
        $allLines = array_merge($allLines, $sprayResult['lines']);
        $allAnswers['ssh_spray'] = $sprayResult['answers'];
    }

    $defaultFilename = 'auth';
}

// Sort all lines chronologically
usort($allLines, function($a, $b) {
    return $a['timestamp'] <=> $b['timestamp'];
});

// Build final log content
$logContent = implode("\n", array_map(fn($l) => $l['line'], $allLines)) . "\n";
$totalLines = count($allLines);

if ($outputMode === 'preview') {
    $logLines = explode("\n", trim($logContent));
    $previewHead = array_slice($logLines, 0, 20);
    $previewTail = array_slice($logLines, -10);
    echo json_encode([
        'success' => true,
        'total_lines' => $totalLines,
        'preview_head' => $previewHead,
        'preview_tail' => $previewTail,
        'answers' => $allAnswers,
    ]);
} else {
    $filename = $defaultFilename . '_' . date('Ymd_His') . '.log';
    $tmpDir = __DIR__ . '/tmp';
    if (!is_dir($tmpDir)) {
        mkdir($tmpDir, 0755, true);
    }
    $filepath = $tmpDir . '/' . $filename;
    file_put_contents($filepath, $logContent);

    $answerFile = $tmpDir . '/' . str_replace('.log', '_answers.json', $filename);
    file_put_contents($answerFile, json_encode($allAnswers, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

    echo json_encode([
        'success' => true,
        'total_lines' => $totalLines,
        'download_url' => 'download.php?f=' . urlencode($filename),
        'answer_url' => 'download.php?f=' . urlencode(basename($answerFile)),
        'answers' => $allAnswers,
    ]);
}

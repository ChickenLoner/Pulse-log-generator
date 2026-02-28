<?php
/**
 * Pulse Generator — File Download Handler
 */

$file = $_GET['f'] ?? '';

// Sanitize — only allow alphanumeric, underscore, dot, dash
if (!preg_match('/^[a-zA-Z0-9_\-\.]+$/', $file)) {
    http_response_code(400);
    echo 'Invalid filename';
    exit;
}

$filepath = __DIR__ . '/tmp/' . $file;

if (!file_exists($filepath)) {
    http_response_code(404);
    echo 'File not found';
    exit;
}

// Determine content type
$ext = pathinfo($file, PATHINFO_EXTENSION);
if ($ext === 'json') {
    header('Content-Type: application/json');
} else {
    header('Content-Type: text/plain');
}

header('Content-Disposition: attachment; filename="' . $file . '"');
header('Content-Length: ' . filesize($filepath));
readfile($filepath);

// Clean up old files (older than 1 hour)
$tmpDir = __DIR__ . '/tmp/';
foreach (glob($tmpDir . '*') as $tmpFile) {
    if (filemtime($tmpFile) < time() - 3600) {
        @unlink($tmpFile);
    }
}

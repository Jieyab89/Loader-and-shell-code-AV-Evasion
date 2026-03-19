<?php
/*
    Author Jieyab89
*/

/* ── CONFIGURATION ─────────────────────────────────────── */
define('VALID_TOKEN',    'CHANGE_ME_123');   /* Must match SERVER_TOKEN in Simple-logen-monitoring.c*/
define('UPLOAD_DIR',     __DIR__ . '/result');
define('MAX_FILE_MB',    15);               /* Max screenshot size in MB */
define('ALLOWED_MIME',   'image/png');
/* ─────────────────────────────────────────────────────── */

function respond(int $code, string $body): void
{
    $messages = [200 => 'OK', 400 => 'Bad Request',
                 403 => 'Forbidden', 413 => 'Payload Too Large',
                 415 => 'Unsupported Media Type', 500 => 'Internal Server Error'];
    $phrase = $messages[$code] ?? 'Unknown';

    http_response_code($code);
    header('Content-Type: text/plain');
    header('Content-Length: ' . strlen($body));
    header('Connection: close');
    echo $body;
    /* Flush output buffer so the client receives the response
       before PHP closes the connection */
    if (function_exists('fastcgi_finish_request')) {
        fastcgi_finish_request();
    } else {
        if (ob_get_level()) ob_end_flush();
        flush();
    }
    exit;
}

/* Only accept POST */
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respond(400, 'Only POST accepted');
}

/* Token check */
$token = isset($_POST['token']) ? trim($_POST['token']) : '';
if ($token !== VALID_TOKEN) {
    respond(403, 'Invalid token');
}

$pc_raw = isset($_POST['pc']) ? trim($_POST['pc']) : '';
if ($pc_raw === '') {
    respond(400, 'Bad Argument');
}
/* Sanitise: only allow alphanumeric, dash, underscore */
$pc = preg_replace('/[^A-Za-z0-9_\-]/', '_', $pc_raw);
if (strlen($pc) > 64) $pc = substr($pc, 0, 64);

if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
    $err = isset($_FILES['file']) ? $_FILES['file']['error'] : 'none';
    respond(400, 'File upload error: ' . $err);
}

/* Size check */
$max_bytes = MAX_FILE_MB * 1024 * 1024;
if ($_FILES['file']['size'] > $max_bytes) {
    respond(413, 'File too large');
}

/* MIME check — use fileinfo on the actual bytes, not the client header */
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime  = finfo_file($finfo, $_FILES['file']['tmp_name']);
finfo_close($finfo);

if ($mime !== ALLOWED_MIME) {
    respond(415, 'Access Denied ' . $mime);
}

/* ── SAVE FILE ──────────────────────────────────────────── */

/* Create per-PC subfolder */
$pc_dir = UPLOAD_DIR . DIRECTORY_SEPARATOR . $pc;
if (!is_dir($pc_dir)) {
    if (!mkdir($pc_dir, 0755, true)) {
        respond(500, 'Cannot create upload directory');
    }
}

/*
 * Filename: use the original name sent by exam_guard.c
 * (already formatted as HOSTNAME_YYYYMMDD_HHMM.png).
 * Strip any path components for safety.
 */
$original = basename($_FILES['file']['name']);
/* Strip non-safe characters */
$safe_name = preg_replace('/[^A-Za-z0-9_\-\.]/', '_', $original);
if (!preg_match('/\.png$/i', $safe_name)) {
    $safe_name .= '.png';
}

/* Avoid collisions: if file already exists, append microseconds */
$dest = $pc_dir . DIRECTORY_SEPARATOR . $safe_name;
if (file_exists($dest)) {
    $base  = pathinfo($safe_name, PATHINFO_FILENAME);
    $dest  = $pc_dir . DIRECTORY_SEPARATOR . $base . '_' . round(microtime(true) * 1000) . '.png';
}

if (!move_uploaded_file($_FILES['file']['tmp_name'], $dest)) {
    respond(500, 'Failed to save file');
}

$log = UPLOAD_DIR . '/upload.log';
$line = date('Y-m-d H:i:s') . "\t" . $pc . "\t" . basename($dest) . "\n";
@file_put_contents($log, $line, FILE_APPEND | LOCK_EX);

respond(200, 'OK');
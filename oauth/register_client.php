<?php
require_once __DIR__ . '/bootstrap.php';

header('X-Frame-Options: DENY');
header('Cache-Control: no-store');
session_start();
$db = rena_db();

if (empty($_SESSION['reg_csrf'])) $_SESSION['reg_csrf'] = bin2hex(random_bytes(16));
$uid = !empty($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : 0;

function owned_apps($db, $uid) {
    $stmt = $db->prepare('SELECT client_id, name, client_secret_hash IS NULL AS is_public, redirect_uris, created_at FROM oauth_clients WHERE owner_user_id = ? ORDER BY created_at DESC');
    $stmt->bind_param('i', $uid);
    $stmt->execute();
    $out = [];
    $res = $stmt->get_result();
    while ($r = $res->fetch_assoc()) {
        $out[] = [
            'client_id'     => $r['client_id'],
            'name'          => $r['name'],
            'type'          => $r['is_public'] ? 'public' : 'confidential',
            'redirect_uris' => json_decode($r['redirect_uris'], true) ?: [],
            'created_at'    => $r['created_at'],
        ];
    }
    $stmt->close();
    return $out;
}

function valid_redirect($u, $public) {
    if (!is_string($u) || $u === '' || strlen($u) > 500) return false;
    if (preg_match('/[\s\x00-\x1f]/', $u) || strpos($u, '#') !== false || strpos($u, '*') !== false) return false;
    $p = parse_url($u);
    if (!$p || empty($p['scheme'])) return false;
    $scheme = strtolower($p['scheme']);
    if ($scheme === 'https') return !empty($p['host']) && !isset($p['user']) && !isset($p['pass']);
    if ($scheme === 'http')  return in_array(strtolower($p['host'] ?? ''), ['localhost', '127.0.0.1'], true); 
    if (!$public) return false;                              
    if (in_array($scheme, ['javascript', 'data', 'file', 'vbscript', 'about', 'blob', 'ftp'], true)) return false;
    return (bool)preg_match('#^[a-z][a-z0-9+.\-]*://#i', $u);
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    if (!$uid) rena_json(['logged_in' => false]);
    $stmt = $db->prepare('SELECT username FROM users WHERE id = ?');
    $stmt->bind_param('i', $uid);
    $stmt->execute();
    $u = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    rena_json(['logged_in' => true, 'username' => $u['username'] ?? '', 'csrf' => $_SESSION['reg_csrf'], 'apps' => owned_apps($db, $uid)]);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') rena_json(['success' => false, 'error' => 'Metodo non supportato'], 405);
if (stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== 0) rena_json(['success' => false, 'error' => 'Content-Type deve essere application/json'], 415);
if (!$uid) rena_json(['success' => false, 'error' => 'Devi accedere con il tuo Rena ID'], 401);

$hdr = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
if (!hash_equals($_SESSION['reg_csrf'], (string)$hdr)) rena_json(['success' => false, 'error' => 'Sessione scaduta, ricarica la pagina'], 403);

$in = json_decode(file_get_contents('php://input'), true);
if (!is_array($in)) rena_json(['success' => false, 'error' => 'JSON non valido'], 400);
$action = $in['action'] ?? '';

if ($action === 'create') {
    $name   = trim((string)($in['name'] ?? ''));
    $public = (($in['type'] ?? '') === 'public');
    $uris   = $in['redirect_uris'] ?? [];

    if (mb_strlen($name) < 3 || mb_strlen($name) > 60) rena_json(['success' => false, 'error' => 'Il nome deve avere tra 3 e 60 caratteri'], 400);
    if (!is_array($uris) || count($uris) < 1 || count($uris) > 5) rena_json(['success' => false, 'error' => 'Inserisci da 1 a 5 URL di callback'], 400);
    $clean = [];
    foreach ($uris as $u) {
        $u = trim((string)$u);
        if (!valid_redirect($u, $public)) {
            rena_json(['success' => false, 'error' => 'URL di callback non valido: ' . mb_substr($u, 0, 80) . ' (usa https://, senza # né *)'], 400);
        }
        $clean[$u] = true;
    }
    $clean = array_keys($clean);

    $stmt = $db->prepare('SELECT COUNT(*) c FROM oauth_clients WHERE owner_user_id = ?');
    $stmt->bind_param('i', $uid);
    $stmt->execute();
    $count = (int)$stmt->get_result()->fetch_assoc()['c'];
    $stmt->close();
    if ($count >= 10) rena_json(['success' => false, 'error' => 'Hai raggiunto il limite di 10 app'], 400);

    $clientId = 'rena_' . bin2hex(random_bytes(10));
    $secret = null; $hash = null;
    if (!$public) { $secret = bin2hex(random_bytes(32)); $hash = hash('sha256', $secret); }
    $json = json_encode($clean, JSON_UNESCAPED_SLASHES);

    $stmt = $db->prepare('INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, owner_user_id) VALUES (?, ?, ?, ?, ?)');
    $stmt->bind_param('ssssi', $clientId, $hash, $name, $json, $uid);
    $stmt->execute();
    $stmt->close();

    rena_json(['success' => true, 'client_id' => $clientId, 'client_secret' => $secret, 'type' => $public ? 'public' : 'confidential']);
}

$clientId = (string)($in['client_id'] ?? '');
$stmt = $db->prepare('SELECT client_secret_hash FROM oauth_clients WHERE client_id = ? AND owner_user_id = ?');
$stmt->bind_param('si', $clientId, $uid);
$stmt->execute();
$row = $stmt->get_result()->fetch_assoc();
$stmt->close();
if (!$row) rena_json(['success' => false, 'error' => 'App non trovata'], 404);

if ($action === 'rotate') {
    if ($row['client_secret_hash'] === null) rena_json(['success' => false, 'error' => 'Le app pubbliche non hanno un secret'], 400);
    $secret = bin2hex(random_bytes(32));
    $hash = hash('sha256', $secret);
    $stmt = $db->prepare('UPDATE oauth_clients SET client_secret_hash = ? WHERE client_id = ? AND owner_user_id = ?');
    $stmt->bind_param('ssi', $hash, $clientId, $uid);
    $stmt->execute();
    $stmt->close();
    rena_json(['success' => true, 'client_id' => $clientId, 'client_secret' => $secret]);
}

if ($action === 'delete') {
    foreach (['oauth_tokens', 'oauth_codes'] as $t) {
        $stmt = $db->prepare("DELETE FROM $t WHERE client_id = ?");
        $stmt->bind_param('s', $clientId);
        $stmt->execute();
        $stmt->close();
    }
    $stmt = $db->prepare('DELETE FROM oauth_clients WHERE client_id = ? AND owner_user_id = ?');
    $stmt->bind_param('si', $clientId, $uid);
    $stmt->execute();
    $stmt->close();
    rena_json(['success' => true]);
}

rena_json(['success' => false, 'error' => 'Azione sconosciuta'], 400);

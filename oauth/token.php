<?php
require_once __DIR__ . '/bootstrap.php';

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Access-Control-Allow-Methods: POST, OPTIONS');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    rena_oauth_error('invalid_request', 'Usa POST', 405);
}
if (($_POST['grant_type'] ?? '') !== 'authorization_code') {
    rena_oauth_error('unsupported_grant_type', 'Supportato solo authorization_code');
}

$clientId = $_POST['client_id'] ?? '';
$secret   = $_POST['client_secret'] ?? '';
if (isset($_SERVER['PHP_AUTH_USER'])) {
    $clientId = $_SERVER['PHP_AUTH_USER'];
    $secret   = $_SERVER['PHP_AUTH_PW'] ?? '';
}

$client = rena_get_client($clientId);
if (!$client) rena_oauth_error('invalid_client', 'Client sconosciuto', 401);

$isPublic = empty($client['client_secret_hash']);
if (!$isPublic) {
    if ($secret === '' || !hash_equals($client['client_secret_hash'], hash('sha256', $secret))) {
        rena_oauth_error('invalid_client', 'Client secret errato', 401);
    }
}

$code        = (string)($_POST['code'] ?? '');
$redirectUri = (string)($_POST['redirect_uri'] ?? '');
$verifier    = (string)($_POST['code_verifier'] ?? '');
if (!preg_match('/^[a-f0-9]{64}$/', $code)) rena_oauth_error('invalid_grant', 'Codice non valido');

$db = rena_db();
$codeHash = rena_hash_token($code);

$stmt = $db->prepare('SELECT client_id, user_id, redirect_uri, code_challenge, used, (expires_at < NOW()) AS expired FROM oauth_codes WHERE code_hash = ?');
$stmt->bind_param('s', $codeHash);
$stmt->execute();
$row = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$row || (int)$row['used'] === 1 || (int)$row['expired'] === 1
    || !hash_equals($row['client_id'], $client['client_id'])
    || !hash_equals($row['redirect_uri'], $redirectUri)) {
    rena_oauth_error('invalid_grant', 'Codice scaduto, già usato o non valido');
}

if (!empty($row['code_challenge'])) {
    if ($verifier === '' || !hash_equals($row['code_challenge'], rena_b64url(hash('sha256', $verifier, true)))) {
        rena_oauth_error('invalid_grant', 'PKCE non valido');
    }
}

$stmt = $db->prepare('UPDATE oauth_codes SET used = 1 WHERE code_hash = ? AND used = 0');
$stmt->bind_param('s', $codeHash);
$stmt->execute();
$claimed = $stmt->affected_rows === 1;
$stmt->close();
if (!$claimed) rena_oauth_error('invalid_grant', 'Codice già usato');

$token = bin2hex(random_bytes(32));
$tokenHash = rena_hash_token($token);
$uid = (int)$row['user_id'];
$scope = 'profile';
$stmt = $db->prepare('INSERT INTO oauth_tokens (token_hash, client_id, user_id, scope, expires_at) VALUES (?, ?, ?, ?, NOW() + INTERVAL 1 HOUR)');
$stmt->bind_param('ssis', $tokenHash, $client['client_id'], $uid, $scope);
$stmt->execute();
$stmt->close();

rena_gc();

rena_json(['access_token' => $token, 'token_type' => 'Bearer', 'expires_in' => 3600, 'scope' => $scope]);

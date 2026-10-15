<?php
require_once __DIR__ . '/bootstrap.php';

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Authorization, Content-Type');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

$auth = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
if ($auth === '' && function_exists('getallheaders')) {
    foreach (getallheaders() as $k => $v) {
        if (strtolower($k) === 'authorization') { $auth = $v; break; }
    }
}
$token = '';
if (stripos($auth, 'Bearer ') === 0) $token = trim(substr($auth, 7));
if ($token === '' && !empty($_POST['access_token'])) $token = (string)$_POST['access_token']; 

if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
    header('WWW-Authenticate: Bearer error="invalid_token"');
    rena_oauth_error('invalid_token', 'Token mancante o non valido', 401);
}

$hash = rena_hash_token($token);
$stmt = rena_db()->prepare('SELECT u.id, u.username, u.profile_photo
                            FROM oauth_tokens t JOIN users u ON u.id = t.user_id
                            WHERE t.token_hash = ? AND t.expires_at > NOW()');
$stmt->bind_param('s', $hash);
$stmt->execute();
$u = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$u) {
    header('WWW-Authenticate: Bearer error="invalid_token"');
    rena_oauth_error('invalid_token', 'Token scaduto o non valido', 401);
}

rena_json([
    'sub'           => (string)$u['id'],
    'username'      => $u['username'],
    'profile_photo' => rena_photo_url($u['id'], $u['profile_photo']),
]);

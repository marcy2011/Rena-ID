<?php
require_once __DIR__ . '/rena-session.php';
rena_session_start();
require_once __DIR__ . '/config_id.php';
require_once __DIR__ . '/rena-security.php';
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

function qr_reply(array $data, int $status = 200): void { http_response_code($status); echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); exit; }
$db = db();
rena_security_schema($db);
$input = json_decode(file_get_contents('php://input'), true);
if (!is_array($input)) qr_reply(['success' => false, 'error' => 'Richiesta non valida'], 400);
$action = (string)($input['action'] ?? '');

if ($action === 'create') {
    $token = bin2hex(random_bytes(32)); $hash = hash('sha256', $token);
    $deviceName = rena_device_name(); $agent = substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 500); $ip = substr((string)($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45);
    $rate = $db->prepare('SELECT COUNT(*) AS attempts FROM rena_qr_logins WHERE ip_address = ? AND created_at > NOW() - INTERVAL 10 MINUTE');
    $rate->bind_param('s', $ip); $rate->execute(); $attempts = (int)$rate->get_result()->fetch_assoc()['attempts']; $rate->close();
    if ($attempts >= 10) qr_reply(['success' => false, 'error' => 'Hai richiesto troppi QR. Attendi qualche minuto e riprova.'], 429);
    $expires = date('Y-m-d H:i:s', time() + 180);
    $db->query("DELETE FROM rena_qr_logins WHERE created_at < NOW() - INTERVAL 1 DAY");
    $external = (string)($input['external_domain'] ?? ''); $parsedExternal = parse_url($external); $externalHost = strtolower((string)($parsedExternal['host'] ?? ''));
    $allowedHosts = ['renadeveloper.altervista.org', 'renastore.altervista.org', 'renaarcade.altervista.org', 'renaai.altervista.org', 'renasupporto.altervista.org'];
    $externalOrigin = ($parsedExternal['scheme'] ?? '') === 'https' && in_array($externalHost, $allowedHosts, true) ? 'https://' . $externalHost : null;
    $stmt = $db->prepare('INSERT INTO rena_qr_logins (token_hash, device_name, user_agent, ip_address, external_origin, expires_at) VALUES (?, ?, ?, ?, ?, ?)');
    $stmt->bind_param('ssssss', $hash, $deviceName, $agent, $ip, $externalOrigin, $expires); $stmt->execute(); $stmt->close();
    $_SESSION['qr_login_token_hash'] = $hash;
    qr_reply(['success' => true, 'token' => $token, 'expires_in' => 180]);
}

$token = (string)($input['token'] ?? '');
if (!preg_match('/^[a-f0-9]{64}$/', $token)) qr_reply(['success' => false, 'error' => 'Richiesta QR non valida'], 400);
$hash = hash('sha256', $token);

if ($action === 'poll') {
    if (!hash_equals((string)($_SESSION['qr_login_token_hash'] ?? ''), $hash)) qr_reply(['success' => false, 'error' => 'Sessione QR scaduta'], 403);
    $stmt = $db->prepare("SELECT status, user_id, external_origin FROM rena_qr_logins WHERE token_hash = ? AND expires_at > NOW()");
    $stmt->bind_param('s', $hash); $stmt->execute(); $row = $stmt->get_result()->fetch_assoc(); $stmt->close();
    if (!$row) { unset($_SESSION['qr_login_token_hash']); qr_reply(['success' => false, 'expired' => true, 'error' => 'QR scaduto. Generane uno nuovo.'], 410); }
    if ($row['status'] !== 'approved') qr_reply(['success' => true, 'status' => 'pending']);
    $stmt = $db->prepare("UPDATE rena_qr_logins SET status = 'consumed' WHERE token_hash = ? AND status = 'approved' AND expires_at > NOW()");
    $stmt->bind_param('s', $hash); $stmt->execute(); $consumed = $stmt->affected_rows === 1; $stmt->close();
    if (!$consumed) qr_reply(['success' => false, 'error' => 'Richiesta già utilizzata o scaduta'], 409);
    $uid = (int)$row['user_id'];
    $stmt = $db->prepare('SELECT username, preferred_language FROM users WHERE id = ?'); $stmt->bind_param('i', $uid); $stmt->execute(); $user = $stmt->get_result()->fetch_assoc(); $stmt->close();
    if (!$user) qr_reply(['success' => false, 'error' => 'Account non trovato'], 404);
    session_regenerate_id(true);
    $_SESSION['user_id'] = $uid; $_SESSION['username'] = $user['username']; unset($_SESSION['qr_login_token_hash']);
    rena_apply_session_persistence($db, $uid);
    $_SESSION['device_id'] = rena_device_id($db, $uid, true);
    $whitelist = include __DIR__ . '/redirect_whitelist.php';
    $redirect = $_SESSION['redirect_after_login'] ?? 'account.php';
    if (!isAllowedRedirect($redirect, $whitelist)) $redirect = 'account.php';
    unset($_SESSION['redirect_after_login']);
    $externalDomain = (string)($row['external_origin'] ?? '');
    if ($externalDomain !== '') {
        $externalHost = strtolower((string)parse_url($externalDomain, PHP_URL_HOST));
        $allowedHosts = ['renadeveloper.altervista.org', 'renastore.altervista.org', 'renaarcade.altervista.org', 'renaai.altervista.org', 'renasupporto.altervista.org'];
        if (in_array($externalHost, $allowedHosts, true)) {
            $serviceToken = bin2hex(random_bytes(32)); $serviceHash = hash('sha256', $serviceToken); $serviceExpiry = date('Y-m-d H:i:s', time() + 86400 * 30); $device = (string)($_SESSION['device_id'] ?? '');
            $stmt = $db->prepare('INSERT INTO rena_service_sessions (token_hash, user_id, service_host, device_id, expires_at) VALUES (?, ?, ?, ?, ?)');
            $stmt->bind_param('sisss', $serviceHash, $uid, $externalHost, $device, $serviceExpiry); $stmt->execute(); $stmt->close();
            $language = in_array(($user['preferred_language'] ?? 'it'), ['it', 'en'], true) ? $user['preferred_language'] : 'it';
            qr_reply(['success' => true, 'status' => 'approved', 'external_data' => ['status' => 'success', 'user_id' => $uid, 'username' => $user['username'], 'preferred_language' => $language, 'token' => $serviceToken], 'external_origin' => $externalDomain]);
        }
    }
    qr_reply(['success' => true, 'status' => 'approved', 'redirect' => forceHttps($redirect)]);
}

if ($action === 'approve_info' || $action === 'approve') {
    $uid = (int)($_SESSION['user_id'] ?? 0);
    if (!$uid) qr_reply(['success' => false, 'error' => 'Accedi a Rena ID sul telefono per approvare questa richiesta'], 401);
    if (empty($_SESSION['qr_approve_csrf'])) $_SESSION['qr_approve_csrf'] = bin2hex(random_bytes(32));
    $stmt = $db->prepare("SELECT device_name, ip_address FROM rena_qr_logins WHERE token_hash = ? AND status = 'pending' AND expires_at > NOW()");
    $stmt->bind_param('s', $hash); $stmt->execute(); $request = $stmt->get_result()->fetch_assoc(); $stmt->close();
    if (!$request) qr_reply(['success' => false, 'expired' => true, 'error' => 'QR scaduto o già utilizzato'], 410);
    if ($action === 'approve_info') {
        qr_reply(['success' => true, 'device_name' => $request['device_name'], 'ip_address' => $request['ip_address'], 'csrf' => $_SESSION['qr_approve_csrf']]);
    }
    if (!hash_equals($_SESSION['qr_approve_csrf'], (string)($input['csrf'] ?? ''))) qr_reply(['success' => false, 'error' => 'Sessione scaduta, ricarica la pagina'], 403);
    $stmt = $db->prepare("UPDATE rena_qr_logins SET user_id = ?, status = 'approved' WHERE token_hash = ? AND status = 'pending' AND expires_at > NOW()");
    $stmt->bind_param('is', $uid, $hash); $stmt->execute(); $approved = $stmt->affected_rows === 1; $stmt->close();
    if (!$approved) qr_reply(['success' => false, 'error' => 'Richiesta scaduta o già approvata'], 409);
    qr_reply(['success' => true]);
}

qr_reply(['success' => false, 'error' => 'Azione non valida'], 400);

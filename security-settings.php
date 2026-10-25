<?php
require_once __DIR__ . '/rena-session.php';
rena_session_start();
require_once __DIR__ . '/config_id.php';
require_once __DIR__ . '/rena-security.php';
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
function security_reply(array $data, int $status = 200): void { http_response_code($status); echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); exit; }
$uid = (int)($_SESSION['user_id'] ?? 0);
if (!$uid) security_reply(['success' => false, 'error' => 'Sessione scaduta'], 401);
$db = db();
rena_security_schema($db);
if (empty($_SESSION['security_csrf'])) $_SESSION['security_csrf'] = bin2hex(random_bytes(32));
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $stmt = $db->prepare('SELECT two_factor_enabled, two_factor_email_enabled, email FROM users WHERE id = ?');
    $stmt->bind_param('i', $uid); $stmt->execute(); $row = $stmt->get_result()->fetch_assoc(); $stmt->close();
    security_reply(['success' => true, 'enabled' => (bool)($row['two_factor_enabled'] ?? false), 'email_enabled' => (bool)($row['two_factor_email_enabled'] ?? false), 'email' => (string)($row['email'] ?? ''), 'csrf' => $_SESSION['security_csrf']]);
}
if ($_SERVER['REQUEST_METHOD'] !== 'POST') security_reply(['success' => false, 'error' => 'Metodo non supportato'], 405);
$input = json_decode(file_get_contents('php://input'), true);
if (!is_array($input) || !hash_equals($_SESSION['security_csrf'], (string)($input['csrf'] ?? ''))) security_reply(['success' => false, 'error' => 'Sessione scaduta, ricarica la pagina'], 403);
$action = (string)($input['action'] ?? '');
if ($action === 'setup') {
    $stmt = $db->prepare('SELECT password, two_factor_enabled FROM users WHERE id = ?');
    $stmt->bind_param('i', $uid); $stmt->execute(); $row = $stmt->get_result()->fetch_assoc(); $stmt->close();
    if (!$row || !password_verify((string)($input['password'] ?? ''), $row['password'])) security_reply(['success' => false, 'error' => 'Password non corretta'], 403);
    if ($row['two_factor_enabled']) security_reply(['success' => false, 'error' => 'La verifica in due passaggi è già attiva'], 400);
    if (empty($_SESSION['pending_totp_secret'])) $_SESSION['pending_totp_secret'] = rena_base32_encode(random_bytes(20));
    $issuer = rawurlencode('Rena ID');
    $account = rawurlencode((string)($_SESSION['username'] ?? 'account'));
    security_reply(['success' => true, 'secret' => $_SESSION['pending_totp_secret'], 'otpauth' => "otpauth://totp/$issuer:$account?secret={$_SESSION['pending_totp_secret']}&issuer=$issuer"]);
}
if ($action === 'enable') {
    $secret = (string)($_SESSION['pending_totp_secret'] ?? '');
    if ($secret === '' || !rena_totp_valid($secret, (string)($input['code'] ?? ''))) security_reply(['success' => false, 'error' => 'Codice non valido'], 400);
    $stmt = $db->prepare('UPDATE users SET two_factor_enabled = 1, two_factor_secret = ? WHERE id = ?');
    $stmt->bind_param('si', $secret, $uid); $stmt->execute(); $stmt->close();
    unset($_SESSION['pending_totp_secret']);
    security_reply(['success' => true]);
}
if ($action === 'disable') {
    $stmt = $db->prepare('SELECT password, two_factor_secret, two_factor_enabled FROM users WHERE id = ?');
    $stmt->bind_param('i', $uid); $stmt->execute(); $row = $stmt->get_result()->fetch_assoc(); $stmt->close();
    if (!$row || !password_verify((string)($input['password'] ?? ''), $row['password']) || !rena_totp_valid((string)$row['two_factor_secret'], (string)($input['code'] ?? ''))) security_reply(['success' => false, 'error' => 'Password o codice non corretti'], 403);
    $stmt = $db->prepare('UPDATE users SET two_factor_enabled = 0, two_factor_secret = NULL WHERE id = ?');
    $stmt->bind_param('i', $uid); $stmt->execute(); $stmt->close();
    security_reply(['success' => true]);
}
if ($action === 'enable_email') {
    $stmt = $db->prepare('SELECT password, email, two_factor_email_enabled FROM users WHERE id = ?');
    $stmt->bind_param('i', $uid); $stmt->execute(); $row = $stmt->get_result()->fetch_assoc(); $stmt->close();
    if (!$row || !password_verify((string)($input['password'] ?? ''), $row['password'])) security_reply(['success' => false, 'error' => 'Password non corretta'], 403);
    if (!filter_var($row['email'] ?? '', FILTER_VALIDATE_EMAIL)) security_reply(['success' => false, 'error' => 'Aggiungi prima un indirizzo email valido al profilo'], 400);
    if ($row['two_factor_email_enabled']) security_reply(['success' => false, 'error' => 'La verifica email è già attiva'], 400);
    $lastSent = (int)($_SESSION['email_factor_sent_at'] ?? 0);
    if ($lastSent && time() - $lastSent < 60) security_reply(['success' => false, 'error' => 'Attendi un minuto prima di richiedere un altro codice'], 429);
    $code = (string)random_int(100000, 999999);
    $safeUsername = htmlspecialchars((string)($_SESSION['username'] ?? 'utente Rena ID'), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $body = "<!doctype html><html lang='it'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Attiva la verifica email</title></head>"
        . "<body style='margin:0;padding:0;background:#000;color:#fff;font-family:Inter,-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif'><div style='max-width:600px;margin:0 auto;padding:40px 20px'><div style='background:#111;border-radius:24px;padding:40px 28px;border:1px solid #292929;text-align:center'>"
        . "<div style='width:56px;height:56px;line-height:56px;margin:0 auto 24px;border-radius:50%;background:#242424;color:#fff;font-size:26px'>R</div><h1 style='font-size:24px;font-weight:600;margin:0 0 18px;color:#fff'>Verifica in due passaggi</h1>"
        . "<p style='font-size:16px;color:#d1d5db;line-height:1.6;margin:0 0 24px'>Ciao $safeUsername, inserisci questo codice per attivare la verifica email su Rena ID.</p>"
        . "<div style='background:linear-gradient(135deg,#3b3b3b,#222);border-radius:16px;padding:26px 18px;margin:24px 0;border:1px solid #3a3a3a'><p style='font-size:14px;color:#d1d5db;margin:0 0 12px'>Il tuo codice di verifica</p><div style='font-size:32px;font-weight:700;color:#fff;letter-spacing:8px;font-family:monospace;white-space:nowrap'>$code</div><p style='font-size:12px;color:#c4c4c4;margin:14px 0 0'>Valido per 10 minuti</p></div>"
        . "<div style='background:#10231b;border-radius:12px;padding:16px;margin:20px 0;border:1px solid #214a37'><p style='font-size:14px;color:#7ee0a8;line-height:1.5;margin:0'>Se non hai richiesto tu questa operazione, ignora questa email e non condividere il codice.</p></div><div style='margin-top:32px;padding-top:20px;border-top:1px solid #292929'><p style='font-size:14px;color:#d1d5db;margin:0 0 8px'>Il Team Rena</p></div></div></div></body></html>";
    $headers = "From: Rena ID <rena@altervista.org>\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n";
    if (!@mail($row['email'], 'Attiva la verifica email Rena ID', $body, $headers)) security_reply(['success' => false, 'error' => 'Non è stato possibile inviare l’email. Riprova più tardi.'], 500);
    $_SESSION['email_factor_challenge'] = ['hash' => password_hash($code, PASSWORD_DEFAULT), 'expires_at' => time() + 600, 'attempts' => 0];
    $_SESSION['email_factor_sent_at'] = time();
    security_reply(['success' => true, 'message' => 'Codice di conferma inviato al tuo indirizzo email']);
}
if ($action === 'confirm_email') {
    $challenge = $_SESSION['email_factor_challenge'] ?? null;
    if (!is_array($challenge) || (int)($challenge['expires_at'] ?? 0) < time() || (int)($challenge['attempts'] ?? 0) >= 5) security_reply(['success' => false, 'error' => 'Codice scaduto o troppi tentativi. Richiedi un nuovo codice.'], 400);
    if (!password_verify(preg_replace('/\D/', '', (string)($input['code'] ?? '')), (string)$challenge['hash'])) {
        $_SESSION['email_factor_challenge']['attempts'] = (int)$challenge['attempts'] + 1;
        security_reply(['success' => false, 'error' => 'Codice non valido'], 400);
    }
    $stmt = $db->prepare('UPDATE users SET two_factor_email_enabled = 1 WHERE id = ?');
    $stmt->bind_param('i', $uid); $stmt->execute(); $stmt->close();
    unset($_SESSION['email_factor_challenge'], $_SESSION['email_factor_sent_at']);
    security_reply(['success' => true]);
}
if ($action === 'disable_email') {
    $stmt = $db->prepare('SELECT password FROM users WHERE id = ?');
    $stmt->bind_param('i', $uid); $stmt->execute(); $row = $stmt->get_result()->fetch_assoc(); $stmt->close();
    if (!$row || !password_verify((string)($input['password'] ?? ''), $row['password'])) security_reply(['success' => false, 'error' => 'Password non corretta'], 403);
    $stmt = $db->prepare('UPDATE users SET two_factor_email_enabled = 0 WHERE id = ?');
    $stmt->bind_param('i', $uid); $stmt->execute(); $stmt->close();
    security_reply(['success' => true]);
}
security_reply(['success' => false, 'error' => 'Azione sconosciuta'], 400);

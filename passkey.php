<?php
if (($_GET['embed'] ?? '') === '1') {
    session_name('RENA_OAUTH_EMBED');
    session_set_cookie_params(['lifetime' => 0, 'path' => '/oauth/', 'secure' => true, 'httponly' => true, 'samesite' => 'None']);
    ini_set('session.use_strict_mode', '1');
}
require_once __DIR__ . '/rena-session.php';
rena_session_start();
function passkey_embed_cookie(): void {
    if (($_GET['embed'] ?? '') === '1') {
        header_remove('Set-Cookie');
        header('Set-Cookie: ' . session_name() . '=' . session_id() . '; Path=/oauth/; Secure; HttpOnly; SameSite=None; Partitioned', false);
    }
}
passkey_embed_cookie();
require_once __DIR__ . '/config_id.php';
require_once __DIR__ . '/rena-security.php';
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

function passkey_reply(array $data, int $status = 200): void { http_response_code($status); echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); exit; }
function pk_b64e(string $data): string { return rtrim(strtr(base64_encode($data), '+/', '-_'), '='); }
function pk_b64d(string $data) { return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', (4 - strlen($data) % 4) % 4), true); }
function pk_cbor(string $data, int &$offset = 0) {
    $first = ord($data[$offset++]); $major = $first >> 5; $add = $first & 31;
    if ($add < 24) $length = $add;
    elseif ($add === 24) $length = ord($data[$offset++]);
    elseif ($add === 25) { $length = unpack('n', substr($data, $offset, 2))[1]; $offset += 2; }
    elseif ($add === 26) { $length = unpack('N', substr($data, $offset, 4))[1]; $offset += 4; }
    elseif ($add === 27) { $parts = unpack('N2', substr($data, $offset, 8)); $length = $parts[1] * 4294967296 + $parts[2]; $offset += 8; }
    elseif ($add === 31) return null;
    else throw new RuntimeException('CBOR non valido');
    if ($major === 0) return $length;
    if ($major === 1) return -1 - $length;
    if ($major === 2 || $major === 3) { $value = substr($data, $offset, (int)$length); $offset += (int)$length; return $value; }
    if ($major === 4) { $out = []; for ($i = 0; $i < $length; $i++) $out[] = pk_cbor($data, $offset); return $out; }
    if ($major === 5) { $out = []; for ($i = 0; $i < $length; $i++) { $key = pk_cbor($data, $offset); $out[$key] = pk_cbor($data, $offset); } return $out; }
    if ($major === 6) return pk_cbor($data, $offset);
    if ($major === 7) { if ($add === 20) return false; if ($add === 21) return true; return null; }
    throw new RuntimeException('CBOR non valido');
}
function pk_der_len(int $length): string { return $length < 128 ? chr($length) : chr(0x80 | strlen(ltrim(pack('N', $length), "\0"))) . ltrim(pack('N', $length), "\0"); }
function pk_der(int $tag, string $data): string { return chr($tag) . pk_der_len(strlen($data)) . $data; }
function pk_der_int(string $bytes): string { $bytes = ltrim($bytes, "\0"); if ($bytes === '') $bytes = "\0"; if ((ord($bytes[0]) & 0x80) !== 0) $bytes = "\0" . $bytes; return pk_der(0x02, $bytes); }
function pk_public_pem(array $cose): string
{
    if (($cose[1] ?? null) === 2 && ($cose[3] ?? null) === -7 && ($cose[-1] ?? null) === 1 && strlen($cose[-2] ?? '') === 32 && strlen($cose[-3] ?? '') === 32) {
        $algorithm = hex2bin('301306072a8648ce3d020106082a8648ce3d030107');
        $point = "\x04" . $cose[-2] . $cose[-3];
        $der = pk_der(0x30, $algorithm . pk_der(0x03, "\0" . $point));
    } elseif (($cose[1] ?? null) === 3 && ($cose[3] ?? null) === -257 && !empty($cose[-1]) && !empty($cose[-2])) {
        $rsa = pk_der(0x30, pk_der_int($cose[-1]) . pk_der_int($cose[-2]));
        $algorithm = hex2bin('300d06092a864886f70d0101010500');
        $der = pk_der(0x30, $algorithm . pk_der(0x03, "\0" . $rsa));
    } else throw new RuntimeException('Algoritmo passkey non supportato');
    return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
}
function pk_client_data(string $json, string $expectedType, string $challenge): array
{
    $data = json_decode($json, true);
    $origin = 'https://' . strtolower((string)($_SERVER['HTTP_HOST'] ?? ''));
    $expectedOrigin = 'https://' . strtolower((string)parse_url($GLOBALS['BASE_URL'] ?? 'https://rena.altervista.org', PHP_URL_HOST));
    if (!is_array($data) || ($data['type'] ?? '') !== $expectedType || !hash_equals($challenge, (string)($data['challenge'] ?? '')) || !hash_equals($expectedOrigin, (string)($data['origin'] ?? '')) || !hash_equals($expectedOrigin, $origin)) throw new RuntimeException('Origine o challenge non validi');
    return $data;
}
function pk_user_id_from_handle(string $handle): int
{
    if (strlen($handle) !== 4) return 0;
    return (int)unpack('N', $handle)[1];
}

$db = db();
rena_security_schema($db);
$input = json_decode(file_get_contents('php://input'), true);
if (!is_array($input)) passkey_reply(['success' => false, 'error' => 'Richiesta non valida'], 400);
$action = (string)($input['action'] ?? '');
$uid = (int)($_SESSION['user_id'] ?? 0);
$rpId = strtolower((string)parse_url($BASE_URL, PHP_URL_HOST));

if ($action === 'list') {
    if (!$uid) passkey_reply(['success' => false, 'error' => 'Sessione scaduta'], 401);
    if (empty($_SESSION['passkey_csrf'])) $_SESSION['passkey_csrf'] = bin2hex(random_bytes(32));
    $stmt = $db->prepare('SELECT credential_id, device_name, created_at, last_used FROM rena_passkeys WHERE user_id = ? ORDER BY created_at DESC');
    $stmt->bind_param('i', $uid); $stmt->execute(); $result = $stmt->get_result(); $items = [];
    while ($row = $result->fetch_assoc()) $items[] = $row;
    $stmt->close(); passkey_reply(['success' => true, 'passkeys' => $items, 'csrf' => $_SESSION['passkey_csrf']]);
}

if ($action === 'password_factor_options') {
    $allowCredentials = [];
    if ($action === 'password_factor_options') {
        $pending = $_SESSION['pending_password_login'] ?? null;
        if (!is_array($pending) || (int)($pending['expires_at'] ?? 0) < time()) passkey_reply(['success' => false, 'error' => 'La verifica è scaduta. Inserisci di nuovo la password.'], 401);
        $pendingUid = (int)$pending['user_id'];
        $stmt = $db->prepare('SELECT credential_id FROM rena_passkeys WHERE user_id = ?'); $stmt->bind_param('i', $pendingUid); $stmt->execute(); $result = $stmt->get_result();
        while ($row = $result->fetch_assoc()) $allowCredentials[] = ['type' => 'public-key', 'id' => $row['credential_id']]; $stmt->close();
        if (!$allowCredentials) passkey_reply(['success' => false, 'error' => 'Non hai passkey attive per questo account'], 400);
        $_SESSION['passkey_login_user_id'] = $pendingUid;
    }
    $_SESSION['passkey_login_challenge'] = bin2hex(random_bytes(32));
    $_SESSION['passkey_login_expires'] = time() + 300;
    $returnTo = (string)($input['return_to'] ?? '');
    if ($returnTo !== '' && preg_match('#^/oauth/authorize\.php(?:\?.*)?$#', $returnTo)) $_SESSION['passkey_redirect'] = $returnTo;
    else unset($_SESSION['passkey_redirect']);
    $external = (string)($input['external_domain'] ?? '');
    $externalHost = strtolower((string)parse_url($external, PHP_URL_HOST));
    if (($parsedExternal = parse_url($external)) && ($parsedExternal['scheme'] ?? '') === 'https' && in_array($externalHost, ['renadeveloper.altervista.org', 'renastore.altervista.org', 'renaarcade.altervista.org', 'renaai.altervista.org', 'renasupporto.altervista.org'], true)) $_SESSION['passkey_external_domain'] = 'https://' . $externalHost;
    else unset($_SESSION['passkey_external_domain']);
    $options = ['challenge' => pk_b64e(hex2bin($_SESSION['passkey_login_challenge'])), 'rpId' => $rpId, 'timeout' => 300000, 'userVerification' => 'required'];
    if ($allowCredentials) $options['allowCredentials'] = $allowCredentials;
    passkey_reply(['success' => true, 'options' => $options]);
}

if ($action === 'login_verify') {
    try {
        $challenge = (string)($_SESSION['passkey_login_challenge'] ?? '');
        if ($challenge === '' || (int)($_SESSION['passkey_login_expires'] ?? 0) < time()) throw new RuntimeException('La richiesta è scaduta. Riprova.');
        $rawId = pk_b64d((string)($input['rawId'] ?? ''));
        $clientData = pk_b64d((string)($input['response']['clientDataJSON'] ?? ''));
        $authData = pk_b64d((string)($input['response']['authenticatorData'] ?? ''));
        $signature = pk_b64d((string)($input['response']['signature'] ?? ''));
        $userHandle = pk_b64d((string)($input['response']['userHandle'] ?? ''));
        if ($rawId === false || $clientData === false || $authData === false || $signature === false || $userHandle === false || !hash_equals((string)($input['id'] ?? ''), pk_b64e($rawId))) throw new RuntimeException('Credenziale non valida');
        pk_client_data($clientData, 'webauthn.get', pk_b64e(hex2bin($challenge)));
        $stmt = $db->prepare('SELECT p.user_id, p.public_key, p.sign_count, u.username FROM rena_passkeys p JOIN users u ON u.id = p.user_id WHERE p.credential_id = ?');
        $credentialId = pk_b64e($rawId); $stmt->bind_param('s', $credentialId); $stmt->execute(); $credential = $stmt->get_result()->fetch_assoc(); $stmt->close();
        $pendingPassword = $_SESSION['pending_password_login'] ?? null;
        $requiredUser = (int)($_SESSION['passkey_login_user_id'] ?? 0);
        $handleUserId = $userHandle !== '' ? pk_user_id_from_handle($userHandle) : 0;
        if (!$credential) throw new RuntimeException('Questa passkey non risulta registrata su Rena ID');
        if ($userHandle !== '' && $handleUserId !== (int)$credential['user_id']) throw new RuntimeException('La passkey ha restituito un account diverso');
        if ($userHandle === '' && $requiredUser === 0) throw new RuntimeException('La passkey non ha restituito l’account associato');
        if ($requiredUser > 0 && (int)$credential['user_id'] !== $requiredUser) throw new RuntimeException('Questa passkey appartiene a un altro account');
        if ($requiredUser > 0 && (!is_array($pendingPassword) || (int)($pendingPassword['expires_at'] ?? 0) < time())) throw new RuntimeException('La verifica con password è scaduta; ripeti l’accesso');
        if (strlen($authData) < 37) throw new RuntimeException('La risposta della passkey è incompleta');
        if (!hash_equals(hash('sha256', $rpId, true), substr($authData, 0, 32))) throw new RuntimeException('Questa passkey è registrata per un dominio Rena diverso');
        $flags = ord($authData[32]);
        if (($flags & 0x01) === 0 || ($flags & 0x04) === 0) throw new RuntimeException('Conferma biometrica o PIN non completata');
        $counter = unpack('N', substr($authData, 33, 4))[1];
        $signed = $authData . hash('sha256', $clientData, true);
        $verified = openssl_verify($signed, $signature, $credential['public_key'], OPENSSL_ALGO_SHA256);
        if ($verified !== 1 || ($counter > 0 && (int)$credential['sign_count'] > 0 && $counter <= (int)$credential['sign_count'])) throw new RuntimeException('Verifica passkey non riuscita');
        $uid = (int)$credential['user_id'];
        $languageStmt = $db->prepare('SELECT preferred_language FROM users WHERE id = ?'); $languageStmt->bind_param('i', $uid); $languageStmt->execute(); $preferredLanguage = (string)($languageStmt->get_result()->fetch_assoc()['preferred_language'] ?? 'it'); $languageStmt->close();
        if (!in_array($preferredLanguage, ['it', 'en'], true)) $preferredLanguage = 'it';
        $stmt = $db->prepare('UPDATE rena_passkeys SET sign_count = ?, last_used = NOW() WHERE credential_id = ?');
        $stmt->bind_param('is', $counter, $credentialId); $stmt->execute(); $stmt->close();
        if (($_GET['embed'] ?? '') !== '1') {
            session_regenerate_id(true);
            passkey_embed_cookie();
        }
        $_SESSION['user_id'] = $uid; $_SESSION['username'] = $credential['username'];
        if (($_GET['embed'] ?? '') !== '1') rena_apply_session_persistence($db, $uid);
        $_SESSION['device_id'] = rena_device_id($db, $uid, true);
        unset($_SESSION['passkey_login_challenge'], $_SESSION['passkey_login_expires']);
        unset($_SESSION['pending_password_login'], $_SESSION['passkey_login_user_id']);
        $redirect = $_SESSION['passkey_redirect'] ?? ($_SESSION['redirect_after_login'] ?? 'account.php'); unset($_SESSION['redirect_after_login'], $_SESSION['passkey_redirect']);
        $externalDomain = (string)($_SESSION['passkey_external_domain'] ?? ''); unset($_SESSION['passkey_external_domain']);
        if ($externalDomain !== '') {
            $token = bin2hex(random_bytes(32)); $host = strtolower((string)parse_url($externalDomain, PHP_URL_HOST));
            $allowedHosts = ['renadeveloper.altervista.org', 'renastore.altervista.org', 'renaarcade.altervista.org', 'renaai.altervista.org', 'renasupporto.altervista.org'];
            if (in_array($host, $allowedHosts, true)) {
                $hash = hash('sha256', $token); $expires = date('Y-m-d H:i:s', time() + 86400 * 30); $device = (string)($_SESSION['device_id'] ?? '');
                $stmt = $db->prepare('INSERT INTO rena_service_sessions (token_hash, user_id, service_host, device_id, expires_at) VALUES (?, ?, ?, ?, ?)');
                $stmt->bind_param('sisss', $hash, $uid, $host, $device, $expires); $stmt->execute(); $stmt->close();
                session_write_close();
                passkey_reply(['success' => true, 'external_data' => ['status' => 'success', 'user_id' => $uid, 'username' => $credential['username'], 'preferred_language' => $preferredLanguage, 'token' => $token], 'external_origin' => $externalDomain]);
            }
        }
        session_write_close();
        passkey_reply(['success' => true, 'redirect' => $redirect]);
    } catch (Throwable $e) {
        unset($_SESSION['passkey_login_challenge'], $_SESSION['passkey_login_expires']);
        passkey_reply(['success' => false, 'error' => $e->getMessage()], 401);
    }
}

if (!$uid) passkey_reply(['success' => false, 'error' => 'Sessione scaduta'], 401);
if (empty($_SESSION['passkey_csrf'])) $_SESSION['passkey_csrf'] = bin2hex(random_bytes(32));
if (!hash_equals($_SESSION['passkey_csrf'], (string)($input['csrf'] ?? ''))) passkey_reply(['success' => false, 'error' => 'Sessione scaduta, ricarica la pagina'], 403);

if ($action === 'register_options') {
    $stmt = $db->prepare('SELECT id, username FROM users WHERE id = ?'); $stmt->bind_param('i', $uid); $stmt->execute(); $user = $stmt->get_result()->fetch_assoc(); $stmt->close();
    $_SESSION['passkey_register_challenge'] = bin2hex(random_bytes(32)); $_SESSION['passkey_register_expires'] = time() + 300;
    $exclude = []; $stmt = $db->prepare('SELECT credential_id FROM rena_passkeys WHERE user_id = ?'); $stmt->bind_param('i', $uid); $stmt->execute(); $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) $exclude[] = ['type' => 'public-key', 'id' => $row['credential_id']]; $stmt->close();
    passkey_reply(['success' => true, 'csrf' => $_SESSION['passkey_csrf'], 'options' => ['challenge' => pk_b64e(hex2bin($_SESSION['passkey_register_challenge'])), 'rp' => ['name' => 'Rena ID', 'id' => $rpId], 'user' => ['id' => pk_b64e(pack('N', $uid)), 'name' => $user['username'], 'displayName' => $user['username']], 'pubKeyCredParams' => [['type' => 'public-key', 'alg' => -7], ['type' => 'public-key', 'alg' => -257]], 'timeout' => 300000, 'attestation' => 'none', 'authenticatorSelection' => ['residentKey' => 'required', 'requireResidentKey' => true, 'userVerification' => 'required'], 'excludeCredentials' => $exclude]]);
}

if ($action === 'register_verify') {
    try {
        $challenge = (string)($_SESSION['passkey_register_challenge'] ?? '');
        if ($challenge === '' || (int)($_SESSION['passkey_register_expires'] ?? 0) < time()) throw new RuntimeException('La richiesta è scaduta. Riprova.');
        $rawId = pk_b64d((string)($input['rawId'] ?? '')); $attestation = pk_b64d((string)($input['response']['attestationObject'] ?? '')); $clientData = pk_b64d((string)($input['response']['clientDataJSON'] ?? ''));
        if ($rawId === false || $attestation === false || $clientData === false || !hash_equals((string)($input['id'] ?? ''), pk_b64e($rawId))) throw new RuntimeException('Credenziale non valida');
        pk_client_data($clientData, 'webauthn.create', pk_b64e(hex2bin($challenge)));
        $offset = 0; $attObj = pk_cbor($attestation, $offset);
        if (!is_array($attObj) || ($attObj['fmt'] ?? '') !== 'none' || empty($attObj['authData'])) throw new RuntimeException('Formato di registrazione non supportato');
        $authData = $attObj['authData'];
        if (strlen($authData) < 55 || !hash_equals(hash('sha256', $rpId, true), substr($authData, 0, 32))) throw new RuntimeException('Dominio passkey non valido');
        $flags = ord($authData[32]);
        if (($flags & 0x01) === 0 || ($flags & 0x04) === 0 || ($flags & 0x40) === 0) throw new RuntimeException('Conferma biometrica o PIN non completata');
        $length = unpack('n', substr($authData, 53, 2))[1]; $credentialId = substr($authData, 55, $length);
        if ($length < 1 || !hash_equals($rawId, $credentialId)) throw new RuntimeException('ID passkey non corrispondente');
        $cborOffset = 55 + $length; $cose = pk_cbor($authData, $cborOffset); if (!is_array($cose)) throw new RuntimeException('Chiave pubblica non valida');
        $publicKey = pk_public_pem($cose); $credentialIdEncoded = pk_b64e($credentialId); $counter = unpack('N', substr($authData, 33, 4))[1];
        $label = trim((string)($input['device_name'] ?? 'Passkey'));
        if ($label === '') $label = 'Passkey'; $label = substr($label, 0, 120);
        $stmt = $db->prepare('INSERT INTO rena_passkeys (credential_id, user_id, public_key, sign_count, device_name) VALUES (?, ?, ?, ?, ?)');
        $stmt->bind_param('sisis', $credentialIdEncoded, $uid, $publicKey, $counter, $label); $stmt->execute(); $stmt->close();
        unset($_SESSION['passkey_register_challenge'], $_SESSION['passkey_register_expires']);
        passkey_reply(['success' => true]);
    } catch (Throwable $e) { passkey_reply(['success' => false, 'error' => $e->getMessage()], 400); }
}

if ($action === 'remove') {
    $credentialId = (string)($input['credential_id'] ?? ''); $password = (string)($input['password'] ?? '');
    $stmt = $db->prepare('SELECT password FROM users WHERE id = ?'); $stmt->bind_param('i', $uid); $stmt->execute(); $user = $stmt->get_result()->fetch_assoc(); $stmt->close();
    if (!$user || !password_verify($password, $user['password'])) passkey_reply(['success' => false, 'error' => 'Password non corretta'], 403);
    $stmt = $db->prepare('DELETE FROM rena_passkeys WHERE credential_id = ? AND user_id = ?'); $stmt->bind_param('si', $credentialId, $uid); $stmt->execute(); $removed = $stmt->affected_rows; $stmt->close();
    if (!$removed) passkey_reply(['success' => false, 'error' => 'Passkey non trovata'], 404);
    passkey_reply(['success' => true]);
}

passkey_reply(['success' => false, 'error' => 'Azione sconosciuta'], 400);

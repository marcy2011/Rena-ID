<?php
require_once __DIR__ . '/rena-session.php';

function rena_security_schema(mysqli $db): void
{
    $db->query("CREATE TABLE IF NOT EXISTS rena_device_sessions (
        device_id CHAR(32) NOT NULL PRIMARY KEY,
        user_id BIGINT UNSIGNED NOT NULL,
        session_hash CHAR(64) NOT NULL,
        device_name VARCHAR(120) NOT NULL,
        user_agent VARCHAR(500) NOT NULL,
        ip_address VARCHAR(45) NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        revoked_at DATETIME NULL,
        INDEX idx_rena_device_user (user_id),
        INDEX idx_rena_device_seen (last_seen)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $db->query("CREATE TABLE IF NOT EXISTS rena_service_sessions (
        token_hash CHAR(64) NOT NULL PRIMARY KEY,
        user_id BIGINT UNSIGNED NOT NULL,
        service_host VARCHAR(255) NOT NULL,
        device_id CHAR(32) NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME NOT NULL,
        INDEX idx_rena_service_user (user_id),
        INDEX idx_rena_service_device (device_id),
        INDEX idx_rena_service_expiry (expires_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $db->query("CREATE TABLE IF NOT EXISTS rena_passkeys (
        credential_id VARCHAR(1400) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
        user_id BIGINT UNSIGNED NOT NULL,
        public_key MEDIUMTEXT NOT NULL,
        sign_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
        device_name VARCHAR(120) NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_used DATETIME NULL,
        INDEX idx_rena_passkey_user (user_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $db->query("CREATE TABLE IF NOT EXISTS rena_qr_logins (
        token_hash CHAR(64) NOT NULL PRIMARY KEY,
        user_id BIGINT UNSIGNED NULL,
        status ENUM('pending','approved','consumed') NOT NULL DEFAULT 'pending',
        device_name VARCHAR(120) NOT NULL,
        user_agent VARCHAR(500) NOT NULL,
        ip_address VARCHAR(45) NOT NULL,
        external_origin VARCHAR(255) NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME NOT NULL,
        INDEX idx_rena_qr_expiry (expires_at),
        INDEX idx_rena_qr_user (user_id),
        INDEX idx_rena_qr_ip_created (ip_address, created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $db->query("CREATE TABLE IF NOT EXISTS rena_oauth_app_prefs (
        user_id BIGINT UNSIGNED NOT NULL,
        client_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        token_never_expires TINYINT(1) NOT NULL DEFAULT 1,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, client_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $passkeyColumn = $db->query("SHOW FULL COLUMNS FROM rena_passkeys LIKE 'credential_id'");
    if ($passkeyColumn && ($column = $passkeyColumn->fetch_assoc()) && (($column['Collation'] ?? '') !== 'ascii_bin' || ($column['Type'] ?? '') !== 'varchar(1400)')) {
        $db->query("ALTER TABLE rena_passkeys MODIFY credential_id VARCHAR(1400) CHARACTER SET ascii COLLATE ascii_bin NOT NULL");
    }
    $columns = [
        'users' => ['two_factor_enabled' => 'TINYINT(1) NOT NULL DEFAULT 0', 'two_factor_secret' => 'VARCHAR(64) NULL', 'two_factor_email_enabled' => 'TINYINT(1) NOT NULL DEFAULT 0', 'preferred_language' => "VARCHAR(2) NOT NULL DEFAULT 'it'", 'keep_signed_in' => 'TINYINT(1) NOT NULL DEFAULT 0'],
        'oauth_codes' => ['device_id' => 'CHAR(32) NULL'],
        'oauth_tokens' => ['device_id' => 'CHAR(32) NULL'],
        'rena_service_sessions' => ['device_id' => 'CHAR(32) NULL'],
        'rena_qr_logins' => ['external_origin' => 'VARCHAR(255) NULL']
    ];
    foreach ($columns as $table => $fields) {
        foreach ($fields as $column => $definition) {
            $check = $db->query("SHOW COLUMNS FROM `$table` LIKE '$column'");
            if ($check && $check->num_rows === 0) $db->query("ALTER TABLE `$table` ADD COLUMN `$column` $definition");
        }
    }
}

const RENA_OAUTH_NEVER_EXPIRES = '9999-12-31 23:59:59';
const RENA_OAUTH_DEFAULT_TTL = 2592000;

function rena_oauth_never_expires(mysqli $db, int $userId, string $clientId): bool
{
    try {
        $stmt = $db->prepare('SELECT token_never_expires FROM rena_oauth_app_prefs WHERE user_id = ? AND client_id = ?');
        if (!$stmt) return true;
        $stmt->bind_param('is', $userId, $clientId);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        return $row ? (int)$row['token_never_expires'] === 1 : true;
    } catch (Throwable $e) {
        return true;
    }
}

function rena_oauth_token_expiry(mysqli $db, int $userId, string $clientId, int $defaultTtl = RENA_OAUTH_DEFAULT_TTL): string
{
    return rena_oauth_never_expires($db, $userId, $clientId) ? RENA_OAUTH_NEVER_EXPIRES : date('Y-m-d H:i:s', time() + $defaultTtl);
}

function rena_oauth_app_prefs(mysqli $db, int $userId): array
{
    $out = [];
    try {
        $stmt = $db->prepare('SELECT client_id, token_never_expires FROM rena_oauth_app_prefs WHERE user_id = ?');
        if (!$stmt) return $out;
        $stmt->bind_param('i', $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        while ($row = $result->fetch_assoc()) $out[(string)$row['client_id']] = (int)$row['token_never_expires'] === 1;
        $stmt->close();
    } catch (Throwable $e) {
    }
    return $out;
}

function rena_oauth_set_policy(mysqli $db, int $userId, string $clientId, bool $neverExpires, int $defaultTtl = RENA_OAUTH_DEFAULT_TTL): bool
{
    try {
        $flag = $neverExpires ? 1 : 0;
        $stmt = $db->prepare('INSERT INTO rena_oauth_app_prefs (user_id, client_id, token_never_expires) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE token_never_expires = VALUES(token_never_expires), updated_at = NOW()');
        if (!$stmt) return false;
        $stmt->bind_param('isi', $userId, $clientId, $flag);
        $ok = $stmt->execute();
        $stmt->close();
        if (!$ok) return false;
        $expires = $neverExpires ? RENA_OAUTH_NEVER_EXPIRES : date('Y-m-d H:i:s', time() + $defaultTtl);
        $upd = $db->prepare('UPDATE oauth_tokens SET expires_at = ? WHERE user_id = ? AND client_id = ?');
        if ($upd) {
            $upd->bind_param('sis', $expires, $userId, $clientId);
            $upd->execute();
            $upd->close();
        }
        return true;
    } catch (Throwable $e) {
        return false;
    }
}

function rena_apply_session_persistence(mysqli $db, int $userId): bool
{
    $stmt = $db->prepare('SELECT keep_signed_in FROM users WHERE id = ?');
    $stmt->bind_param('i', $userId);
    $stmt->execute();
    $enabled = (int)($stmt->get_result()->fetch_assoc()['keep_signed_in'] ?? 0) === 1;
    $stmt->close();
    rena_set_session_persistence($enabled);
    return $enabled;
}

function rena_device_name(): string
{
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    if (preg_match('/Windows/i', $ua)) $os = 'Windows';
    elseif (preg_match('/Macintosh|Mac OS/i', $ua)) $os = 'Mac';
    elseif (preg_match('/Android/i', $ua)) $os = 'Android';
    elseif (preg_match('/iPhone|iPad/i', $ua)) $os = 'iPhone/iPad';
    elseif (preg_match('/Linux/i', $ua)) $os = 'Linux';
    else $os = 'Dispositivo';
    if (preg_match('/Edg\//i', $ua)) $browser = 'Edge';
    elseif (preg_match('/Firefox\//i', $ua)) $browser = 'Firefox';
    elseif (preg_match('/Chrome\//i', $ua)) $browser = 'Chrome';
    elseif (preg_match('/Safari\//i', $ua)) $browser = 'Safari';
    else $browser = 'Browser';
    return $browser . ' · ' . $os;
}

function rena_device_id(mysqli $db, int $userId, bool $notify = false): string
{
    $deviceId = $_COOKIE['rena_device_id'] ?? '';
    if (!preg_match('/^[a-f0-9]{32}$/', $deviceId)) {
        $deviceId = bin2hex(random_bytes(16));
        setcookie('rena_device_id', $deviceId, ['expires' => time() + 15552000, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
        $_COOKIE['rena_device_id'] = $deviceId;
    }
    $stmt = $db->prepare('SELECT user_id, revoked_at FROM rena_device_sessions WHERE device_id = ?');
    $stmt->bind_param('s', $deviceId);
    $stmt->execute();
    $existing = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    if ($existing && (int)$existing['user_id'] !== $userId) {
        $deviceId = bin2hex(random_bytes(16));
        setcookie('rena_device_id', $deviceId, ['expires' => time() + 15552000, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
        $_COOKIE['rena_device_id'] = $deviceId;
        $existing = null;
    }
    $name = rena_device_name();
    $ua = substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 500);
    $ip = substr((string)($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45);
    $sessionHash = hash('sha256', session_id());
    if (!$existing) {
        $stmt = $db->prepare('INSERT INTO rena_device_sessions (device_id, user_id, session_hash, device_name, user_agent, ip_address) VALUES (?, ?, ?, ?, ?, ?)');
        $stmt->bind_param('sissss', $deviceId, $userId, $sessionHash, $name, $ua, $ip);
        $stmt->execute();
        $stmt->close();
        if ($notify) {
            $mailStmt = $db->prepare('SELECT email FROM users WHERE id = ?');
            $mailStmt->bind_param('i', $userId);
            $mailStmt->execute();
            $email = (string)($mailStmt->get_result()->fetch_assoc()['email'] ?? '');
            $mailStmt->close();
            if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $subject = 'Nuovo accesso al tuo Rena ID';
                $safeName = htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
                $safeIp = htmlspecialchars($ip, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
                $safeIp = str_replace(['.', ':'], ['.<span></span>', ':<span></span>'], $safeIp);
                $when = (new DateTime('now', new DateTimeZone('Europe/Rome')))->format('d/m/Y H:i');
                $when = str_replace(['/', ':', ' '], ['/<span></span>', ':<span></span>', ' <span></span>'], $when);
                $accountUrl = 'https://rena.altervista.org/account.php';
                $rowStyle = "padding:12px 0;border-bottom:1px solid #292929;font-size:14px";
                $body = "<!doctype html><html lang='it'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'><meta name='format-detection' content='telephone=no,date=no,address=no,email=no,url=no'><title>Nuovo accesso a Rena ID</title></head>"
                    . "<body style='margin:0;padding:0;background:#000;color:#fff;font-family:Inter,-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif'><div style='max-width:600px;margin:0 auto;padding:40px 20px'>"
                    . "<div style='background:#111;border-radius:24px;padding:40px 28px;border:1px solid #292929;text-align:center'>"
                    . "<h1 style='font-size:24px;font-weight:600;margin:0 0 18px;color:#fff'>Nuovo accesso al tuo account</h1>"
                    . "<p style='font-size:16px;color:#d1d5db;line-height:1.6;margin:0 0 24px'>Abbiamo rilevato un accesso al tuo Rena ID da un dispositivo che non avevamo mai visto.</p>"
                    . "<div style='background:linear-gradient(135deg,#3b3b3b,#222);border-radius:16px;padding:10px 22px;margin:24px 0;border:1px solid #3a3a3a;text-align:left'>"
                    . "<table role='presentation' width='100%' cellspacing='0' cellpadding='0' style='border-collapse:collapse'>"
                    . "<tr><td style='$rowStyle;color:#c4c4c4'>Dispositivo</td><td style='$rowStyle;color:#fff;font-weight:600;text-align:right'>$safeName</td></tr>"
                    . "<tr><td style='$rowStyle;color:#c4c4c4'>Indirizzo IP</td><td style='$rowStyle;color:#fff;font-weight:600;text-align:right;font-family:monospace'>$safeIp</td></tr>"
                    . "<tr><td style='padding:12px 0;font-size:14px;color:#c4c4c4'>Data e ora</td><td style='padding:12px 0;font-size:14px;color:#fff;font-weight:600;text-align:right'>$when</td></tr>"
                    . "</table></div>"
                    . "<div style='background:#2a1414;border-radius:12px;padding:16px;margin:20px 0;border:1px solid #5a2424'><p style='font-size:14px;color:#f0a3a3;line-height:1.5;margin:0'>Se non sei stato tu, revoca subito il dispositivo dalla pagina Gestione account e cambia la password.</p></div>"
                    . "<a href='$accountUrl' style='display:inline-block;background:#fff;color:#000;text-decoration:none;font-size:15px;font-weight:600;padding:14px 28px;border-radius:12px;margin-top:8px'>Gestisci i dispositivi</a>"
                    . "<div style='margin-top:32px;padding-top:20px;border-top:1px solid #292929'><p style='font-size:14px;color:#d1d5db;margin:0 0 8px'>Se sei stato tu, non devi fare nulla.</p><p style='font-size:12px;color:#777;margin:0'>Il Team Rena</p></div>"
                    . "</div></div></body></html>";
                $headers = "From: Rena ID <rena@altervista.org>\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n";
                @mail($email, $subject, $body, $headers);
            }
        }
    } else {
        if (!empty($existing['revoked_at'])) {
            setcookie('rena_device_id', '', ['expires' => time() - 3600, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
            unset($_COOKIE['rena_device_id']);
            return rena_device_id($db, $userId, $notify);
        }
        $stmt = $db->prepare('UPDATE rena_device_sessions SET session_hash = ?, device_name = ?, user_agent = ?, ip_address = ?, last_seen = NOW() WHERE device_id = ? AND user_id = ?');
        $stmt->bind_param('sssssi', $sessionHash, $name, $ua, $ip, $deviceId, $userId);
        $stmt->execute();
        $stmt->close();
    }
    return $deviceId;
}

function rena_totp_code(string $secret, ?int $time = null): string
{
    $key = base32_decode($secret);
    $counter = (int)floor(($time ?? time()) / 30);
    $binaryCounter = pack('N*', 0) . pack('N*', $counter);
    $hash = hash_hmac('sha1', $binaryCounter, $key, true);
    $offset = ord($hash[19]) & 0x0f;
    $value = ((ord($hash[$offset]) & 0x7f) << 24) | ((ord($hash[$offset + 1]) & 0xff) << 16) | ((ord($hash[$offset + 2]) & 0xff) << 8) | (ord($hash[$offset + 3]) & 0xff);
    return str_pad((string)($value % 1000000), 6, '0', STR_PAD_LEFT);
}

function base32_decode(string $value): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $value = strtoupper(preg_replace('/[^A-Z2-7]/i', '', $value));
    $buffer = 0; $bits = 0; $out = '';
    for ($i = 0; $i < strlen($value); $i++) {
        $buffer = ($buffer << 5) | strpos($alphabet, $value[$i]);
        $bits += 5;
        if ($bits >= 8) { $bits -= 8; $out .= chr(($buffer >> $bits) & 0xff); }
    }
    return $out;
}

function rena_totp_valid(string $secret, string $code): bool
{
    $code = preg_replace('/\D/', '', $code);
    if (strlen($code) !== 6) return false;
    for ($offset = -1; $offset <= 1; $offset++) if (hash_equals(rena_totp_code($secret, time() + $offset * 30), $code)) return true;
    return false;
}

function rena_base32_encode(string $bytes): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; $buffer = 0; $bits = 0; $out = '';
    for ($i = 0; $i < strlen($bytes); $i++) {
        $buffer = ($buffer << 8) | ord($bytes[$i]); $bits += 8;
        while ($bits >= 5) { $bits -= 5; $out .= $alphabet[($buffer >> $bits) & 31]; }
    }
    if ($bits > 0) $out .= $alphabet[($buffer << (5 - $bits)) & 31];
    return $out;
}

function rena_send_login_email_code(mysqli $db, int $userId, string $username): array
{
    $lastSent = (int)($_SESSION['login_email_code_sent_at'] ?? 0);
    if ($lastSent && time() - $lastSent < 60) return ['success' => false, 'error' => 'Attendi un minuto prima di richiedere un altro codice.'];
    $stmt = $db->prepare('SELECT email, two_factor_email_enabled FROM users WHERE id = ?');
    $stmt->bind_param('i', $userId); $stmt->execute(); $user = $stmt->get_result()->fetch_assoc(); $stmt->close();
    if (!$user || empty($user['two_factor_email_enabled']) || !filter_var($user['email'] ?? '', FILTER_VALIDATE_EMAIL)) return ['success' => false, 'error' => 'La verifica via email non è attiva per questo account.'];
    $code = (string)random_int(100000, 999999);
    $subject = 'Il tuo codice di accesso Rena ID';
    $safeUsername = htmlspecialchars($username, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $body = "<!doctype html><html lang='it'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Codice di accesso Rena ID</title></head>"
        . "<body style='margin:0;padding:0;background:#000;color:#fff;font-family:Inter,-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif'><div style='max-width:600px;margin:0 auto;padding:40px 20px'>"
        . "<div style='background:#111;border-radius:24px;padding:40px 28px;border:1px solid #292929;text-align:center'>"
        . "<h1 style='font-size:24px;font-weight:600;margin:0 0 18px;color:#fff'>Verifica in due passaggi</h1>"
        . "<p style='font-size:16px;color:#d1d5db;line-height:1.6;margin:0 0 24px'>Ciao $safeUsername, inserisci questo codice per completare l’accesso a Rena ID.</p>"
        . "<div style='background:linear-gradient(135deg,#3b3b3b,#222);border-radius:16px;padding:26px 18px;margin:24px 0;border:1px solid #3a3a3a'>"
        . "<p style='font-size:14px;color:#d1d5db;margin:0 0 12px'>Il tuo codice di verifica</p><div style='font-size:32px;font-weight:700;color:#fff;letter-spacing:8px;font-family:monospace;white-space:nowrap'>$code</div>"
        . "<p style='font-size:12px;color:#c4c4c4;margin:14px 0 0'>Valido per 10 minuti</p></div>"
        . "<div style='background:#10231b;border-radius:12px;padding:16px;margin:20px 0;border:1px solid #214a37'><p style='font-size:14px;color:#7ee0a8;line-height:1.5;margin:0'>Se non hai richiesto tu questo codice, ignora questa email. Il tuo account rimane protetto.</p></div>"
        . "<div style='margin-top:32px;padding-top:20px;border-top:1px solid #292929'><p style='font-size:14px;color:#d1d5db;margin:0 0 8px'>Grazie per aver scelto Rena ID</p><p style='font-size:12px;color:#777;margin:0'>Il Team Rena</p></div>"
        . "</div></div></body></html>";
    $headers = "From: Rena ID <rena@altervista.org>\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n";
    if (!@mail($user['email'], $subject, $body, $headers)) return ['success' => false, 'error' => 'Non è stato possibile inviare l’email. Riprova più tardi.'];
    $_SESSION['login_email_challenge'] = ['user_id' => $userId, 'username' => $username, 'hash' => password_hash($code, PASSWORD_DEFAULT), 'expires_at' => time() + 600, 'attempts' => 0];
    $_SESSION['login_email_code_sent_at'] = time();
    return ['success' => true, 'message' => 'Codice inviato all’indirizzo email associato al tuo account.'];
}

function rena_check_login_email_code(int $userId, string $username, string $code): bool
{
    $challenge = $_SESSION['login_email_challenge'] ?? null;
    if (!is_array($challenge) || (int)($challenge['user_id'] ?? 0) !== $userId || !hash_equals((string)($challenge['username'] ?? ''), $username) || (int)($challenge['expires_at'] ?? 0) < time() || (int)($challenge['attempts'] ?? 0) >= 5) return false;
    if (!preg_match('/^\d{6}$/', $code) || !password_verify($code, (string)$challenge['hash'])) {
        $_SESSION['login_email_challenge']['attempts'] = (int)$challenge['attempts'] + 1;
        return false;
    }
    unset($_SESSION['login_email_challenge'], $_SESSION['login_email_code_sent_at']);
    return true;
}
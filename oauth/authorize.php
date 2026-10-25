<?php
require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../rena-security.php';
require_once __DIR__ . '/../rena-ui.php';

header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store');
header_remove('Permissions-Policy');
header('Permissions-Policy: publickey-credentials-get=(self), publickey-credentials-create=(self)');

session_name('RENA_OAUTH_EMBED');
session_set_cookie_params(['lifetime' => 0, 'path' => '/oauth/', 'secure' => true, 'httponly' => true, 'samesite' => 'None']);
ini_set('session.use_strict_mode', '1');
require_once __DIR__ . '/../rena-session.php';
rena_session_start();
function oauth_embed_cookie(): void {
    header_remove('Set-Cookie');
    header('Set-Cookie: ' . session_name() . '=' . session_id() . '; Path=/oauth/; Secure; HttpOnly; SameSite=None; Partitioned', false);
}
oauth_embed_cookie();
$db = rena_db();
rena_security_schema($db);
$sessionLang = (string)($_SESSION['rena_preferred_language'] ?? '');
$preferredLanguage = in_array($sessionLang, ['it', 'en'], true) ? $sessionLang : rui_guess_lang();
if (!empty($_SESSION['user_id'])) {
    $_SESSION['device_id'] = rena_device_id($db, (int)$_SESSION['user_id'], true);
    $languageStmt = $db->prepare('SELECT preferred_language FROM users WHERE id = ?');
    $languageUid = (int)$_SESSION['user_id']; $languageStmt->bind_param('i', $languageUid); $languageStmt->execute();
    $languageRow = $languageStmt->get_result()->fetch_assoc(); $languageStmt->close();
    $savedLanguage = (string)($languageRow['preferred_language'] ?? 'it');
    $preferredLanguage = in_array($savedLanguage, ['it', 'en'], true) ? $savedLanguage : 'it';
    $_SESSION['rena_preferred_language'] = $preferredLanguage;
}

function h($s) { return rui_h($s); }
function pw_toggle_html(): string {
    return '<button type="button" class="pw-toggle" data-pw-toggle aria-pressed="false" aria-label="' . h(rui_t('Mostra password', 'Show password')) . '">' . rui_icon('eye') . '</button>';
}

function icon_key(): string { return '<svg class="icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" width="16" height="16" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M22 8.29344C22 11.7692 19.1708 14.5869 15.6807 14.5869C15.0439 14.5869 13.5939 14.4405 12.8885 13.8551L12.0067 14.7333C11.4883 15.2496 11.6283 15.4016 11.8589 15.652C11.9551 15.7565 12.0672 15.8781 12.1537 16.0505C12.1537 16.0505 12.8885 17.075 12.1537 18.0995C11.7128 18.6849 10.4783 19.5045 9.06754 18.0995L8.77362 18.3922C8.77362 18.3922 9.65538 19.4167 8.92058 20.4412C8.4797 21.0267 7.30403 21.6121 6.27531 20.5876L5.2466 21.6121C4.54119 22.3146 3.67905 21.9048 3.33616 21.6121L2.45441 20.7339C1.63143 19.9143 2.1115 19.0264 2.45441 18.6849L10.0963 11.0743C10.0963 11.0743 9.3615 9.90338 9.3615 8.29344C9.3615 4.81767 12.1907 2 15.6807 2C19.1708 2 22 4.81767 22 8.29344ZM15.681 10.4889C16.8984 10.4889 17.8853 9.50601 17.8853 8.29353C17.8853 7.08105 16.8984 6.09814 15.681 6.09814C14.4635 6.09814 13.4766 7.08105 13.4766 8.29353C13.4766 9.50601 14.4635 10.4889 15.681 10.4889Z" fill="currentColor"></path></svg>'; }
function icon_fingerprint(): string { return '<svg class="icon" width="18" height="18" style="flex-shrink:0" fill="currentColor" viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M63.28,202a15.29,15.29,0,0,1-7.7-2,14.84,14.84,0,0,1-5.52-20.46C69.34,147.36,128,72.25,256,72.25c55.47,0,104.12,14.57,144.53,43.29,33.26,23.57,51.9,50.25,60.78,63.1a14.79,14.79,0,0,1-4,20.79,15.52,15.52,0,0,1-21.24-4C420,172.32,371,102,256,102c-112.25,0-163,64.71-179.53,92.46A15,15,0,0,1,63.28,202Z"></path><path d="M320.49,496a15.31,15.31,0,0,1-3.79-.43c-92.85-23-127.52-115.82-128.93-119.68l-.22-.85c-.76-2.68-19.39-66.33,9.21-103.61,13.11-17,33.05-25.72,59.38-25.72,24.48,0,42.14,7.61,54.28,23.36,10,12.86,14,28.72,17.87,44,8.13,31.82,14,48.53,47.79,50.25,14.84.75,24.59-7.93,30.12-15.32,14.95-20.15,17.55-53,6.28-82C398,228.57,346.61,158,256,158c-38.68,0-74.22,12.43-102.72,35.79C129.69,213.14,111,240.46,102,268.54c-16.69,52.28,5.2,134.46,5.41,135.21A14.83,14.83,0,0,1,96.54,422a15.39,15.39,0,0,1-18.74-10.6c-1-3.75-24.38-91.4-5.1-151.82,21-65.47,85.81-131.47,183.33-131.47,45.07,0,87.65,15.32,123.19,44.25,27.52,22.5,50,52.72,61.76,82.93,14.95,38.57,10.94,81.86-10.19,110.14-14.08,18.86-34.13,28.72-56.34,27.65-57.86-2.9-68.26-43.29-75.84-72.75-7.8-30.22-12.79-44.79-42.58-44.79-16.36,0-27.85,4.5-35,13.82-9.75,12.75-10.51,32.68-9.43,47.14a152.44,152.44,0,0,0,5.1,29.79c2.38,6,33.37,82,107.59,100.39a14.88,14.88,0,0,1,11,18.11A15.36,15.36,0,0,1,320.49,496Z"></path><path d="M201.31,489.14a15.5,15.5,0,0,1-11.16-4.71c-37.16-39-58.18-82.61-66.09-137.14V347c-4.44-36.1,2.06-87.21,33.91-122.35,23.51-25.93,56.56-39.11,98.06-39.11,49.08,0,87.65,22.82,111.7,65.89,17.45,31.29,20.91,62.47,21,63.75a15.07,15.07,0,0,1-13.65,16.4,15.26,15.26,0,0,1-16.79-13.29h0A154,154,0,0,0,340.43,265c-18.64-32.89-47-49.61-84.51-49.61-32.4,0-57.75,9.75-75.19,29-25.14,27.75-30,70.5-26.55,98.78,6.93,48.22,25.46,86.58,58.18,120.86a14.7,14.7,0,0,1-.76,21.11A15.44,15.44,0,0,1,201.31,489.14Z"></path><path d="M372.5,446.18c-32.5,0-60.13-9-82.24-26.89-44.42-35.79-49.4-94.08-49.62-96.54a15.27,15.27,0,0,1,30.45-2.36c.11.86,4.55,48.54,38.79,76,20.26,16.18,47.34,22.6,80.71,18.85a15.2,15.2,0,0,1,16.91,13.18,14.92,14.92,0,0,1-13.44,16.5A187,187,0,0,1,372.5,446.18Z"></path><path d="M398.18,48.79C385.5,40.54,340.54,16,256,16c-88.74,0-133.81,27.11-143.78,34a11.59,11.59,0,0,0-1.84,1.4.36.36,0,0,1-.22.1,14.87,14.87,0,0,0-5.09,11.15A15.06,15.06,0,0,0,120.38,77.5a15.56,15.56,0,0,0,8.88-2.79c.43-.32,39.22-28.82,126.77-28.82S382.58,74.29,383,74.5a15.25,15.25,0,0,0,9.21,3A15.06,15.06,0,0,0,407.5,62.61,14.9,14.9,0,0,0,398.18,48.79Z"></path></svg>'; }

function page(array $title, string $bodyHtml, string $script = '') {
    rui_set_lang($GLOBALS['preferredLanguage'] ?? 'it');
    echo '<!DOCTYPE html><html lang="' . h(rui_lang()) . '"><head>';
    rui_head('Rena - ' . $title['it'], 'Rena - ' . $title['en'], '../');
    echo '</head><body class="auth">';
    rui_sprite();
    echo '<main class="auth-wrap"><div class="card">' . $bodyHtml . '</div></main>';
    rui_scripts('../');
    echo '<script>RenaUI.initLang(' . json_encode(rui_lang()) . ', true);' . $script . '</script></body></html>';
    exit;
}
function alert_html($msg, string $kind = 'error'): string {
    if (!$msg) return '';
    return '<div class="alert ' . ($kind === 'error' ? 'alert-error' : '') . '" role="' . ($kind === 'error' ? 'alert' : 'status') . '">'
         . rui_icon($kind === 'error' ? 'alert-circle' : 'info') . '<span>' . h(rui_pick($msg)) . '</span></div>';
}

$clientId    = $_GET['client_id'] ?? '';
$redirectUri = $_GET['redirect_uri'] ?? '';
$client      = rena_get_client($clientId);

if (!$client || !rena_redirect_allowed($client, $redirectUri)) {
    http_response_code(400);
    page(rui_msg('Richiesta non valida', 'Invalid request'),
        '<div class="logo">' . rui_icon('alert-circle') . '</div><h1>' . h(rui_t('Richiesta non valida', 'Invalid request')) . '</h1>'
        . '<p class="subtitle">' . h(rui_t("L'applicazione che ti ha inviato qui non è registrata correttamente su Rena ID. Torna all'app e riprova.", 'The app that sent you here is not registered correctly with Rena ID. Go back to the app and try again.')) . '</p>');
}

$origins = [];
foreach (json_decode($client['redirect_uris'], true) ?: [] as $u) {
    $p = parse_url($u);
    $sch = strtolower($p['scheme'] ?? '');
    if (!$p || empty($p['host']) || !in_array($sch, ['https', 'http'], true)) continue;
    $origins[$sch . '://' . $p['host'] . (isset($p['port']) ? ':' . $p['port'] : '')] = true;
}
header_remove('X-Frame-Options');
header_remove('Content-Security-Policy');
header('Content-Security-Policy: frame-ancestors ' . ($origins ? implode(' ', array_keys($origins)) : "'none'"));

$state     = $_GET['state'] ?? '';
$challenge = $_GET['code_challenge'] ?? '';
$method    = $_GET['code_challenge_method'] ?? '';
$isPublic  = empty($client['client_secret_hash']);

function back_to_client($redirectUri, array $params) {
    global $origins;
    $sep = (strpos($redirectUri, '?') === false) ? '?' : '&';
    $url = $redirectUri . $sep . http_build_query($params);
    $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP;
    $message = json_encode(['type' => 'rena-oauth', 'url' => $url, 'params' => $params], $flags);
    $script = 'var U=' . json_encode($url, $flags) . ',M=' . $message . ',T=' . json_encode(array_keys($origins), $flags) . ';'
        . 'if(window.parent!==window){T.forEach(function(o){try{window.parent.postMessage(M,o)}catch(e){}})}else{location.replace(U)}';
    $failed = isset($params['error']);
    $body = '<div class="logo">' . rui_icon($failed ? 'alert-circle' : 'check-circle') . '</div>'
        . '<h1>' . h($failed ? rui_t('Accesso annullato', 'Sign-in cancelled') : rui_t('Accesso completato', 'Signed in')) . '</h1>'
        . '<p class="subtitle">' . h(rui_t('Ti stiamo riportando all’app…', 'Taking you back to the app…')) . '</p>'
        . '<a class="btn" href="' . h($url) . '" target="_top" rel="noopener">' . h(rui_t('Continua', 'Continue')) . '</a>';
    page(rui_msg($failed ? 'Accesso annullato' : 'Accesso completato', $failed ? 'Sign-in cancelled' : 'Signed in'), $body, $script);
}

function issue_code_and_redirect($db, array $client, string $redirectUri, string $challenge, string $state) {
    $code = bin2hex(random_bytes(32));
    $codeHash = rena_hash_token($code);
    $uid = (int)$_SESSION['user_id'];
    $ch = $challenge !== '' ? $challenge : null;
    $deviceId = (string)($_SESSION['device_id'] ?? '');
    $stmt = $db->prepare('INSERT INTO oauth_codes (code_hash, client_id, user_id, redirect_uri, code_challenge, device_id, expires_at) VALUES (?, ?, ?, ?, ?, ?, NOW() + INTERVAL 120 SECOND)');
    $stmt->bind_param('ssisss', $codeHash, $client['client_id'], $uid, $redirectUri, $ch, $deviceId);
    $stmt->execute();
    $stmt->close();
    back_to_client($redirectUri, ['code' => $code, 'state' => $state]);
}

if (($_GET['response_type'] ?? '') !== 'code') {
    back_to_client($redirectUri, ['error' => 'unsupported_response_type', 'state' => $state]);
}
if ($challenge !== '' && ($method !== 'S256' || !preg_match('/^[A-Za-z0-9_\-]{43,128}$/', $challenge))) {
    back_to_client($redirectUri, ['error' => 'invalid_request', 'error_description' => 'PKCE: usare S256', 'state' => $state]);
}
if ($isPublic && $challenge === '') {
    back_to_client($redirectUri, ['error' => 'invalid_request', 'error_description' => 'PKCE obbligatorio per client pubblici', 'state' => $state]);
}

if (empty($_SESSION['oauth_csrf'])) $_SESSION['oauth_csrf'] = bin2hex(random_bytes(16));
$csrf = $_SESSION['oauth_csrf'];

$error = null;
$notice = null;
$selectedLoginMethod = (string)($_POST['login_method'] ?? '');
$factorStep = false;
$factorOptions = ['totp' => false, 'email' => false, 'passkey' => false];
if (!empty($_SESSION['pending_password_login']) && (int)($_SESSION['pending_password_login']['expires_at'] ?? 0) >= time()) {
    $factorStep = true;
    $pendingUid = (int)$_SESSION['pending_password_login']['user_id'];
    $stmt = $db->prepare('SELECT two_factor_enabled, two_factor_email_enabled, preferred_language FROM users WHERE id = ?'); $stmt->bind_param('i', $pendingUid); $stmt->execute(); $pendingFactors = $stmt->get_result()->fetch_assoc(); $stmt->close();
    $pendingLanguage = (string)($pendingFactors['preferred_language'] ?? 'it');
    $preferredLanguage = in_array($pendingLanguage, ['it', 'en'], true) ? $pendingLanguage : 'it';
    $factorOptions['totp'] = !empty($pendingFactors['two_factor_enabled']); $factorOptions['email'] = !empty($pendingFactors['two_factor_email_enabled']);
    $stmt = $db->prepare('SELECT COUNT(*) AS total FROM rena_passkeys WHERE user_id = ?'); $stmt->bind_param('i', $pendingUid); $stmt->execute(); $factorOptions['passkey'] = (int)$stmt->get_result()->fetch_assoc()['total'] > 0; $stmt->close();
} else unset($_SESSION['pending_password_login']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($csrf, (string)($_POST['csrf'] ?? ''))) {
        http_response_code(400);
        page(rui_msg('Sessione scaduta', 'Session expired'),
            '<div class="logo">' . rui_icon('clock') . '</div><h1>' . h(rui_t('Sessione scaduta', 'Session expired')) . '</h1><p class="subtitle">' . h(rui_t('Ricarica la pagina e riprova.', 'Reload the page and try again.')) . '</p>'
            . '<a class="btn" href="">' . rui_icon('refresh') . h(rui_t('Ricarica', 'Reload')) . '</a>');
    }
    $do = $_POST['do'] ?? '';
    if ($do === '' && isset($_POST['two_factor_code']) && !empty($_SESSION['pending_password_login'])) $do = 'verify_factor';

    if ($do === 'send_email_code') {
        $pending = $_SESSION['pending_password_login'] ?? null;
        if (is_array($pending) && (int)($pending['expires_at'] ?? 0) >= time()) {
            $pendingUid = (int)$pending['user_id']; $stmt = $db->prepare('SELECT id, username FROM users WHERE id = ?'); $stmt->bind_param('i', $pendingUid); $stmt->execute(); $account = $stmt->get_result()->fetch_assoc(); $stmt->close();
        } else {
            $u = trim($_POST['username'] ?? ''); $p = (string)($_POST['password'] ?? '');
            $stmt = $db->prepare('SELECT id, username, password, two_factor_email_enabled FROM users WHERE username = ?');
            $stmt->bind_param('s', $u); $stmt->execute(); $account = $stmt->get_result()->fetch_assoc(); $stmt->close();
            if ($account && (!password_verify($p, $account['password']) || empty($account['two_factor_email_enabled']))) $account = null;
        }
        if ($account) {
            $sent = rena_send_login_email_code($db, (int)$account['id'], (string)$account['username']);
            $text = $sent['message'] ?? $sent['error'] ?? '';
            if (!empty($sent['success'])) $notice = $text ?: rui_msg('Codice inviato. Controlla la tua email.', 'Code sent. Check your email.');
            else $error = $text ?: rui_msg('Invio non riuscito', 'Could not send the code');
            $selectedLoginMethod = 'email';
        } else $error = rui_msg('Username o password non validi', 'Incorrect username or password');
    } elseif ($do === 'login') {
        $u = trim($_POST['username'] ?? '');
        $p = (string)($_POST['password'] ?? '');
        $stmt = $db->prepare('SELECT id, username, password, two_factor_enabled, two_factor_secret, two_factor_email_enabled, preferred_language FROM users WHERE username = ?');
        $stmt->bind_param('s', $u);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        if ($user && !empty($user['password']) && password_verify($p, $user['password'])) {
            $accountLanguage = (string)($user['preferred_language'] ?? 'it');
            $preferredLanguage = in_array($accountLanguage, ['it', 'en'], true) ? $accountLanguage : 'it';
            $stmt = $db->prepare('SELECT COUNT(*) AS total FROM rena_passkeys WHERE user_id = ?'); $stmt->bind_param('i', $user['id']); $stmt->execute(); $hasPasskey = (int)$stmt->get_result()->fetch_assoc()['total'] > 0; $stmt->close();
            $factorOptions = ['totp' => !empty($user['two_factor_enabled']), 'email' => !empty($user['two_factor_email_enabled']), 'passkey' => $hasPasskey];
            if (in_array(true, $factorOptions, true)) {
                $_SESSION['pending_password_login'] = ['user_id' => (int)$user['id'], 'username' => (string)$user['username'], 'expires_at' => time() + 300]; $factorStep = true;
            } else {
                $_SESSION['user_id'] = $user['id']; $_SESSION['username'] = $user['username']; $_SESSION['rena_preferred_language'] = $preferredLanguage; $_SESSION['device_id'] = rena_device_id($db, (int)$user['id'], true);
                $_SESSION['oauth_csrf'] = bin2hex(random_bytes(16));
                session_write_close();
                issue_code_and_redirect($db, $client, $redirectUri, $challenge, $state);
            }
        } else $error = rui_msg('Username o password non validi', 'Incorrect username or password');
    } elseif ($do === 'verify_factor') {
        $pending = $_SESSION['pending_password_login'] ?? null;
        if (!is_array($pending) || (int)($pending['expires_at'] ?? 0) < time()) { unset($_SESSION['pending_password_login']); $error = rui_msg('La verifica è scaduta. Inserisci di nuovo la password.', 'Verification expired. Enter your password again.'); }
        else {
            $pendingUid = (int)$pending['user_id']; $stmt = $db->prepare('SELECT id, username, two_factor_enabled, two_factor_secret, two_factor_email_enabled, preferred_language FROM users WHERE id = ?');
            $stmt->bind_param('i', $pendingUid); $stmt->execute(); $user = $stmt->get_result()->fetch_assoc(); $stmt->close();
            $accountLanguage = (string)($user['preferred_language'] ?? 'it');
            $preferredLanguage = in_array($accountLanguage, ['it', 'en'], true) ? $accountLanguage : 'it';
            $method = (string)($_POST['login_method'] ?? 'totp');
            $factorOk = false;
            if ($user && $method === 'email' && !empty($user['two_factor_email_enabled'])) $factorOk = rena_check_login_email_code($pendingUid, (string)$user['username'], preg_replace('/\D+/', '', (string)($_POST['two_factor_code'] ?? '')));
            elseif ($user && $method === 'totp' && !empty($user['two_factor_enabled'])) $factorOk = rena_totp_valid((string)$user['two_factor_secret'], preg_replace('/\D+/', '', (string)($_POST['two_factor_code'] ?? '')));
            if ($factorOk) {
                unset($_SESSION['pending_password_login']);
                $_SESSION['user_id'] = $user['id']; $_SESSION['username'] = $user['username']; $_SESSION['rena_preferred_language'] = $preferredLanguage; $_SESSION['device_id'] = rena_device_id($db, $pendingUid, true);
                $_SESSION['oauth_csrf'] = bin2hex(random_bytes(16)); $csrf = $_SESSION['oauth_csrf'];
            } else {
            $error = rui_msg('Codice di verifica non valido o scaduto', 'Invalid or expired verification code'); $factorStep = true;
            $selectedLoginMethod = $method;
            }
        }
    } elseif ($do === 'switch') {
        unset($_SESSION['user_id'], $_SESSION['username'], $_SESSION['pending_password_login']);
        header('Location: ' . $_SERVER['REQUEST_URI']);
        exit;
    } elseif ($do === 'deny') {
        back_to_client($redirectUri, ['error' => 'access_denied', 'state' => $state]);
    } elseif ($do === 'allow' && !empty($_SESSION['user_id'])) {
        issue_code_and_redirect($db, $client, $redirectUri, $challenge, $state);
    }
}

$hidden = '<input type="hidden" name="csrf" value="' . h($csrf) . '">';
$appName = h($client['name']);

if (empty($_SESSION['user_id'])) {
    $hasCode = $factorOptions['totp'] || $factorOptions['email'];
    $selected = ($selectedLoginMethod === 'totp' && $factorOptions['totp']) || ($selectedLoginMethod === 'email' && $factorOptions['email'])
        ? $selectedLoginMethod : ($factorOptions['totp'] ? 'totp' : ($factorOptions['email'] ? 'email' : ''));

    if (!$factorStep) {
        $body = '<div class="logo">' . rui_icon('id') . '</div>'
          . '<h1>' . h(rui_t('Accedi a Rena ID', 'Sign in to Rena ID')) . '</h1>'
          . '<p class="subtitle">' . h(rui_t('per continuare su ', 'to continue to ')) . '<strong>' . $appName . '</strong></p>'
          . alert_html($error) . alert_html($notice, 'info')
          . '<form method="post" action="" data-busy>' . $hidden
          . '<div class="field"><label for="username">Username</label><div class="input"><input type="text" id="username" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required autofocus value="' . h($_POST['username'] ?? '') . '" placeholder="' . h(rui_t('Il tuo username', 'Your username')) . '"></div></div>'
          . '<div class="field"><label for="password">Password</label><div class="input"><input type="password" id="password" name="password" autocomplete="current-password" required placeholder="' . h(rui_t('La tua password', 'Your password')) . '">' . pw_toggle_html() . '</div>'
          . '<div class="field-row"><span></span><a class="link" href="/password-forgot.php" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;gap:6px">' . icon_key() . h(rui_t('Password dimenticata?', 'Forgot your password?')) . '</a></div></div>'
          . '<button class="btn" type="submit" name="do" value="login">' . h(rui_t('Accedi', 'Sign in')) . '</button>'
          . '<p class="foot">' . h(rui_t('Non hai un account?', "Don't have an account?")) . ' <a href="/register.php" target="_blank" rel="noopener">' . h(rui_t('Registrati', 'Sign up')) . '</a></p>'
          . '</form>';
        page(rui_msg('Accedi a Rena ID', 'Sign in to Rena ID'), $body);
    }

    $body = '<div class="logo">' . rui_icon('shield-check') . '</div>'
      . '<h1>' . h(rui_t('Verifica in due passaggi', 'Two-step verification')) . '</h1>'
      . '<p class="subtitle">' . h(rui_t('Password verificata per ', 'Password verified for ')) . '<strong>' . h($_SESSION['pending_password_login']['username'] ?? '') . '</strong>. ' . h(rui_t('Conferma che sei tu per continuare su ', 'Confirm it’s you to continue to ')) . '<strong>' . $appName . '</strong>.</p>'
      . alert_html($error) . alert_html($notice, 'info')
      . '<form method="post" action="" id="factorForm" data-busy>' . $hidden
      . '<input type="hidden" name="username" value="' . h($_SESSION['pending_password_login']['username'] ?? '') . '">';
    if ($hasCode) $body .= '<button type="submit" name="do" value="verify_factor" hidden tabindex="-1" aria-hidden="true"></button>';
    if ($factorOptions['totp'] && $factorOptions['email']) {
        $body .= '<div class="seg" role="radiogroup" aria-label="' . h(rui_t('Metodo di verifica', 'Verification method')) . '">'
              . '<label><input type="radio" name="login_method" value="totp"' . ($selected === 'totp' ? ' checked' : '') . '><span>' . h(rui_t('App di autenticazione', 'Authenticator app')) . '</span></label>'
              . '<label><input type="radio" name="login_method" value="email"' . ($selected === 'email' ? ' checked' : '') . '><span>' . h(rui_t('Codice via email', 'Email code')) . '</span></label></div>';
    } elseif ($hasCode) {
        $body .= '<input type="hidden" name="login_method" value="' . h($selected) . '">';
    }
    if ($hasCode) {
        $body .= '<div class="field"><label for="two_factor_code">' . h(rui_t('Codice a 6 cifre', '6-digit code')) . '</label>'
              . '<div class="input"><input type="text" class="otp" id="two_factor_code" name="two_factor_code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" placeholder="000000" data-otp data-autosubmit required autofocus></div><p class="hint" id="methodHint"></p></div>';
        if ($factorOptions['email']) {
            $body .= '<div class="field" id="emailSend"' . ($selected === 'email' ? '' : ' hidden') . '><button class="btn btn-ghost" type="submit" name="do" value="send_email_code" formnovalidate>' . rui_icon('mail') . h(rui_t('Invia il codice via email', 'Send the code by email')) . '</button></div>';
        }
        $body .= '<button class="btn" type="submit" name="do" value="verify_factor">' . rui_icon('check') . h(rui_t('Verifica e accedi', 'Verify and sign in')) . '</button>';
    }
    if ($factorOptions['passkey']) {
        if ($hasCode) $body .= '<div class="divider">' . h(rui_t('oppure', 'or')) . '</div>';
        $body .= '<button class="btn ' . ($hasCode ? 'btn-ghost' : '') . '" type="button" id="passkeyBtn">' . icon_fingerprint() . h(rui_t('Verifica con passkey', 'Verify with passkey')) . '</button>';
    }
    $body .= '<p class="foot"><button class="link" type="submit" name="do" value="switch" formnovalidate>' . rui_icon('arrow-left') . ' ' . h(rui_t('Usa un altro account', 'Use another account')) . '</button></p></form>';

    $hintFlags = JSON_UNESCAPED_UNICODE | JSON_HEX_TAG;
    $hintTotp  = json_encode(rui_t('Apri la tua app di autenticazione e inserisci il codice mostrato.', 'Open your authenticator app and enter the code it shows.'), $hintFlags);
    $hintEmail = json_encode(rui_t('Controlla la tua casella email e inserisci il codice ricevuto.', 'Check your inbox and enter the code we sent you.'), $hintFlags);
    $script = "var f=document.getElementById('factorForm'),es=document.getElementById('emailSend'),mh=document.getElementById('methodHint'),HT=" . $hintTotp . ",HE=" . $hintEmail . ";"
      . "function um(){var r=f.querySelector('[name=login_method]:checked'),h=f.querySelector('input[type=hidden][name=login_method]'),m=r?r.value:(h?h.value:'');if(mh)mh.textContent=m==='email'?HE:HT;if(es)es.hidden=m!=='email'}"
      . "if(f){f.addEventListener('change',um);um();"
      . "if(es){es.querySelector('button').addEventListener('click',function(){var r=f.querySelector('[name=login_method][value=email]');if(r)r.checked=true})}}"
      . "var pk=document.getElementById('passkeyBtn');if(pk)pk.addEventListener('click',function(){var R=RenaUI,ret=location.pathname+location.search;R.busy(pk,true);"
      . "R.passkeyLogin('passkey.php?embed=1',{action:'password_factor_options',return_to:ret}).then(function(){location.reload()})"
      . ".catch(function(e){R.toast(e.message||R.t('Accesso con passkey non riuscito','Passkey sign-in failed'),'error');R.busy(pk,false)})});";
    page(rui_msg('Accedi a Rena ID', 'Sign in to Rena ID'), $body, $script);
}

$stmt = $db->prepare('SELECT id, username, profile_photo FROM users WHERE id = ?');
$uid = (int)$_SESSION['user_id'];
$stmt->bind_param('i', $uid);
$stmt->execute();
$me = $stmt->get_result()->fetch_assoc();
$stmt->close();
if (!$me) { unset($_SESSION['user_id'], $_SESSION['username']); header('Location: ' . $_SERVER['REQUEST_URI']); exit; }

$photo = rena_photo_url($me['id'], $me['profile_photo']);
$avatar = $photo
    ? '<img class="avatar" src="' . h($photo) . '" alt="" width="84" height="84" onerror="this.replaceWith(Object.assign(document.createElement(\'div\'),{className:\'avatar\',textContent:this.dataset.i}))" data-i="' . h(mb_strtoupper(mb_substr($me['username'], 0, 1))) . '">'
    : '<div class="avatar" aria-hidden="true">' . h(mb_strtoupper(mb_substr($me['username'], 0, 1))) . '</div>';
$returnHost = parse_url($redirectUri, PHP_URL_HOST) ?: (parse_url($redirectUri, PHP_URL_SCHEME) . '://');

$body = '<div class="logo">' . $avatar . '</div>'
  . '<h1>' . h(rui_t('Ciao, ', 'Hello, ')) . h($me['username']) . '</h1>'
  . '<p class="subtitle"><strong>' . $appName . '</strong> ' . h(rui_t('vuole accedere con il tuo Rena ID.', 'wants to sign in with your Rena ID.')) . '</p>'
  . '<p class="label" style="text-align:left;margin-bottom:0">' . h(rui_t('Condividerai:', 'You will share:')) . '</p>'
  . '<ul class="scopes">'
  . '<li>' . rui_icon('check-circle') . h(rui_t('Il tuo nome utente', 'Your username')) . '</li>'
  . '<li>' . rui_icon('check-circle') . h(rui_t('La tua foto profilo', 'Your profile photo')) . '</li></ul>'
  . '<p class="hint" style="text-align:center;margin:-4px 0 18px">' . h(rui_t('Non condivideremo email, password o altri dati. Dopo l’accesso tornerai su ', 'We won’t share your email, password or any other data. After signing in you’ll return to ')) . '<strong style="color:#fff">' . h($returnHost) . '</strong>.</p>'
  . '<form method="post" action="" data-busy>' . $hidden
  . '<button class="btn" name="do" value="allow">' . rui_icon('check') . h(rui_t('Continua come ', 'Continue as ')) . h($me['username']) . '</button>'
  . '<button class="btn btn-ghost" name="do" value="deny">' . h(rui_t('Annulla', 'Cancel')) . '</button>'
  . '<p class="foot"><button class="link" name="do" value="switch" type="submit">' . h(rui_t('Usa un altro account', 'Use another account')) . '</button></p></form>';
page(rui_msg('Autorizza accesso', 'Authorize access'), $body);

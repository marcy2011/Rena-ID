<?php
require_once __DIR__ . '/bootstrap.php';

header('X-Frame-Options: DENY');
header("Content-Security-Policy: frame-ancestors 'none'");
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store');

$embed = (($_GET['embed'] ?? '') === '1');
if ($embed) {
    session_name('RENA_OAUTH_EMBED');
    session_set_cookie_params(['lifetime' => 0, 'path' => '/oauth/', 'secure' => true, 'httponly' => true, 'samesite' => 'None']);
}
session_start();
$db = rena_db();

function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

function page($title, $bodyHtml) {
    echo '<!DOCTYPE html><html lang="it"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
       . '<title>' . h($title) . '</title><style>'
       . '*{box-sizing:border-box;margin:0;padding:0}body{font-family:Inter,system-ui,sans-serif;background:#000;color:#fff;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}'
       . '.card{background:rgba(0,0,0,.7);border:1px solid rgba(255,255,255,.1);border-radius:24px;width:100%;max-width:400px;padding:36px;text-align:center}'
       . 'h1{font-size:22px;margin-bottom:8px}p{color:#d1d5db;font-size:14px;line-height:1.5;margin-bottom:16px}'
       . '.avatar{width:84px;height:84px;border-radius:50%;object-fit:cover;background:#1a1a1a;margin:8px auto 14px;display:block}'
       . 'label{display:block;text-align:left;font-size:14px;color:#d1d5db;margin-bottom:6px}'
       . 'input[type=text],input[type=password]{width:100%;padding:14px 16px;border:2px solid #2a2a2a;border-radius:12px;background:#1a1a1a;color:#fff;font-size:16px;margin-bottom:16px}'
       . '.btn{display:block;width:100%;padding:14px;border:0;border-radius:12px;background:#fff;color:#000;font-size:16px;font-weight:600;cursor:pointer;margin-top:8px}'
       . '.btn.sec{background:#2c2c2c;color:#fff}.err{color:#ff6b6b;font-size:14px;margin-bottom:14px}'
       . '.scopes{background:#111;border-radius:12px;padding:12px 14px;text-align:left;font-size:14px;margin:14px 0 8px}.scopes li{margin-left:18px;color:#d1d5db}'
       . 'a{color:#fff}</style></head><body><div class="card">' . $bodyHtml . '</div></body></html>';
    exit;
}

$clientId    = $_GET['client_id'] ?? '';
$redirectUri = $_GET['redirect_uri'] ?? '';
$client      = rena_get_client($clientId);

if (!$client || !rena_redirect_allowed($client, $redirectUri)) {
    http_response_code(400);
    page('Richiesta non valida', '<h1>Richiesta non valida</h1><p>L\'applicazione che ti ha inviato qui non è registrata correttamente su Rena ID.</p>');
}

if ($embed) {
    $origins = [];
    foreach (json_decode($client['redirect_uris'], true) ?: [] as $u) {
        $p = parse_url($u);
        $sch = strtolower($p['scheme'] ?? '');
        if (!$p || empty($p['host']) || !in_array($sch, ['https', 'http'], true)) continue;
        $origins[$sch . '://' . $p['host'] . (isset($p['port']) ? ':' . $p['port'] : '')] = true;
    }
    header_remove('X-Frame-Options');
    header('Content-Security-Policy: frame-ancestors ' . ($origins ? implode(' ', array_keys($origins)) : "'none'"));
}

$state     = $_GET['state'] ?? '';
$challenge = $_GET['code_challenge'] ?? '';
$method    = $_GET['code_challenge_method'] ?? '';
$isPublic  = empty($client['client_secret_hash']);

function back_to_client($redirectUri, array $params) {
    $sep = (strpos($redirectUri, '?') === false) ? '?' : '&';
    header('Location: ' . $redirectUri . $sep . http_build_query($params));
    exit;
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

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($csrf, (string)($_POST['csrf'] ?? ''))) {
        http_response_code(400);
        page('Richiesta non valida', '<h1>Sessione scaduta</h1><p>Ricarica la pagina e riprova.</p>');
    }
    $do = $_POST['do'] ?? '';

    if ($do === 'login') {
        $u = trim($_POST['username'] ?? '');
        $p = (string)($_POST['password'] ?? '');
        $stmt = $db->prepare('SELECT id, username, password FROM users WHERE username = ?');
        $stmt->bind_param('s', $u);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        if ($user && !empty($user['password']) && password_verify($p, $user['password'])) {
            session_regenerate_id(true);
            $_SESSION['user_id']  = $user['id'];      
            $_SESSION['username'] = $user['username'];
            $_SESSION['oauth_csrf'] = bin2hex(random_bytes(16));
            header('Location: ' . $_SERVER['REQUEST_URI']);
            exit;
        }
        sleep(1); 
        $error = 'Username o password non corretti';
    } elseif ($do === 'switch') {
        unset($_SESSION['user_id'], $_SESSION['username']);
        header('Location: ' . $_SERVER['REQUEST_URI']);
        exit;
    } elseif ($do === 'deny') {
        back_to_client($redirectUri, ['error' => 'access_denied', 'state' => $state]);
    } elseif ($do === 'allow' && !empty($_SESSION['user_id'])) {
        $code = bin2hex(random_bytes(32));
        $codeHash = rena_hash_token($code);
        $uid = (int)$_SESSION['user_id'];
        $ch = $challenge !== '' ? $challenge : null;
        $stmt = $db->prepare('INSERT INTO oauth_codes (code_hash, client_id, user_id, redirect_uri, code_challenge, expires_at) VALUES (?, ?, ?, ?, ?, NOW() + INTERVAL 120 SECOND)');
        $stmt->bind_param('ssiss', $codeHash, $client['client_id'], $uid, $redirectUri, $ch);
        $stmt->execute();
        $stmt->close();
        back_to_client($redirectUri, ['code' => $code, 'state' => $state]);
    }
}

$hidden = '<input type="hidden" name="csrf" value="' . h($csrf) . '">';

if (empty($_SESSION['user_id'])) {
    $body = '<h1>Accedi a Rena ID</h1><p>per continuare su <strong>' . h($client['name']) . '</strong></p>'
          . ($error ? '<div class="err">' . h($error) . '</div>' : '')
          . '<form method="post" action="">' . $hidden . '<input type="hidden" name="do" value="login">'
          . '<label>Username</label><input type="text" name="username" autocomplete="username" required>'
          . '<label>Password</label><input type="password" name="password" autocomplete="current-password" required>'
          . '<button class="btn" type="submit">Accedi</button></form>'
          . '<p style="margin-top:16px"><a href="/register.php" target="_blank" rel="noopener">Crea il tuo Rena ID</a> · <a href="/password-forgot.php" target="_blank" rel="noopener">Password dimenticata?</a></p>';
    page('Accedi a Rena ID', $body);
}

$stmt = $db->prepare('SELECT id, username, profile_photo FROM users WHERE id = ?');
$uid = (int)$_SESSION['user_id'];
$stmt->bind_param('i', $uid);
$stmt->execute();
$me = $stmt->get_result()->fetch_assoc();
$stmt->close();
if (!$me) { unset($_SESSION['user_id'], $_SESSION['username']); header('Location: ' . $_SERVER['REQUEST_URI']); exit; }

$photo = rena_photo_url($me['id'], $me['profile_photo']);
$avatar = $photo ? '<img class="avatar" src="' . h($photo) . '" alt="">' : '<div class="avatar"></div>';

$body = $avatar . '<h1>Ciao, ' . h($me['username']) . '</h1>'
      . '<p><strong>' . h($client['name']) . '</strong> vuole accedere con il tuo Rena ID.</p>'
      . '<p style="font-size:13px">Dopo l\'accesso tornerai su: <strong>' . h(parse_url($redirectUri, PHP_URL_HOST) ?: (parse_url($redirectUri, PHP_URL_SCHEME) . '://')) . '</strong></p>'
      . '<ul class="scopes"><li>Il tuo nome utente</li><li>La tua foto profilo</li></ul>'
      . '<p style="font-size:12px">Non condivideremo email, password o altri dati.</p>'
      . '<form method="post" action="">' . $hidden . '<button class="btn" name="do" value="allow">Continua come ' . h($me['username']) . '</button>'
      . '<button class="btn sec" name="do" value="deny">Annulla</button>'
      . '<button class="btn sec" name="do" value="switch" style="background:none;font-size:14px">Usa un altro account</button></form>';
page('Autorizza accesso', $body);

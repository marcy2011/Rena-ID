<?php
if (defined('RUI_LOADED')) return;
define('RUI_LOADED', true);

const RUI_SERVICE_HOSTS = [
    'renadeveloper.altervista.org' => 'Rena Developer',
    'renastore.altervista.org'     => 'Rena Store',
    'renaarcade.altervista.org'    => 'Rena Arcade',
    'renaai.altervista.org'        => 'Rena AI',
    'renasupporto.altervista.org'  => 'Rena Supporto',
];
const RUI_FLAGS = [
    'it' => 'https://renadeveloper.altervista.org/bandierait.png',
    'en' => 'https://renadeveloper.altervista.org/bandieraen.png',
];

if (!function_exists('mb_strlen')) { function mb_strlen($s) { return preg_match_all('/./su', (string)$s); } }
if (!function_exists('mb_substr')) { function mb_substr($s, $start, $len = null) { $a = preg_split('//u', (string)$s, -1, PREG_SPLIT_NO_EMPTY) ?: []; return implode('', array_slice($a, $start, $len)); } }
if (!function_exists('mb_strtoupper')) { function mb_strtoupper($s) { return strtoupper((string)$s); } }

$GLOBALS['rui_lang'] = 'it';

function rui_set_lang(string $lang): void { $GLOBALS['rui_lang'] = $lang === 'en' ? 'en' : 'it'; }
function rui_lang(): string { return $GLOBALS['rui_lang'] === 'en' ? 'en' : 'it'; }
function rui_guess_lang(): string {
    $h = strtolower(substr((string)($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ''), 0, 2));
    return ($h === '' || $h === 'it') ? 'it' : 'en';
}
function rui_h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
function rui_t(string $it, string $en): string { return rui_lang() === 'en' ? $en : $it; }
function rui_te(string $it, string $en): void { echo rui_h(rui_t($it, $en)); }
function rui_msg(string $it, string $en): array { return ['it' => $it, 'en' => $en]; }
function rui_pick($msg): string {
    if (is_array($msg)) return (string)($msg[rui_lang()] ?? $msg['it'] ?? '');
    return (string)$msg;
}
function rui_tr(string $it, string $en, string $tag = 'span', string $attrs = ''): string {
    return "<$tag $attrs data-translate-it=\"" . rui_h($it) . '" data-translate-en="' . rui_h($en) . '">' . rui_h(rui_t($it, $en)) . "</$tag>";
}
function rui_ph(string $it, string $en): string {
    return 'placeholder="' . rui_h(rui_t($it, $en)) . '" data-placeholder-it="' . rui_h($it) . '" data-placeholder-en="' . rui_h($en) . '"';
}

function rui_asset(string $file, string $prefix = ''): string {
    $path = __DIR__ . '/' . $file;
    return $prefix . $file . (is_file($path) ? '?v=' . filemtime($path) : '');
}
function rui_head(string $titleIt, string $titleEn, string $prefix = ''): void {
    echo '<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">'
       . '<meta name="color-scheme" content="dark"><meta name="theme-color" content="#000000">'
       . '<link rel="icon" type="image/png" href="' . $prefix . 'renaidlogo.png">'
       . '<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
       . '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap">'
       . '<link rel="stylesheet" href="' . rui_h(rui_asset('rena-ui.css', $prefix)) . '">'
       . '<title data-translate-it="' . rui_h($titleIt) . '" data-translate-en="' . rui_h($titleEn) . '">' . rui_h(rui_t($titleIt, $titleEn)) . '</title>';
}
function rui_scripts(string $prefix = ''): void {
    echo '<script src="' . rui_h(rui_asset('rena-ui.js', $prefix)) . '"></script>';
}

function rui_icon(string $name, string $class = ''): string {
    return '<svg class="i ' . $class . '" aria-hidden="true" focusable="false"><use href="#i-' . $name . '"/></svg>';
}
function rui_sprite(): void {
    $s = [
        'id'        => '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="9" r="3"/><path d="M17.97 20c-.16-2.9-1.05-5-5.97-5s-5.81 2.1-5.97 5"/>',
        'user'      => '<circle cx="12" cy="8" r="4"/><path d="M4 21c1-4 4-6 8-6s7 2 8 6"/>',
        'lock'      => '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
        'eye'       => '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
        'eye-off'   => '<path d="M3 3l18 18"/><path d="M6.6 6.6A17 17 0 0 0 2 12s3.5 7 10 7a9.7 9.7 0 0 0 4.4-1M10 5.2A10 10 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.2 4.2"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
        'key'       => '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3M14 9l2 2"/>',
        'mail'      => '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
        'qr'        => '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3zM20 14v1M14 20h1M18 18h3v3h-3z"/>',
        'fingerprint'=> '<path d="M12 11v4c0 2-.5 4-1.5 6M8 11a4 4 0 0 1 8 0v2c0 3 .5 5 1.5 7M5 12a7 7 0 0 1 14 0M5 17c.5-1.5 1-3 1-5"/>',
        'shield'    => '<path d="M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6z"/>',
        'shield-check'=> '<path d="M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
        'monitor'   => '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
        'phone'     => '<rect x="7" y="2" width="10" height="20" rx="2"/><path d="M11 18h2"/>',
        'link'      => '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
        'globe'     => '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/>',
        'clock'     => '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
        'trash'     => '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>',
        'camera'    => '<path d="M4 8h3l2-3h6l2 3h3v11H4z"/><circle cx="12" cy="13" r="3.5"/>',
        'upload'    => '<path d="M12 16V4M7 9l5-5 5 5M4 20h16"/>',
        'logout'    => '<path d="M9 4H5v16h4M16 8l4 4-4 4M20 12H9"/>',
        'arrow-left'=> '<path d="M19 12H5M11 6l-6 6 6 6"/>',
        'check'     => '<path d="M5 12l5 5 9-10"/>',
        'check-circle'=> '<circle cx="12" cy="12" r="9"/><path d="M8 12l3 3 5-6"/>',
        'alert'     => '<path d="M12 3l10 18H2z"/><path d="M12 10v5M12 18v.01"/>',
        'alert-circle'=> '<circle cx="12" cy="12" r="9"/><path d="M12 7v6M12 16.5v.01"/>',
        'info'      => '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5v.01"/>',
        'x'         => '<path d="M6 6l12 12M18 6L6 18"/>',
        'circle'    => '<circle cx="12" cy="12" r="8"/>',
        'plus'      => '<path d="M12 5v14M5 12h14"/>',
        'send'      => '<path d="M21 3L10 14M21 3l-7 18-4-7-7-4z"/>',
        'copy'      => '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/>',
        'sliders'   => '<path d="M4 6h8M18 6h2M4 12h2M12 12h8M4 18h10M20 18h0"/><circle cx="15" cy="6" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="17" cy="18" r="2"/>',
        'home'      => '<path d="M4 11l8-7 8 7v9H4z"/>',
        'news'      => '<path d="M5 4h11v16H7a2 2 0 0 1-2-2zM16 8h3v10a2 2 0 0 1-2 2M8 8h5M8 12h5M8 16h3"/>',
        'loader'    => '<path d="M12 3a9 9 0 1 0 9 9"/>',
        'refresh'   => '<path d="M20 11a8 8 0 0 0-14-4L4 9M4 4v5h5M4 13a8 8 0 0 0 14 4l2-2M20 20v-5h-5"/>',
        'image'     => '<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="10" r="1.5"/><path d="M21 16l-5-5-8 8"/>',
    ];
    echo '<svg width="0" height="0" style="position:absolute" aria-hidden="true" focusable="false"><defs>';
    foreach ($s as $id => $inner) echo '<symbol id="i-' . $id . '" viewBox="0 0 24 24">' . $inner . '</symbol>';
    echo '</defs></svg><div class="toast-region" id="toasts" role="status" aria-live="polite"></div>';
}

function rui_lang_switcher(): void {
    ?>
<button type="button" class="lang-btn" id="langBtn" aria-haspopup="dialog" aria-label="<?= rui_h(rui_t('Cambia lingua', 'Change language')) ?>">
  <img id="langFlag" src="<?= RUI_FLAGS[rui_lang()] ?>" alt="" width="22" height="16"><span id="langCode"><?= strtoupper(rui_lang()) ?></span>
</button>
<dialog id="langDialog" aria-labelledby="langTitle"><div class="dlg">
  <button type="button" class="dlg-close" data-close aria-label="<?= rui_h(rui_t('Chiudi', 'Close')) ?>"><?= rui_icon('x') ?></button>
  <h2 id="langTitle" data-translate-it="Seleziona lingua" data-translate-en="Select language"><?= rui_te('Seleziona lingua', 'Select language') ?></h2>
  <div class="lang-list">
    <button type="button" class="lang-opt" data-lang="it"><img src="<?= RUI_FLAGS['it'] ?>" alt="" width="24" height="17"><span>Italiano</span><?= rui_icon('check', 'lang-check') ?></button>
    <button type="button" class="lang-opt" data-lang="en"><img src="<?= RUI_FLAGS['en'] ?>" alt="" width="24" height="17"><span>English</span><?= rui_icon('check', 'lang-check') ?></button>
  </div>
</div></dialog>
<?php
}

function rui_context_menu(): void {
    ?>
<nav id="custom-menu" aria-label="Rena" hidden><ul>
  <li><a href="https://rena.altervista.org"><?= rui_icon('home') ?><span>Home</span></a></li>
  <li><a href="https://rena.altervista.org/privacy-policy.html"><?= rui_icon('shield') ?><span>Privacy Policy</span></a></li>
  <li><a href="https://rena.altervista.org/chi-siamo.html"><?= rui_icon('user') ?><?= rui_tr('Chi siamo', 'About us') ?></a></li>
  <li><a href="https://rena.altervista.org/news.php"><?= rui_icon('news') ?><span>News</span></a></li>
</ul></nav>
<?php
}

function rui_allowed_service_url(string $url): ?string {
    $p = parse_url(trim($url));
    if (!$p || strtolower((string)($p['scheme'] ?? '')) !== 'https' || isset($p['user']) || isset($p['pass'])) return null;
    $host = strtolower((string)($p['host'] ?? ''));
    if (!isset(RUI_SERVICE_HOSTS[$host]) || isset($p['port'])) return null;
    return filter_var(trim($url), FILTER_SANITIZE_URL) ?: null;
}
function rui_service_name(?string $url): string {
    $host = strtolower((string)parse_url((string)$url, PHP_URL_HOST));
    return RUI_SERVICE_HOSTS[$host] ?? '';
}
function rui_register_service_session(mysqli $db, int $uid, string $token, string $serviceUrl, string $deviceId): void {
    $host = strtolower((string)parse_url($serviceUrl, PHP_URL_HOST));
    if (!isset(RUI_SERVICE_HOSTS[$host])) return;
    try {
        $hash = hash('sha256', $token);
        $expires = date('Y-m-d H:i:s', time() + 86400 * 30);
        $stmt = $db->prepare('INSERT INTO rena_service_sessions (token_hash, user_id, service_host, device_id, expires_at) VALUES (?, ?, ?, ?, ?)');
        $stmt->bind_param('sisss', $hash, $uid, $host, $deviceId, $expires);
        $stmt->execute();
        $stmt->close();
    } catch (Throwable $e) {
        error_log('Rena service session tracking error: ' . $e->getMessage());
    }
}
function rui_password_problem(string $pw): ?array {
    if (strlen($pw) < 8) return rui_msg('La password deve essere di almeno 8 caratteri', 'Your password must be at least 8 characters');
    if (!preg_match('/[0-9]/', $pw)) return rui_msg('La password deve contenere almeno un numero', 'Your password must contain at least one number');
    if (!preg_match('/[\/\-_]/', $pw)) return rui_msg('La password deve contenere almeno un carattere speciale (/, -, _)', 'Your password must contain at least one special character (/, -, _)');
    return null;
}

function rui_handoff_page(array $userData, string $serviceUrl, string $kind = 'login'): void {
    $name = rui_service_name($serviceUrl) ?: (string)parse_url($serviceUrl, PHP_URL_HOST);
    $sep = strpos($serviceUrl, '?') === false ? '?' : '&';
    $target = $serviceUrl . $sep . 'token=' . rawurlencode((string)$userData['token'])
        . '&user_id=' . rawurlencode((string)$userData['user_id'])
        . '&username=' . rawurlencode((string)$userData['username']);
    $title = $kind === 'register' ? rui_msg('Account creato', 'Account created') : rui_msg('Accesso completato', 'Signed in');
    header('Cache-Control: no-store');
    ?><!DOCTYPE html>
<html lang="<?= rui_lang() ?>"><head><?php rui_head($title['it'], $title['en']); ?></head>
<body class="auth"><?php rui_sprite(); ?>
<main class="auth-wrap"><div class="card" role="status" aria-live="polite">
  <div class="logo ok"><?= rui_icon('check-circle') ?></div>
  <h1><?= rui_h(rui_pick($title)) ?></h1>
  <p class="subtitle" id="handoffText"><?= rui_te('Ti stiamo riportando su ', 'Taking you back to ') ?><strong><?= rui_h($name) ?></strong>…</p>
  <a class="btn btn-ghost" id="handoffLink" href="<?= rui_h($target) ?>" hidden><?= rui_te('Continua su ', 'Continue to ') ?><?= rui_h($name) ?></a>
</div></main>
<script>
(function () {
  var data = <?= json_encode($userData, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP) ?>;
  var origin = <?= json_encode($serviceUrl, JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP) ?>;
  var target = <?= json_encode($target, JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP) ?>;
  var link = document.getElementById('handoffLink');
  setTimeout(function () { link.hidden = false; }, 2500);
  if (window.opener) {
    window.opener.postMessage(data, origin);
    setTimeout(function () {
      window.close();
      document.getElementById('handoffText').textContent = <?= json_encode(rui_t('Puoi chiudere questa finestra e tornare al servizio.', 'You can close this window and go back to the service.')) ?>;
    }, 400);
  } else {
    window.location.href = target;
  }
})();
</script></body></html>
<?php
    exit;
}

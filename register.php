<?php
ini_set('display_errors', '0'); 
error_reporting(E_ALL);

require_once __DIR__ . '/rena-session.php';
rena_session_start();
require_once __DIR__ . '/config_id.php';
require_once __DIR__ . '/rena-security.php';
require_once __DIR__ . '/rena-ui.php';

$error = null;
$db = new mysqli('localhost', 'username', 'password', 'my_rena');
$db->set_charset('utf8mb4');
rena_security_schema($db);

$externalUrl = rui_allowed_service_url((string)($_GET['external_domain'] ?? ''));
$serviceName = rui_service_name($externalUrl);
$postUsername = trim((string)($_POST['username'] ?? ''));
$postEmail = trim((string)($_POST['email'] ?? ''));

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $postUsername;
    $email = $postEmail;
    $password = (string)($_POST['password'] ?? '');
    $confirm_password = (string)($_POST['confirm_password'] ?? '');
    $len = mb_strlen($username);

    if ($len < 3 || $len > 30 || !preg_match('/^[\p{L}\p{N}._-]+$/u', $username)) {
        $error = rui_msg('Lo username deve avere da 3 a 30 caratteri: lettere, numeri, punto, trattino o underscore.', 'Your username must be 3–30 characters: letters, numbers, dot, hyphen or underscore.');
    } elseif ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = rui_msg('Indirizzo email non valido', 'Invalid email address');
    } elseif ($password !== $confirm_password) {
        $error = rui_msg('Le password non coincidono', 'Passwords do not match');
    } elseif ($problem = rui_password_problem($password)) {
        $error = $problem;
    } else {
        $stmt = $db->prepare('SELECT id FROM users WHERE username = ?');
        $stmt->bind_param('s', $username); $stmt->execute(); $taken = $stmt->get_result()->num_rows > 0; $stmt->close();
        $emailTaken = false;
        if (!$taken && $email !== '') {
            $stmt = $db->prepare('SELECT id FROM users WHERE email = ?');
            $stmt->bind_param('s', $email); $stmt->execute(); $emailTaken = $stmt->get_result()->num_rows > 0; $stmt->close();
        }
        if ($taken) {
            $error = rui_msg('Username già utilizzato', 'Username already taken');
        } elseif ($emailTaken) {
            $error = rui_msg('Questa email è già associata a un account', 'This email is already linked to an account');
        } else {
            $password_hash = password_hash($password, PASSWORD_DEFAULT);
            $emailValue = $email !== '' ? $email : null;
            $stmt = $db->prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)');
            $stmt->bind_param('sss', $username, $emailValue, $password_hash);
            if ($stmt->execute()) {
                $user_id = (int)$db->insert_id;
                $stmt->close();
                session_regenerate_id(true);
                $_SESSION['user_id'] = $user_id;
                $_SESSION['username'] = $username;
                rena_apply_session_persistence($db, $user_id);
                $_SESSION['device_id'] = rena_device_id($db, $user_id, true);

                if ($externalUrl) {
                    $token = bin2hex(random_bytes(32));
                    $_SESSION['cross_domain_token'] = $token;
                    rui_register_service_session($db, $user_id, $token, $externalUrl, (string)($_SESSION['device_id'] ?? ''));
                    rui_set_lang(rui_guess_lang());
                    rui_handoff_page(['status' => 'success', 'user_id' => $user_id, 'username' => $username, 'profile_pic' => null, 'token' => $token], $externalUrl, 'register');
                }
                header('Location: account.php');
                exit();
            }
            error_log('Register error: ' . $stmt->error);
            $error = rui_msg('Non è stato possibile creare l’account. Riprova tra poco.', 'We could not create your account. Please try again shortly.');
        }
    }
}
$db->close();
rui_set_lang(rui_guess_lang());
?>
<!DOCTYPE html>
<html lang="<?= rui_lang() ?>">
<head><?php rui_head('Rena - Crea Rena ID', 'Rena - Create Rena ID'); ?></head>
<body class="auth">
<?php rui_sprite(); rui_lang_switcher(); ?>

<main class="auth-wrap"><div class="card">
  <div class="logo"><?= rui_icon('id') ?></div>
  <h1><?= rui_tr('Crea il tuo Rena ID', 'Create your Rena ID') ?></h1>
  <p class="subtitle">
    <?php if ($serviceName): ?><?= rui_tr('Un solo account per continuare su ', 'One account to continue to ') ?><strong><?= rui_h($serviceName) ?></strong>.
    <?php else: ?><?= rui_tr('Un solo account per tutti i servizi Rena.', 'One account for every Rena service.') ?><?php endif; ?>
  </p>

  <?php if ($error): ?><div class="alert alert-error" role="alert" id="serverError"><?= rui_icon('alert-circle') ?><span data-msg='<?= rui_h(json_encode($error, JSON_UNESCAPED_UNICODE)) ?>'><?= rui_h(rui_pick($error)) ?></span></div><?php endif; ?>

  <form method="post" action="" id="registerForm" data-busy novalidate>
    <div class="field">
      <label for="username">Username</label>
      <div class="input"><input type="text" id="username" name="username" required minlength="3" maxlength="30" autocomplete="username" autocapitalize="none" spellcheck="false" autofocus value="<?= rui_h($postUsername) ?>" <?= rui_ph('Scegli uno username', 'Choose a username') ?>></div>
      <p class="hint"><?= rui_tr('Da 3 a 30 caratteri: lettere, numeri, . - _', '3–30 characters: letters, numbers, . - _') ?></p>
    </div>

    <div class="field">
      <label for="email"><?= rui_tr('Email', 'Email') ?> <span style="color:var(--faint);font-weight:400">(<?= rui_tr('facoltativa', 'optional') ?>)</span></label>
      <div class="input"><input type="email" id="email" name="email" autocomplete="email" value="<?= rui_h($postEmail) ?>" <?= rui_ph('tua@email.com', 'you@email.com') ?>></div>
      <p class="hint"><?= rui_tr('Consigliata: serve per recuperare la password e per la verifica via email.', 'Recommended: you need it to reset your password and for email verification.') ?></p>
    </div>

    <div class="field">
      <label for="password">Password</label>
      <div class="input"><input type="password" id="password" name="password" required autocomplete="new-password" <?= rui_ph('Crea una password', 'Create a password') ?>></div>
      <ul class="rules" id="rules" aria-live="polite">
        <li data-rule="length"><?= rui_icon('circle') ?><?= rui_tr('Almeno 8 caratteri', 'At least 8 characters') ?></li>
        <li data-rule="number"><?= rui_icon('circle') ?><?= rui_tr('Almeno un numero', 'At least one number') ?></li>
        <li data-rule="special"><?= rui_icon('circle') ?><?= rui_tr('Almeno un carattere speciale (/, -, _)', 'At least one special character (/, -, _)') ?></li>
      </ul>
    </div>

    <div class="field">
      <label for="confirm_password"><?= rui_tr('Conferma password', 'Confirm password') ?></label>
      <div class="input"><input type="password" id="confirm_password" name="confirm_password" required autocomplete="new-password" <?= rui_ph('Ripeti la password', 'Repeat the password') ?>></div>
      <div class="match" id="match" aria-live="polite"></div>
    </div>

    <button type="submit" class="btn"><?= rui_icon('user') ?><?= rui_tr('Crea account', 'Create account') ?></button>
    <p class="hint" style="text-align:center;margin-top:14px"><?= rui_tr('Creando un account accetti la', 'By creating an account you accept the') ?> <a href="https://rena.altervista.org/privacy-policy.html" target="_blank" rel="noopener">Privacy Policy</a>.</p>
    <p class="foot"><?= rui_tr('Hai già un account?', 'Already have an account?') ?> <a href="login.php<?= $externalUrl ? '?external_domain=' . rawurlencode($externalUrl) : '' ?>"><?= rui_tr('Accedi', 'Sign in') ?></a></p>
  </form>
</div></main>

<?php rui_context_menu(); rui_scripts(); ?>
<script>
(function () {
  var R = RenaUI, $ = R.$;
  R.initLang(<?= json_encode(rui_lang()) ?>, false);
  ['password', 'confirm_password'].forEach(function (id) { $('#' + id).parentElement.append(R.pwToggle()); });

  var pw = $('#password'), cf = $('#confirm_password'), rules = $('#rules'), match = $('#match'), form = $('#registerForm');
  function checkMatch() {
    if (!cf.value) { match.textContent = ''; match.className = 'match'; return false; }
    var ok = pw.value === cf.value;
    match.className = 'match ' + (ok ? 'ok' : 'bad');
    match.textContent = ok ? R.t('Le password coincidono', 'Passwords match') : R.t('Le password non coincidono', 'Passwords do not match');
    return ok;
  }
  pw.addEventListener('input', function () { R.paintRules(rules, pw.value); checkMatch(); });
  cf.addEventListener('input', checkMatch);
  document.addEventListener('rena:lang', function () {
    checkMatch();
    R.$$('[data-msg]').forEach(function (e) { try { e.textContent = R.pick(JSON.parse(e.dataset.msg)); } catch (x) {} });
  });

  form.addEventListener('submit', function (e) {
    var problem = null, target = null;
    if (!/^[\p{L}\p{N}._-]{3,30}$/u.test($('#username').value.trim())) { problem = R.t('Lo username deve avere da 3 a 30 caratteri: lettere, numeri, . - _', 'Your username must be 3–30 characters: letters, numbers, . - _'); target = $('#username'); }
    else if ($('#email').value && !$('#email').checkValidity()) { problem = R.t('Controlla l’indirizzo email', 'Check your email address'); target = $('#email'); }
    else if (!R.pwRules(pw.value).ok) { problem = R.t('La password non soddisfa ancora tutti i requisiti', 'Your password doesn’t meet all requirements yet'); target = pw; }
    else if (pw.value !== cf.value) { problem = R.t('Le password non coincidono', 'Passwords do not match'); target = cf; }
    if (problem) { e.preventDefault(); R.toast(problem, 'error'); target.focus(); }
  });
  if ($('#serverError')) $('#serverError').scrollIntoView({ block: 'nearest' });
})();
</script>
</body>
</html>


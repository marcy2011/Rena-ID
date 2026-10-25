<?php
require_once __DIR__ . '/rena-session.php';
rena_session_start();
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
require __DIR__ . '/config_id.php';
require_once __DIR__ . '/rena-security.php';
require_once __DIR__ . '/rena-ui.php';
$db = db();
rena_security_schema($db);

$whitelist = include __DIR__ . '/redirect_whitelist.php';
$factorStep = false;
$preferredLanguage = null;
$factorOptions = ['totp' => false, 'email' => false, 'passkey' => false];
$error = null;
$notice = null;

$externalUrl = rui_allowed_service_url((string)($_GET['external_domain'] ?? ''));
$serviceName = rui_service_name($externalUrl);

if (!empty($_SESSION['pending_password_login']) && (int)($_SESSION['pending_password_login']['expires_at'] ?? 0) >= time()) {
    $factorStep = true;
    $pendingUid = (int)$_SESSION['pending_password_login']['user_id'];
    $factorStmt = $db->prepare('SELECT two_factor_enabled, two_factor_email_enabled, preferred_language FROM users WHERE id = ?');
    $factorStmt->bind_param('i', $pendingUid); $factorStmt->execute(); $pendingFactors = $factorStmt->get_result()->fetch_assoc(); $factorStmt->close();
    $pendingLanguage = (string)($pendingFactors['preferred_language'] ?? 'it');
    $preferredLanguage = in_array($pendingLanguage, ['it', 'en'], true) ? $pendingLanguage : 'it';
    $factorOptions['totp'] = !empty($pendingFactors['two_factor_enabled']);
    $factorOptions['email'] = !empty($pendingFactors['two_factor_email_enabled']);
    $factorStmt = $db->prepare('SELECT COUNT(*) AS total FROM rena_passkeys WHERE user_id = ?');
    $factorStmt->bind_param('i', $pendingUid); $factorStmt->execute(); $factorOptions['passkey'] = (int)$factorStmt->get_result()->fetch_assoc()['total'] > 0; $factorStmt->close();
} else unset($_SESSION['pending_password_login']);

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    if (isset($_GET['cancel_login'])) { unset($_SESSION['pending_password_login']); $factorStep = false; $preferredLanguage = null; }
    $candidate = $_GET['redirect'] ?? $_SERVER['HTTP_REFERER'] ?? '';
    if (isAllowedRedirect($candidate, $whitelist)) {
        $_SESSION['redirect_after_login'] = forceHttps(filter_var($candidate, FILTER_SANITIZE_URL));
    } elseif (empty($_SESSION['redirect_after_login'])) {
        $_SESSION['redirect_after_login'] = 'account.php';
    }
    if (isset($_GET['device_revoked'])) $notice = rui_msg('Questo dispositivo è stato disconnesso. Accedi di nuovo per continuare.', 'This device was signed out. Sign in again to continue.');
    if (isset($_GET['account_deleted'])) $notice = rui_msg('Il tuo account è stato eliminato.', 'Your account has been deleted.');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = (string)($_POST['username'] ?? '');
    $password = (string)($_POST['password'] ?? '');

    if (isset($_POST['request_email_code'])) {
        header('Content-Type: application/json; charset=utf-8');
        $pending = $_SESSION['pending_password_login'] ?? null;
        if (is_array($pending) && (int)($pending['expires_at'] ?? 0) >= time()) {
            $lookup = $db->prepare('SELECT id, username FROM users WHERE id = ?'); $pendingUid = (int)$pending['user_id'];
            $lookup->bind_param('i', $pendingUid); $lookup->execute(); $account = $lookup->get_result()->fetch_assoc(); $lookup->close();
        } else {
            $lookup = $db->prepare('SELECT id, username, password, two_factor_email_enabled FROM users WHERE username = ?');
            $lookup->bind_param('s', $username); $lookup->execute(); $account = $lookup->get_result()->fetch_assoc(); $lookup->close();
            if ($account && (!password_verify($password, $account['password']) || empty($account['two_factor_email_enabled']))) $account = null;
        }
        if (!$account) { http_response_code(401); echo json_encode(['success' => false, 'error' => 'Password non valida oppure verifica via email non attiva']); exit; }
        $response = rena_send_login_email_code($db, (int)$account['id'], (string)$account['username']);
        if (!$response['success']) http_response_code(400);
        echo json_encode($response, JSON_UNESCAPED_UNICODE); exit;
    }

    $isSecondStep = !empty($_POST['complete_login']);
    if ($isSecondStep) {
        $pending = $_SESSION['pending_password_login'] ?? null;
        if (!is_array($pending) || (int)($pending['expires_at'] ?? 0) < time()) { unset($_SESSION['pending_password_login']); $user = null; $passwordValid = false; }
        else { $pendingUid = (int)$pending['user_id']; $lookup = $db->prepare('SELECT id, username, two_factor_enabled, two_factor_secret, two_factor_email_enabled, preferred_language, keep_signed_in FROM users WHERE id = ?'); $lookup->bind_param('i', $pendingUid); $lookup->execute(); $user = $lookup->get_result()->fetch_assoc(); $lookup->close(); $passwordValid = !!$user && (int)$user['id'] === $pendingUid; }
    } else {
        $lookup = $db->prepare('SELECT id, username, password, two_factor_enabled, two_factor_secret, two_factor_email_enabled, preferred_language, keep_signed_in FROM users WHERE username = ?');
        $lookup->bind_param('s', $username); $lookup->execute(); $user = $lookup->get_result()->fetch_assoc(); $lookup->close();
        $passwordValid = !!$user && password_verify($password, $user['password']);
    }
    if ($user && $passwordValid) {
        $accountLanguage = (string)($user['preferred_language'] ?? 'it');
        $preferredLanguage = in_array($accountLanguage, ['it', 'en'], true) ? $accountLanguage : 'it';
        $passkeyCheck = $db->prepare('SELECT COUNT(*) AS total FROM rena_passkeys WHERE user_id = ?'); $passkeyCheck->bind_param('i', $user['id']); $passkeyCheck->execute(); $hasPasskey = (int)$passkeyCheck->get_result()->fetch_assoc()['total'] > 0; $passkeyCheck->close();
        $factorOptions = ['totp' => !empty($user['two_factor_enabled']), 'email' => !empty($user['two_factor_email_enabled']), 'passkey' => $hasPasskey];
        $hasFactor = in_array(true, $factorOptions, true);
        if (!$isSecondStep && $hasFactor) {
            $_SESSION['pending_password_login'] = ['user_id' => (int)$user['id'], 'username' => (string)$user['username'], 'expires_at' => time() + 300];
            $factorStep = true; $factorOk = false;
        } elseif ($isSecondStep) {
            $method = (string)($_POST['login_method'] ?? 'totp');
            if ($method === 'email') $factorOk = $factorOptions['email'] && rena_check_login_email_code((int)$user['id'], (string)$user['username'], (string)($_POST['two_factor_code'] ?? ''));
            elseif ($method === 'totp') $factorOk = $factorOptions['totp'] && rena_totp_valid((string)$user['two_factor_secret'], (string)($_POST['two_factor_code'] ?? ''));
            else $factorOk = false;
        } else $factorOk = true;

        if (!$factorOk) {
            if ($isSecondStep) { $factorStep = true; $error = rui_msg('Codice di verifica non valido o scaduto', 'Invalid or expired verification code'); }
            elseif (!$factorStep) $error = rui_msg('Username o password non validi', 'Incorrect username or password');
        } else {
            unset($_SESSION['pending_password_login']);
            session_regenerate_id(true);
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['rena_preferred_language'] = $preferredLanguage;
            rena_apply_session_persistence($db, (int)$user['id']);
            $_SESSION['device_id'] = rena_device_id($db, (int)$user['id'], true);

            if ($externalUrl) {
                $token = bin2hex(random_bytes(32));
                $_SESSION['cross_domain_token'] = $token;
                rui_register_service_session($db, (int)$user['id'], $token, $externalUrl, (string)($_SESSION['device_id'] ?? ''));

                $profile_photo = null;
                $profile_stmt = $db->prepare('SELECT profile_photo FROM users WHERE id = ?');
                $profile_user_id = (int)$user['id'];
                $profile_stmt->bind_param('i', $profile_user_id); $profile_stmt->execute();
                $profile_data = $profile_stmt->get_result()->fetch_assoc(); $profile_stmt->close();
                if (!empty($profile_data['profile_photo'])) {
                    $photo = (string)$profile_data['profile_photo'];
                    if (filter_var($photo, FILTER_VALIDATE_URL)) $profile_photo = $photo;
                    elseif (strpos($photo, 'uploads/profile_photos/') !== false) $profile_photo = 'https://rena.altervista.org/' . ltrim($photo, '/');
                    else $profile_photo = 'https://rena.altervista.org/uploads/profile_photos/' . $profile_user_id . '/' . ltrim($photo, '/');
                }
                rui_set_lang($preferredLanguage);
                rui_handoff_page([
                    'status' => 'success', 'user_id' => $user['id'], 'username' => $user['username'],
                    'profile_photo' => $profile_photo, 'preferred_language' => $preferredLanguage, 'token' => $token,
                ], $externalUrl, 'login');
            } else {
                $redirect_url = 'account.php';
                if (!empty($_POST['redirect_url']) && isAllowedRedirect($_POST['redirect_url'], $whitelist)) {
                    $redirect_url = $_POST['redirect_url'];
                } elseif (!empty($_SESSION['redirect_after_login']) && isAllowedRedirect($_SESSION['redirect_after_login'], $whitelist)) {
                    $redirect_url = $_SESSION['redirect_after_login'];
                }
                unset($_SESSION['redirect_after_login']);
                header('Location: ' . forceHttps($redirect_url));
                exit();
            }
        }
    } else {
        $error = $isSecondStep
            ? rui_msg('La verifica è scaduta. Inserisci di nuovo la password.', 'Verification expired. Enter your password again.')
            : rui_msg('Username o password non validi', 'Incorrect username or password');
        if ($isSecondStep) { $factorStep = false; }
    }
}
$db->close();

rui_set_lang($preferredLanguage ?? rui_guess_lang());
$pendingName = (string)($_SESSION['pending_password_login']['username'] ?? '');
$isMobileUa = preg_match('/Android|iPhone|iPad|iPod|Mobile/i', (string)($_SERVER['HTTP_USER_AGENT'] ?? '')) === 1;
$hasCode = $factorOptions['totp'] || $factorOptions['email'];
$method = (string)($_POST['login_method'] ?? '');
if (!($method === 'totp' && $factorOptions['totp']) && !($method === 'email' && $factorOptions['email'])) $method = $factorOptions['totp'] ? 'totp' : ($factorOptions['email'] ? 'email' : '');
$cancelQs = http_build_query(array_merge($_GET, ['cancel_login' => 1]));
$redirectValue = $_SESSION['redirect_after_login'] ?? 'account.php';
?>
<!DOCTYPE html>
<html lang="<?= rui_lang() ?>">
<head><?php rui_head('Rena - Accedi a Rena ID', 'Rena - Sign in to Rena ID'); ?></head>
<body class="auth">
<?php rui_sprite(); ?>
<?php if (!$factorStep) rui_lang_switcher(); ?>

<main class="auth-wrap"><div class="card">
  <div class="logo"><?= rui_icon($factorStep ? 'shield-check' : 'id') ?></div>

<?php if (!$factorStep): ?>
  <h1><?= rui_tr('Accedi a Rena ID', 'Sign in to Rena ID') ?></h1>
  <p class="subtitle">
    <?php if ($serviceName): ?><?= rui_tr('per continuare su ', 'to continue to ') ?><strong><?= rui_h($serviceName) ?></strong>
    <?php else: ?><?= rui_tr('Usa il tuo username e la tua password.', 'Use your username and password.') ?><?php endif; ?>
  </p>

  <?php if ($notice): ?><div class="alert" role="status"><?= rui_icon('info') ?><span data-msg='<?= rui_h(json_encode($notice, JSON_UNESCAPED_UNICODE)) ?>'><?= rui_h(rui_pick($notice)) ?></span></div><?php endif; ?>
  <?php if ($error): ?><div class="alert alert-error" role="alert"><?= rui_icon('alert-circle') ?><span data-msg='<?= rui_h(json_encode($error, JSON_UNESCAPED_UNICODE)) ?>'><?= rui_h(rui_pick($error)) ?></span></div><?php endif; ?>

  <form method="post" action="" data-busy>
    <input type="hidden" name="redirect_url" value="<?= rui_h($redirectValue) ?>">
    <div class="field">
      <label for="username">Username</label>
      <div class="input"><input type="text" id="username" name="username" required autocomplete="username" autocapitalize="none" spellcheck="false" autofocus value="<?= rui_h($_POST['username'] ?? '') ?>" <?= rui_ph('Il tuo username', 'Your username') ?>></div>
    </div>
    <div class="field">
      <label for="password">Password</label>
      <div class="input"><input type="password" id="password" name="password" required autocomplete="current-password" <?= rui_ph('La tua password', 'Your password') ?>></div>
      <div class="field-row"><span></span><a href="password-forgot.php" class="link" style="display:inline-flex;align-items:center;gap:6px"><svg class="icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" width="16" height="16" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M22 8.29344C22 11.7692 19.1708 14.5869 15.6807 14.5869C15.0439 14.5869 13.5939 14.4405 12.8885 13.8551L12.0067 14.7333C11.4883 15.2496 11.6283 15.4016 11.8589 15.652C11.9551 15.7565 12.0672 15.8781 12.1537 16.0505C12.1537 16.0505 12.8885 17.075 12.1537 18.0995C11.7128 18.6849 10.4783 19.5045 9.06754 18.0995L8.77362 18.3922C8.77362 18.3922 9.65538 19.4167 8.92058 20.4412C8.4797 21.0267 7.30403 21.6121 6.27531 20.5876L5.2466 21.6121C4.54119 22.3146 3.67905 21.9048 3.33616 21.6121L2.45441 20.7339C1.63143 19.9143 2.1115 19.0264 2.45441 18.6849L10.0963 11.0743C10.0963 11.0743 9.3615 9.90338 9.3615 8.29344C9.3615 4.81767 12.1907 2 15.6807 2C19.1708 2 22 4.81767 22 8.29344ZM15.681 10.4889C16.8984 10.4889 17.8853 9.50601 17.8853 8.29353C17.8853 7.08105 16.8984 6.09814 15.681 6.09814C14.4635 6.09814 13.4766 7.08105 13.4766 8.29353C13.4766 9.50601 14.4635 10.4889 15.681 10.4889Z" fill="currentColor"></path></svg><?= rui_tr('Password dimenticata?', 'Forgot your password?') ?></a></div>
    </div>
    <button type="submit" class="btn"><?= rui_tr('Accedi', 'Sign in') ?></button>
    <?php if (!$isMobileUa): ?>
    <div class="divider qr-only"><?= rui_tr('oppure', 'or') ?></div>
    <button type="button" class="btn btn-ghost qr-only" id="qrStart"><?= rui_icon('qr') ?><?= rui_tr('Accedi con il telefono', 'Sign in with your phone') ?></button>
    <?php endif; ?>
    <p class="foot"><?= rui_tr('Non hai un account?', "Don't have an account?") ?> <a href="register.php<?= $externalUrl ? '?external_domain=' . rawurlencode($externalUrl) : '' ?>"><?= rui_tr('Registrati', 'Sign up') ?></a></p>
  </form>

<?php else: ?>
  <h1><?= rui_te('Verifica in due passaggi', 'Two-step verification') ?></h1>
  <p class="subtitle"><?= rui_te('Password verificata per ', 'Password verified for ') ?><strong><?= rui_h($pendingName) ?></strong>. <?= rui_te('Conferma che sei tu per completare l’accesso.', 'Confirm it’s you to finish signing in.') ?></p>
  <?php if ($error): ?><div class="alert alert-error" role="alert"><?= rui_icon('alert-circle') ?><span><?= rui_h(rui_pick($error)) ?></span></div><?php endif; ?>

  <form method="post" action="" id="factorForm" data-busy>
    <input type="hidden" name="complete_login" value="1">
    <input type="hidden" name="username" value="<?= rui_h($pendingName) ?>">
    <input type="hidden" name="redirect_url" value="<?= rui_h($redirectValue) ?>">
    <?php if ($factorOptions['totp'] && $factorOptions['email']): ?>
      <div class="seg" role="radiogroup" aria-label="<?= rui_h(rui_t('Metodo di verifica', 'Verification method')) ?>">
        <label><input type="radio" name="login_method" value="totp" <?= $method === 'totp' ? 'checked' : '' ?>><span><?= rui_te('App di autenticazione', 'Authenticator app') ?></span></label>
        <label><input type="radio" name="login_method" value="email" <?= $method === 'email' ? 'checked' : '' ?>><span><?= rui_te('Codice via email', 'Email code') ?></span></label>
      </div>
    <?php elseif ($hasCode): ?>
      <input type="hidden" name="login_method" value="<?= rui_h($method) ?>">
    <?php endif; ?>

    <?php if ($hasCode): ?>
    <div class="field">
      <label for="two_factor_code"><?= rui_te('Codice a 6 cifre', '6-digit code') ?></label>
      <div class="input"><input type="text" class="otp" id="two_factor_code" name="two_factor_code" required inputmode="numeric" maxlength="6" pattern="[0-9]{6}" autocomplete="one-time-code" placeholder="000000" data-otp data-autosubmit autofocus></div>
      <p class="hint" id="methodHint"></p>
    </div>
    <?php if ($factorOptions['email']): ?>
    <div class="field" id="emailSend" hidden>
      <button type="button" class="btn btn-ghost" id="sendEmailCode"><?= rui_icon('mail') ?><span><?= rui_te('Invia il codice via email', 'Send the code by email') ?></span></button>
      <p class="hint" id="emailStatus" role="status" aria-live="polite"></p>
    </div>
    <?php endif; ?>
    <button type="submit" class="btn"><?= rui_icon('check') ?><?= rui_te('Verifica e accedi', 'Verify and sign in') ?></button>
    <?php endif; ?>

    <?php if ($factorOptions['passkey']): ?>
      <?php if ($hasCode): ?><div class="divider"><?= rui_te('oppure', 'or') ?></div><?php endif; ?>
      <button type="button" class="btn <?= $hasCode ? 'btn-ghost' : '' ?>" id="passkeyBtn"><svg class="icon" width="18" height="18" style="flex-shrink:0" fill="currentColor" viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M63.28,202a15.29,15.29,0,0,1-7.7-2,14.84,14.84,0,0,1-5.52-20.46C69.34,147.36,128,72.25,256,72.25c55.47,0,104.12,14.57,144.53,43.29,33.26,23.57,51.9,50.25,60.78,63.1a14.79,14.79,0,0,1-4,20.79,15.52,15.52,0,0,1-21.24-4C420,172.32,371,102,256,102c-112.25,0-163,64.71-179.53,92.46A15,15,0,0,1,63.28,202Z"></path><path d="M320.49,496a15.31,15.31,0,0,1-3.79-.43c-92.85-23-127.52-115.82-128.93-119.68l-.22-.85c-.76-2.68-19.39-66.33,9.21-103.61,13.11-17,33.05-25.72,59.38-25.72,24.48,0,42.14,7.61,54.28,23.36,10,12.86,14,28.72,17.87,44,8.13,31.82,14,48.53,47.79,50.25,14.84.75,24.59-7.93,30.12-15.32,14.95-20.15,17.55-53,6.28-82C398,228.57,346.61,158,256,158c-38.68,0-74.22,12.43-102.72,35.79C129.69,213.14,111,240.46,102,268.54c-16.69,52.28,5.2,134.46,5.41,135.21A14.83,14.83,0,0,1,96.54,422a15.39,15.39,0,0,1-18.74-10.6c-1-3.75-24.38-91.4-5.1-151.82,21-65.47,85.81-131.47,183.33-131.47,45.07,0,87.65,15.32,123.19,44.25,27.52,22.5,50,52.72,61.76,82.93,14.95,38.57,10.94,81.86-10.19,110.14-14.08,18.86-34.13,28.72-56.34,27.65-57.86-2.9-68.26-43.29-75.84-72.75-7.8-30.22-12.79-44.79-42.58-44.79-16.36,0-27.85,4.5-35,13.82-9.75,12.75-10.51,32.68-9.43,47.14a152.44,152.44,0,0,0,5.1,29.79c2.38,6,33.37,82,107.59,100.39a14.88,14.88,0,0,1,11,18.11A15.36,15.36,0,0,1,320.49,496Z"></path><path d="M201.31,489.14a15.5,15.5,0,0,1-11.16-4.71c-37.16-39-58.18-82.61-66.09-137.14V347c-4.44-36.1,2.06-87.21,33.91-122.35,23.51-25.93,56.56-39.11,98.06-39.11,49.08,0,87.65,22.82,111.7,65.89,17.45,31.29,20.91,62.47,21,63.75a15.07,15.07,0,0,1-13.65,16.4,15.26,15.26,0,0,1-16.79-13.29h0A154,154,0,0,0,340.43,265c-18.64-32.89-47-49.61-84.51-49.61-32.4,0-57.75,9.75-75.19,29-25.14,27.75-30,70.5-26.55,98.78,6.93,48.22,25.46,86.58,58.18,120.86a14.7,14.7,0,0,1-.76,21.11A15.44,15.44,0,0,1,201.31,489.14Z"></path><path d="M372.5,446.18c-32.5,0-60.13-9-82.24-26.89-44.42-35.79-49.4-94.08-49.62-96.54a15.27,15.27,0,0,1,30.45-2.36c.11.86,4.55,48.54,38.79,76,20.26,16.18,47.34,22.6,80.71,18.85a15.2,15.2,0,0,1,16.91,13.18,14.92,14.92,0,0,1-13.44,16.5A187,187,0,0,1,372.5,446.18Z"></path><path d="M398.18,48.79C385.5,40.54,340.54,16,256,16c-88.74,0-133.81,27.11-143.78,34a11.59,11.59,0,0,0-1.84,1.4.36.36,0,0,1-.22.1,14.87,14.87,0,0,0-5.09,11.15A15.06,15.06,0,0,0,120.38,77.5a15.56,15.56,0,0,0,8.88-2.79c.43-.32,39.22-28.82,126.77-28.82S382.58,74.29,383,74.5a15.25,15.25,0,0,0,9.21,3A15.06,15.06,0,0,0,407.5,62.61,14.9,14.9,0,0,0,398.18,48.79Z"></path></svg><?= rui_te('Verifica con passkey', 'Verify with passkey') ?></button>
    <?php endif; ?>
    <p class="foot"><a href="login.php?<?= rui_h($cancelQs) ?>"><?= rui_icon('arrow-left') ?> <?= rui_te('Usa un altro account', 'Use another account') ?></a></p>
  </form>
<?php endif; ?>
</div></main>

<?php if (!$factorStep && !$isMobileUa): ?>
<dialog id="qrDialog" aria-labelledby="qrTitle"><div class="dlg" style="text-align:center">
  <button type="button" class="dlg-close" data-close aria-label="<?= rui_h(rui_t('Chiudi', 'Close')) ?>"><?= rui_icon('x') ?></button>
  <h2 id="qrTitle" style="margin-right:0" data-translate-it="Accedi con il telefono" data-translate-en="Sign in with your phone"><?= rui_te('Accedi con il telefono', 'Sign in with your phone') ?></h2>
  <ol class="qr-steps" style="margin-top:14px">
    <li><?= rui_tr('Apri Rena ID sul telefono dove hai già effettuato l’accesso', 'Open Rena ID on a phone where you are already signed in') ?></li>
    <li><?= rui_tr('Scansiona questo codice con la fotocamera', 'Scan this code with the camera') ?></li>
    <li><?= rui_tr('Approva la richiesta: qui l’accesso parte da solo', 'Approve the request — you will be signed in here automatically') ?></li>
  </ol>
  <div class="qr-box" id="qrCode"><?= rui_icon('loader', 'spin') ?></div>
  <p class="hint" id="qrStatus" role="status" aria-live="polite" style="text-align:center"></p>
  <button type="button" class="btn btn-ghost" id="qrRetry" hidden><?= rui_icon('refresh') ?><?= rui_tr('Genera un nuovo codice', 'Generate a new code') ?></button>
</div></dialog>
<?php endif; ?>

<?php rui_context_menu(); rui_scripts(); ?>
<script src="https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js"></script>
<script>
(function () {
  var R = RenaUI, $ = R.$;
  var factorStep = <?= $factorStep ? 'true' : 'false' ?>;
  R.initLang(<?= json_encode(rui_lang()) ?>, factorStep);
  var ext = <?= json_encode((string)$externalUrl) ?>;

  var pw = $('#password');
  if (pw) pw.parentElement.append(R.pwToggle());
  document.addEventListener('rena:lang', function () {
    R.$$('[data-msg]').forEach(function (e) { try { e.textContent = R.pick(JSON.parse(e.dataset.msg)); } catch (x) {} });
    updateMethod();
  });

  function finish(data) {
    if (data.external_data) {
      if (window.opener) { window.opener.postMessage(data.external_data, data.external_origin); window.close(); }
      else location.href = data.external_origin + '?token=' + encodeURIComponent(data.external_data.token) + '&user_id=' + encodeURIComponent(data.external_data.user_id) + '&username=' + encodeURIComponent(data.external_data.username);
    } else location.href = data.redirect || 'account.php';
  }

  var form = $('#factorForm');
  function currentMethod() { var r = form && form.querySelector('[name=login_method]:checked'); var h = form && form.querySelector('input[type=hidden][name=login_method]'); return r ? r.value : (h ? h.value : ''); }
  function updateMethod() {
    if (!form) return;
    var m = currentMethod(), hint = $('#methodHint'), send = $('#emailSend');
    if (hint) hint.textContent = m === 'email' ? R.t('Controlla la tua casella email e inserisci il codice ricevuto.', 'Check your inbox and enter the code we sent you.') : R.t('Apri la tua app di autenticazione e inserisci il codice mostrato.', 'Open your authenticator app and enter the code it shows.');
    if (send) send.hidden = m !== 'email';
  }
  if (form) {
    form.addEventListener('change', updateMethod); updateMethod();
    var send = $('#sendEmailCode'), cooldown = 0;
    if (send) send.addEventListener('click', function () {
      var fd = new FormData(form); fd.set('request_email_code', '1'); fd.set('login_method', 'email');
      var status = $('#emailStatus'); R.busy(send, true); status.textContent = '';
      fetch(location.href, { method: 'POST', body: fd, credentials: 'same-origin', cache: 'no-store' })
        .then(function (r) { return r.json().then(function (d) { if (!r.ok || !d.success) throw new Error(d.error || R.t('Invio non riuscito', 'Could not send the code')); return d; }); })
        .then(function (d) {
          status.textContent = d.message || R.t('Codice inviato. Controlla la tua email.', 'Code sent. Check your email.');
          $('#two_factor_code').focus(); cooldown = 30;
          var span = send.querySelector('span'), label = span.textContent, tick = setInterval(function () {
            cooldown--; if (cooldown <= 0) { clearInterval(tick); span.textContent = label; send.disabled = false; return; }
            span.textContent = R.t('Reinvia tra ', 'Resend in ') + cooldown + 's';
          }, 1000);
        })
        .catch(function (e) { status.textContent = e.message; })
        .finally(function () { R.busy(send, false); if (cooldown > 0) send.disabled = true; });
    });
    var pk = $('#passkeyBtn');
    if (pk) pk.addEventListener('click', function () {
      R.busy(pk, true);
      R.passkeyLogin('passkey.php', { action: 'password_factor_options', external_domain: ext })
        .then(finish)
        .catch(function (e) { R.toast(e.message || R.t('Accesso con passkey non riuscito', 'Passkey sign-in failed'), 'error'); })
        .finally(function () { R.busy(pk, false); });
    });
  }

  var qrBtn = $('#qrStart'); if (!qrBtn) return;
  var dlg = $('#qrDialog'), box = $('#qrCode'), status = $('#qrStatus'), retry = $('#qrRetry');
  var poll = null, tick = null, token = null, deadline = 0;
  function stop() { clearInterval(poll); clearInterval(tick); token = null; }
  function expired(msg) { stop(); box.replaceChildren(R.icon('x')); status.textContent = msg || R.t('Codice scaduto.', 'Code expired.'); retry.hidden = false; }
  function start() {
    stop(); retry.hidden = true; box.replaceChildren(R.icon('loader', 'spin')); status.textContent = R.t('Preparazione del codice…', 'Preparing the code…');
    if (typeof qrcode !== 'function') return expired(R.t('Impossibile caricare il generatore di QR. Riprova.', 'Could not load the QR generator. Try again.'));
    R.api('qr-login.php', { action: 'create', external_domain: ext }).then(function (d) {
      token = d.token; deadline = Date.now() + d.expires_in * 1000;
      var qr = qrcode(0, 'M'); qr.addData(location.origin + '/qr-approve.php?token=' + encodeURIComponent(token)); qr.make();
      box.innerHTML = qr.createImgTag(5, 4, R.t('Codice QR per accedere a Rena ID', 'QR code to sign in to Rena ID'));
      tick = setInterval(function () {
        var s = Math.max(0, Math.round((deadline - Date.now()) / 1000));
        if (s <= 0) return expired();
        status.textContent = R.t('In attesa di approvazione dal telefono · scade tra ', 'Waiting for approval on your phone · expires in ') + Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
      }, 1000);
      poll = setInterval(check, 2000);
    }).catch(function (e) { expired(e.message); });
  }
  function check() {
    if (!token) return;
    fetch('qr-login.php', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action: 'poll', token: token }), cache: 'no-store' })
      .then(function (r) { return r.json().then(function (d) { return [r, d]; }); })
      .then(function (a) {
        var r = a[0], d = a[1];
        if (d.success && d.status === 'approved') { stop(); status.textContent = R.t('Approvato! Accesso in corso…', 'Approved! Signing you in…'); finish(d); }
        else if (!r.ok) expired(d.error);
      }).catch(function () {});
  }
  qrBtn.addEventListener('click', function () { dlg.showModal(); start(); });
  retry.addEventListener('click', start);
  dlg.addEventListener('close', stop);
})();
</script>
</body>
</html>

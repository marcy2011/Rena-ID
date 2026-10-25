<?php
require_once __DIR__ . '/rena-session.php';
rena_session_start();
require_once __DIR__ . '/config_id.php';
require_once __DIR__ . '/rena-security.php';
require_once __DIR__ . '/rena-ui.php';

$token = (string)($_GET['token'] ?? '');
$validToken = preg_match('/^[a-f0-9]{64}$/', $token) === 1;
$uid = (int)($_SESSION['user_id'] ?? 0);
if (!$uid) {
    $return = 'https://rena.altervista.org/qr-approve.php?token=' . rawurlencode($token);
    header('Location: login.php?redirect=' . rawurlencode($return)); exit;
}
$db = db();
rena_security_schema($db);
$stmt = $db->prepare('SELECT username, preferred_language FROM users WHERE id = ?'); $stmt->bind_param('i', $uid); $stmt->execute(); $account = $stmt->get_result()->fetch_assoc(); $stmt->close();
if (!$account) { http_response_code(401); exit('Sessione Rena ID non valida'); }
$preferredLanguage = in_array(($account['preferred_language'] ?? 'it'), ['it', 'en'], true) ? (string)$account['preferred_language'] : 'it';
rui_set_lang($preferredLanguage);
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Referrer-Policy: no-referrer');
?>
<!DOCTYPE html>
<html lang="<?= rui_lang() ?>">
<head><?php rui_head('Approva accesso · Rena ID', 'Approve sign-in · Rena ID'); ?></head>
<body class="auth">
<?php rui_sprite(); ?>
<main class="auth-wrap"><div class="card wide">

  <section id="viewAsk">
    <div class="logo"><?= rui_icon('shield-check') ?></div>
    <h1><?= rui_te('Vuoi accedere su un altro dispositivo?', 'Sign in on another device?') ?></h1>
    <p class="subtitle"><?= rui_te('Qualcuno ha richiesto di accedere a Rena ID da questo dispositivo:', 'Someone asked to sign in to Rena ID from this device:') ?></p>

    <div class="device-box" id="device" aria-live="polite">
      <?= rui_icon('monitor') ?>
      <div><strong id="deviceName"><?= rui_te('Verifica richiesta…', 'Checking request…') ?></strong><small id="deviceIp"></small></div>
    </div>

    <p class="hint" style="text-align:center;margin:-4px 0 18px">
      <?= rui_te('Account: ', 'Account: ') ?><strong style="color:#fff"><?= rui_h($account['username']) ?></strong>
    </p>

    <div class="alert" id="askWarn"><?= rui_icon('alert-circle') ?><span><?= rui_te('Approva solo se hai appena aperto Rena ID su questo computer. Se non sei stato tu, non approvare.', 'Only approve if you just opened Rena ID on that computer. If it wasn’t you, don’t approve.') ?></span></div>
    <div class="alert alert-error" id="askError" role="alert" hidden><?= rui_icon('alert-circle') ?><span id="askErrorText"></span></div>

    <button id="approve" type="button" class="btn" disabled><?= rui_icon('check') ?><?= rui_te('Approva accesso', 'Approve sign-in') ?></button>
    <a class="btn btn-ghost" id="deny" href="https://rena.altervista.org/account.php"><?= rui_te('Non sono stato io', 'It wasn’t me') ?></a>
  </section>

  <section id="viewDone" hidden role="status" aria-live="polite">
    <div class="logo ok"><?= rui_icon('check-circle') ?></div>
    <h1><?= rui_te('Accesso approvato', 'Sign-in approved') ?></h1>
    <p class="subtitle"><?= rui_te('Puoi tornare al computer: l’accesso verrà completato automaticamente.', 'Go back to your computer — sign-in will finish automatically.') ?></p>
    <a class="btn btn-ghost" href="https://rena.altervista.org/account.php"><?= rui_icon('user') ?><?= rui_te('Apri il tuo account', 'Open your account') ?></a>
  </section>

  <section id="viewError" hidden role="alert">
    <div class="logo"><?= rui_icon('alert-circle') ?></div>
    <h1 id="errTitle"><?= rui_te('Codice non valido', 'Invalid code') ?></h1>
    <p class="subtitle" id="errText"></p>
    <a class="btn btn-ghost" href="https://rena.altervista.org/account.php"><?= rui_te('Vai al tuo account', 'Go to your account') ?></a>
  </section>

</div></main>
<?php rui_scripts(); ?>
<script>
(function () {
  var R = RenaUI, $ = R.$;
  R.initLang(<?= json_encode($preferredLanguage) ?>, true);
  var qrToken = <?= json_encode($token) ?>, valid = <?= $validToken ? 'true' : 'false' ?>, csrf = '';
  var approve = $('#approve');

  function show(id) { ['viewAsk', 'viewDone', 'viewError'].forEach(function (v) { $('#' + v).hidden = v !== id; }); }
  function fail(title, text) { $('#errTitle').textContent = title; $('#errText').textContent = text; show('viewError'); }
  function send(payload) {
    return fetch('qr-login.php', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), cache: 'no-store' })
      .then(function (r) { return r.json().then(function (d) { if (!r.ok || !d.success) { var e = new Error(d.error || R.t('Richiesta non riuscita', 'Request failed')); e.expired = !!d.expired; throw e; } return d; }); });
  }

  if (!valid) { fail(R.t('Codice QR non valido', 'Invalid QR code'), R.t('Torna al computer e genera un nuovo codice dalla pagina di accesso.', 'Go back to your computer and generate a new code from the sign-in page.')); return; }

  send({ action: 'approve_info', token: qrToken }).then(function (d) {
    csrf = d.csrf;
    $('#deviceName').textContent = d.device_name;
    $('#deviceIp').textContent = d.ip_address ? 'IP ' + d.ip_address : '';
    approve.disabled = false; approve.focus();
  }).catch(function (e) {
    if (e.expired) fail(R.t('Codice scaduto', 'Code expired'), R.t('Il codice è scaduto o è già stato usato. Genera un nuovo codice sul computer.', 'This code expired or was already used. Generate a new one on your computer.'));
    else fail(R.t('Impossibile verificare la richiesta', 'Could not check the request'), e.message);
  });

  approve.addEventListener('click', function () {
    R.busy(approve, true); $('#askError').hidden = true;
    send({ action: 'approve', token: qrToken, csrf: csrf }).then(function () { show('viewDone'); })
      .catch(function (e) {
        R.busy(approve, false);
        if (e.expired) return fail(R.t('Codice scaduto', 'Code expired'), R.t('Il codice è scaduto. Genera un nuovo codice sul computer.', 'The code expired. Generate a new one on your computer.'));
        $('#askErrorText').textContent = e.message; $('#askError').hidden = false;
      });
  });
})();
</script>
</body>
</html>

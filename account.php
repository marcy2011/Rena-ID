<?php

require_once __DIR__ . '/rena-session.php';

rena_session_start();

if (!isset($_SESSION['user_id'])) {
  header("Location: login.php");
  exit();
}

require __DIR__ . '/config_id.php';
require_once __DIR__ . '/rena-security.php';
require_once __DIR__ . '/rena-ui.php';

try {
  $db = db();
} catch (mysqli_sql_exception $e) {
  error_log("Database connection error: " . $e->getMessage());
  http_response_code(500);
  exit("Errore di connessione al database. Riprova più tardi.");
}

mysqli_report(MYSQLI_REPORT_OFF);
rena_security_schema($db);

$cookie_device_id = (string)($_COOKIE['rena_device_id'] ?? '');
if (preg_match('/^[a-f0-9]{32}$/', $cookie_device_id)) {
  $device_check = $db->prepare('SELECT revoked_at FROM rena_device_sessions WHERE device_id = ? AND user_id = ?');
  $device_check->bind_param('si', $cookie_device_id, $_SESSION['user_id']);
  $device_check->execute();
  $device_row = $device_check->get_result()->fetch_assoc();
  $device_check->close();

  if ($device_row && !empty($device_row['revoked_at'])) {
    $_SESSION = [];
    session_destroy();
    header('Location: login.php?device_revoked=1');
    exit();
  }
}

$current_device_id = rena_device_id($db, (int)$_SESSION['user_id']);
$_SESSION['device_id'] = $current_device_id;

$user_id = (int) $_SESSION['user_id'];
$error = null;
$errPanel = '';
$flash = $_SESSION['account_flash'] ?? null;
unset($_SESSION['account_flash']);

$langStmt = $db->prepare('SELECT preferred_language FROM users WHERE id = ?');
$langStmt->bind_param('i', $user_id);
$langStmt->execute();
$langRow = $langStmt->get_result()->fetch_assoc();
$langStmt->close();

$storedLanguage = (string)($langRow['preferred_language'] ?? 'it');
$preferredLanguage = in_array($storedLanguage, ['it', 'en'], true) ? $storedLanguage : 'it';
rui_set_lang($preferredLanguage);

if (empty($_SESSION['account_csrf'])) {
  $_SESSION['account_csrf'] = bin2hex(random_bytes(16));
}
$csrf = $_SESSION['account_csrf'];

function flash_redirect(array $msg, string $anchor = ''): void
{
  $_SESSION['account_flash'] = $msg;
  header('Location: account.php' . ($anchor !== '' ? '#' . $anchor : ''));
  exit();
}

function versionOf($path)
{
  return preg_match('/^v(\d+)\./', basename($path), $m) ? (int) $m[1] : 0;
}

function findLatestPhoto($user_id)
{
  $files = glob("uploads/profile_photos/{$user_id}/v*.*");
  if (!$files) {
    return null;
  }
  usort($files, function ($a, $b) {
    return versionOf($b) - versionOf($a);
  });
  return $files[0];
}

function getLatestProfilePhoto($user_id, $db)
{
  $stmt = $db->prepare("SELECT profile_photo FROM users WHERE id = ?");
  $stmt->bind_param("i", $user_id);
  $stmt->execute();
  $row = $stmt->get_result()->fetch_assoc();

  if (!empty($row['profile_photo']) && is_file($row['profile_photo'])) {
    return $row['profile_photo'];
  }
  return findLatestPhoto($user_id);
}

function convertToWebP($source, $mime, $destination)
{
  if (!function_exists('imagewebp')) {
    return false;
  }

  switch ($mime) {
    case 'image/jpeg':
      $image = @imagecreatefromjpeg($source);
      break;
    case 'image/png':
      $image = @imagecreatefrompng($source);
      break;
    case 'image/gif':
      $image = @imagecreatefromgif($source);
      break;
    default:
      $image = false;
  }

  if (!$image) {
    return false;
  }

  imagepalettetotruecolor($image);
  imagealphablending($image, true);
  imagesavealpha($image, true);
  $ok = imagewebp($image, $destination, 80);
  imagedestroy($image);

  return $ok;
}

function deleteUserPhotos($user_id)
{
  $dir = "uploads/profile_photos/{$user_id}";
  if (!is_dir($dir)) {
    return;
  }
  foreach (glob($dir . "/*") ?: [] as $file) {
    if (is_file($file)) {
      unlink($file);
    }
  }
  rmdir($dir);
}

function acct_alert(string $panel): void
{
  global $error, $errPanel;
  if ($error && $errPanel === $panel) {
    echo '<div class="alert alert-error" role="alert">'
      . rui_icon('alert-circle')
      . '<span>' . rui_h(rui_pick($error)) . '</span></div>';
  }
}

$postedUsername = trim((string)($_POST['username'] ?? ''));
$postedEmail = trim((string)($_POST['email'] ?? ''));

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  if (!hash_equals($csrf, (string)($_POST['csrf'] ?? ''))) {
    $error = rui_msg('Sessione scaduta. Ricarica la pagina e riprova.', 'Session expired. Reload the page and try again.');

  } elseif (isset($_POST['update_language'])) {
    $preferred_language = (string)($_POST['preferred_language'] ?? '');

    if (!in_array($preferred_language, ['it', 'en'], true)) {
      $error = rui_msg('Seleziona una lingua valida.', 'Choose a valid language.');
      $errPanel = 'preferences';
    } else {
      $language_stmt = $db->prepare('UPDATE users SET preferred_language = ? WHERE id = ?');
      $language_stmt->bind_param('si', $preferred_language, $user_id);

      if ($language_stmt->execute()) {
        $_SESSION['rena_preferred_language'] = $preferred_language;
        flash_redirect(
          $preferred_language === 'it'
            ? rui_msg('Lingua aggiornata.', 'Lingua aggiornata.')
            : rui_msg('Language updated.', 'Language updated.'),
          'preferences'
        );
      }

      $error = rui_msg('Non è stato possibile aggiornare la lingua.', 'Could not update the language.');
      $errPanel = 'preferences';
      $language_stmt->close();
    }

  } elseif (isset($_POST['update_app_token_policy'])) {
    $policyClient = (string)($_POST['client_id'] ?? '');

    if (!preg_match('/^[A-Za-z0-9_.\-]{1,128}$/', $policyClient)) {
      $error = rui_msg('App non valida.', 'Invalid app.');
      $errPanel = 'apps';
    } else {
      $policyNever = !empty($_POST['token_never_expires']);

      if (rena_oauth_set_policy($db, $user_id, $policyClient, $policyNever)) {
        flash_redirect(
          $policyNever
            ? rui_msg('Il token di questa app non scadrà.', 'This app’s token will not expire.')
            : rui_msg('Il token di questa app scadrà dopo 30 giorni.', 'This app’s token will expire after 30 days.'),
          'apps'
        );
      }

      $error = rui_msg('Non è stato possibile aggiornare l’impostazione.', 'Could not update the setting.');
      $errPanel = 'apps';
    }

  } elseif (isset($_POST['update_session_preference'])) {
    $keepSignedIn = isset($_POST['keep_signed_in']) ? 1 : 0;
    $preferenceStmt = $db->prepare('UPDATE users SET keep_signed_in = ? WHERE id = ?');
    $preferenceStmt->bind_param('ii', $keepSignedIn, $user_id);

    if ($preferenceStmt->execute()) {
      rena_apply_session_persistence($db, $user_id);
      flash_redirect(
        $keepSignedIn
          ? rui_msg('Resterai connesso su questo dispositivo per 30 giorni di inattività.', 'You will stay signed in on this device for 30 days of inactivity.')
          : rui_msg('Ora la sessione scade automaticamente.', 'Your session will now expire automatically.'),
        'preferences'
      );
    }

    $error = rui_msg('Non è stato possibile aggiornare la preferenza.', 'Could not update the preference.');
    $errPanel = 'preferences';
    $preferenceStmt->close();

  } elseif (isset($_POST['update_profile']) || isset($_POST['change_password'])) {
    $isPasswordForm = isset($_POST['change_password']);
    $panel = $isPasswordForm ? 'passwordDialog' : 'profile';
    $current_password = (string)($_POST['current_password'] ?? '');

    $stmt = $db->prepare("SELECT username, email, password FROM users WHERE id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $cur = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$cur || !password_verify($current_password, $cur['password'])) {
      $error = rui_msg('Password attuale non corretta.', 'Current password is incorrect.');
      $errPanel = $panel;

    } elseif ($isPasswordForm) {
      $new_password = (string)($_POST['new_password'] ?? '');

      if ($new_password !== (string)($_POST['confirm_password'] ?? '')) {
        $error = rui_msg('Le nuove password non coincidono.', 'The new passwords do not match.');
        $errPanel = $panel;
      } elseif ($problem = rui_password_problem($new_password)) {
        $error = $problem;
        $errPanel = $panel;
      } else {
        $hash = password_hash($new_password, PASSWORD_DEFAULT);
        $stmt = $db->prepare("UPDATE users SET password = ? WHERE id = ?");
        $stmt->bind_param("si", $hash, $user_id);

        if ($stmt->execute()) {
          flash_redirect(rui_msg('Password cambiata.', 'Password changed.'), 'security');
        }

        error_log("Password update error: " . $stmt->error);
        $error = rui_msg('Errore durante il cambio password.', 'Could not change your password.');
        $errPanel = $panel;
      }

    } else {
      $new_username = $postedUsername;
      $new_email = $postedEmail;
      $updates = [];
      $types = '';
      $values = [];

      if ($new_username === '') {
        $error = rui_msg('Lo username non può essere vuoto.', 'Username can’t be empty.');
      } elseif ($new_username !== $cur['username']) {
        $len = mb_strlen($new_username);

        if ($len < 3 || $len > 30 || !preg_match('/^[\p{L}\p{N}._-]+$/u', $new_username)) {
          $error = rui_msg(
            'Lo username deve avere da 3 a 30 caratteri: lettere, numeri, punto, trattino o underscore.',
            'Username must be 3–30 characters: letters, numbers, dot, hyphen or underscore.'
          );
        } else {
          $stmt = $db->prepare("SELECT id FROM users WHERE username = ? AND id != ?");
          $stmt->bind_param("si", $new_username, $user_id);
          $stmt->execute();

          if ($stmt->get_result()->num_rows > 0) {
            $error = rui_msg('Username già in uso.', 'Username already taken.');
          } else {
            $updates[] = 'username = ?';
            $types .= 's';
            $values[] = $new_username;
          }
          $stmt->close();
        }
      }

      if (!$error && $new_email !== '' && $new_email !== (string)$cur['email']) {
        if (!filter_var($new_email, FILTER_VALIDATE_EMAIL)) {
          $error = rui_msg('Indirizzo email non valido.', 'Invalid email address.');
        } else {
          $stmt = $db->prepare("SELECT id FROM users WHERE email = ? AND id != ?");
          $stmt->bind_param("si", $new_email, $user_id);
          $stmt->execute();

          if ($stmt->get_result()->num_rows > 0) {
            $error = rui_msg('Questa email è già associata a un altro account.', 'This email is already linked to another account.');
          } else {
            $updates[] = 'email = ?';
            $types .= 's';
            $values[] = $new_email;
          }
          $stmt->close();
        }
      }

      if ($error) {
        $errPanel = 'profile';
      } elseif (!$updates) {
        flash_redirect(rui_msg('Nessuna modifica da salvare.', 'There are no changes to save.'), 'profile');
      } else {
        $types .= 'i';
        $values[] = $user_id;

        $stmt = $db->prepare("UPDATE users SET " . implode(', ', $updates) . " WHERE id = ?");
        $stmt->bind_param($types, ...$values);

        if ($stmt->execute()) {
          if ($new_username !== '' && $new_username !== $cur['username']) {
            $_SESSION['username'] = $new_username;
          }
          flash_redirect(rui_msg('Profilo aggiornato.', 'Profile updated.'), 'profile');
        }

        error_log("Profile update error: " . $stmt->error);
        $error = rui_msg('Errore nell’aggiornamento del profilo.', 'Could not update your profile.');
        $errPanel = 'profile';
      }
    }

  } elseif (isset($_POST['upload_photo']) && isset($_FILES['profile_photo'])) {
    $errPanel = 'photoDialog';
    $file = $_FILES['profile_photo'];

    if ($file['error'] !== UPLOAD_ERR_OK) {
      switch ($file['error']) {
        case UPLOAD_ERR_INI_SIZE:
        case UPLOAD_ERR_FORM_SIZE:
          $error = rui_msg('Il file è troppo grande. Massimo 5 MB.', 'The file is too large. 5 MB maximum.');
          break;
        case UPLOAD_ERR_PARTIAL:
          $error = rui_msg('Il file è stato caricato solo in parte. Riprova.', 'The file was only partly uploaded. Try again.');
          break;
        case UPLOAD_ERR_NO_FILE:
          $error = rui_msg('Seleziona un’immagine da caricare.', 'Choose an image to upload.');
          break;
        default:
          error_log("Upload error code: " . $file['error']);
          $error = rui_msg('Errore nel caricamento del file.', 'Upload failed.');
      }

    } elseif (!is_uploaded_file($file['tmp_name'])) {
      $error = rui_msg('Caricamento non valido.', 'Invalid upload.');

    } elseif ($file['size'] > 5000000) {
      $error = rui_msg('Il file è troppo grande. Massimo 5 MB.', 'The file is too large. 5 MB maximum.');

    } else {
      $check = @getimagesize($file['tmp_name']);
      $allowed_mime_types = ['image/jpeg' => 'jpg', 'image/png' => 'png', 'image/gif' => 'gif'];

      if ($check === false) {
        $error = rui_msg('Il file non è un’immagine valida.', 'The file is not a valid image.');
      } elseif (!isset($allowed_mime_types[$check['mime']])) {
        $error = rui_msg('Formato non consentito. Usa JPG, PNG o GIF.', 'Format not allowed. Use JPG, PNG or GIF.');
      } elseif ($check[0] > 8000 || $check[1] > 8000) {
        $error = rui_msg('Le dimensioni dell’immagine sono troppo grandi (massimo 8000 px).', 'The image is too large (8000 px maximum).');
      } else {
        $target_dir = "uploads/profile_photos/{$user_id}/";

        if (!is_dir($target_dir) && !mkdir($target_dir, 0755, true)) {
          error_log("Cannot create directory: " . $target_dir);
          $error = rui_msg('Impossibile salvare la foto. Contatta l’assistenza.', 'Could not save the photo. Contact support.');
        } else {
          $version = 1;
          foreach (glob($target_dir . "v*.*") ?: [] as $existing) {
            $version = max($version, versionOf($existing) + 1);
          }

          $webp_file = $target_dir . "v{$version}.webp";
          $final_file = null;

          if (convertToWebP($file['tmp_name'], $check['mime'], $webp_file)) {
            $final_file = $webp_file;
          } else {
            $original_file = $target_dir . "v{$version}." . $allowed_mime_types[$check['mime']];
            if (move_uploaded_file($file['tmp_name'], $original_file)) {
              $final_file = $original_file;
            }
          }

          if ($final_file === null) {
            $error = rui_msg('Errore nel caricamento della foto.', 'Could not upload the photo.');
          } else {
            $stmt = $db->prepare("UPDATE users SET profile_photo = ? WHERE id = ?");
            $stmt->bind_param("si", $final_file, $user_id);

            if ($stmt->execute()) {
              flash_redirect(rui_msg('Foto profilo aggiornata.', 'Profile photo updated.'));
            }

            error_log("Photo DB error: " . $stmt->error);
            unlink($final_file);
            $error = rui_msg('Errore nel salvataggio della foto.', 'Could not save the photo.');
          }
        }
      }
    }

  } elseif (isset($_POST['remove_photo'])) {
    $empty = '';
    $stmt = $db->prepare("UPDATE users SET profile_photo = ? WHERE id = ?");
    $stmt->bind_param("si", $empty, $user_id);

    if ($stmt->execute()) {
      deleteUserPhotos($user_id);
      flash_redirect(rui_msg('Foto profilo rimossa.', 'Profile photo removed.'));
    }

    $error = rui_msg('Non è stato possibile rimuovere la foto.', 'Could not remove the photo.');
    $errPanel = 'photoDialog';

  } elseif (isset($_POST['delete_account'])) {
    $errPanel = 'deleteDialog';
    $delete_password = (string)($_POST['delete_password'] ?? '');
    $delete_confirmation = trim((string)($_POST['delete_confirmation'] ?? ''));

    $stmt = $db->prepare("SELECT password FROM users WHERE id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();

    if (!$user || !password_verify($delete_password, $user['password'])) {
      $error = rui_msg('Password non corretta.', 'Incorrect password.');
    } elseif (strtolower($delete_confirmation) !== "delete my account") {
      $error = rui_msg('Devi digitare esattamente “delete my account” per confermare.', 'You must type exactly “delete my account” to confirm.');
    } else {
      $stmt = $db->prepare("DELETE FROM users WHERE id = ?");
      $stmt->bind_param("i", $user_id);

      if ($stmt->execute()) {
        deleteUserPhotos($user_id);
        session_destroy();
        header("Location: login.php?account_deleted=1");
        exit();
      }

      error_log("Account delete error: " . $stmt->error);
      $error = rui_msg('Errore durante l’eliminazione dell’account.', 'Could not delete your account.');
    }
  }
}

$stmt = $db->prepare("SELECT username, email, profile_photo, created_at, preferred_language, keep_signed_in FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$user_data = $stmt->get_result()->fetch_assoc();

if (!$user_data) {
  session_destroy();
  header("Location: login.php");
  exit();
}

$_SESSION['username'] = $user_data['username'];
rena_apply_session_persistence($db, $user_id);

$storedLanguage = (string)($user_data['preferred_language'] ?? 'it');
$preferredLanguage = in_array($storedLanguage, ['it', 'en'], true) ? $storedLanguage : 'it';
$_SESSION['rena_preferred_language'] = $preferredLanguage;
rui_set_lang($preferredLanguage);

if (!empty($user_data['profile_photo']) && (substr($user_data['profile_photo'], -1) === '/' || !is_file($user_data['profile_photo']))) {
  $latest_photo = findLatestPhoto($user_id);
  if ($latest_photo !== null) {
    $stmt = $db->prepare("UPDATE users SET profile_photo = ? WHERE id = ?");
    $stmt->bind_param("si", $latest_photo, $user_id);
    $stmt->execute();
  }
  $user_data['profile_photo'] = $latest_photo;
}

$latest_photo = getLatestProfilePhoto($user_id, $db);
$photoUrl = ($latest_photo && is_file($latest_photo)) ? $latest_photo . '?v=' . filemtime($latest_photo) : null;
$initial = mb_strtoupper(mb_substr($user_data['username'], 0, 1));
$hasEmail = !empty($user_data['email']);
$memberSince = '';

if (!empty($user_data['created_at'])) {
  $d = new DateTime($user_data['created_at']);
  $memberSince = $preferredLanguage === 'en' ? $d->format('M j, Y') : $d->format('d/m/Y');
}

$vUser = $errPanel === 'profile' ? $postedUsername : $user_data['username'];
$vEmail = $errPanel === 'profile' ? $postedEmail : (string)($user_data['email'] ?? '');
$serviceNames = RUI_SERVICE_HOSTS;
?>
<!DOCTYPE html>
<html lang="<?= rui_lang() ?>">

<head>
  <?php rui_head('Il tuo account · Rena ID', 'Your account · Rena ID'); ?>
</head>

<body class="acct-page">
  <?php rui_sprite(); ?>

  <header class="topbar">
    <div class="topbar-in">
      <button type="button" class="btn btn-ghost btn-sm" id="backBtn">
        <?= rui_icon('arrow-left') ?><span><?= rui_te('Indietro', 'Back') ?></span>
      </button>
      <a class="brand" href="account.php" style="white-space:nowrap;flex-shrink:0">
        <img src="idlogo.png" alt="" width="30" height="30" style="display:block;flex-shrink:0;object-fit:contain">
        <span style="white-space:nowrap">Rena ID</span>
      </a>
      <a class="btn btn-ghost btn-sm" href="logout-id.php" style="white-space:nowrap;flex-shrink:0">
        <?= rui_icon('logout') ?><span style="white-space:nowrap">Logout</span>
      </a>
    </div>
  </header>

  <div class="shell">
    <?php if ($flash): ?>
      <div class="alert alert-ok" role="status" id="flash">
        <?= rui_icon('check-circle') ?><span><?= rui_h(rui_pick($flash)) ?></span>
      </div>
    <?php endif; ?>
    <?php acct_alert(''); ?>

    <section class="hero" aria-labelledby="heroName">
      <button type="button" class="hero-photo" data-open="photoDialog" aria-label="<?= rui_h(rui_t('Cambia foto profilo', 'Change profile photo')) ?>">
        <?php if ($photoUrl): ?>
          <img src="<?= rui_h($photoUrl) ?>" alt="" id="heroImg">
        <?php else: ?>
          <span class="initial" aria-hidden="true"><?= rui_h($initial) ?></span>
        <?php endif; ?>
        <span class="cam"><?= rui_icon('camera') ?></span>
      </button>
      <div>
        <h1 id="heroName"><?= rui_h($user_data['username']) ?></h1>
        <p>
          <?php if ($hasEmail): ?>
            <?= rui_h($user_data['email']) ?>
          <?php else: ?>
            <a href="#profile" id="addEmailLink"><?= rui_te('Aggiungi un’email per recuperare l’account', 'Add an email so you can recover your account') ?></a>
          <?php endif; ?>
        </p>
        <?php if ($memberSince): ?>
          <div class="hero-meta">
            <span class="chip"><?= rui_icon('clock') ?><?= rui_te('Account creato il ', 'Member since ') ?><?= rui_h($memberSince) ?></span>
          </div>
        <?php endif; ?>
      </div>
    </section>

    <div class="acct-grid">
      <nav class="acct-nav" aria-label="<?= rui_h(rui_t('Sezioni dell’account', 'Account sections')) ?>">
        <a href="#profile"><?= rui_icon('user') ?><?= rui_te('Profilo', 'Profile') ?></a>
        <a href="#security"><?= rui_icon('shield-check') ?><?= rui_te('Sicurezza', 'Security') ?></a>
        <a href="#devices"><?= rui_icon('monitor') ?><?= rui_te('Dispositivi', 'Devices') ?></a>
        <a href="#apps"><?= rui_icon('link') ?><?= rui_te('App collegate', 'Connected apps') ?></a>
        <a href="#preferences"><?= rui_icon('sliders') ?><?= rui_te('Preferenze', 'Preferences') ?></a>
        <a href="#danger" class="danger"><?= rui_icon('trash') ?><?= rui_te('Elimina account', 'Delete account') ?></a>
      </nav>

      <main class="acct-main">

        <section class="panel" id="profile" aria-labelledby="h-profile">
          <div class="panel-head">
            <h2 id="h-profile"><?= rui_icon('user') ?><?= rui_te('Profilo', 'Profile') ?></h2>
            <p><?= rui_te('Username ed email del tuo Rena ID.', 'The username and email of your Rena ID.') ?></p>
          </div>
          <?php acct_alert('profile'); ?>
          <form method="POST" id="profileForm" autocomplete="on" data-busy>
            <input type="hidden" name="csrf" value="<?= rui_h($csrf) ?>">
            <div class="form-grid">
              <div class="field">
                <label for="username">Username</label>
                <div class="input">
                  <input type="text" id="username" name="username"
                    value="<?= rui_h($vUser) ?>"
                    data-initial="<?= rui_h($user_data['username']) ?>"
                    required minlength="3" maxlength="30"
                    autocomplete="username" autocapitalize="none" spellcheck="false">
                </div>
              </div>
              <div class="field">
                <label for="email">Email</label>
                <div class="input">
                  <input type="email" id="email" name="email"
                    value="<?= rui_h($vEmail) ?>"
                    data-initial="<?= rui_h($user_data['email'] ?? '') ?>"
                    autocomplete="email"
                    placeholder="<?= rui_h(rui_t('tua@email.com', 'you@email.com')) ?>">
                </div>
              </div>
            </div>
            <div class="confirm-pw" id="confirmPw" hidden>
              <div class="field">
                <label for="current_password"><?= rui_te('Conferma con la tua password', 'Confirm with your password') ?></label>
                <div class="input">
                  <input type="password" id="current_password" name="current_password" autocomplete="current-password">
                </div>
                <div class="field-row">
                  <span class="hint" style="margin:0"><?= rui_te('Serve per salvare le modifiche.', 'Needed to save your changes.') ?></span>
                  <a href="password-forgot.php" class="link"><?= rui_te('Password dimenticata?', 'Forgot your password?') ?></a>
                </div>
              </div>
            </div>
            <div class="form-actions">
              <button type="submit" name="update_profile" value="1" class="btn btn-sm" id="saveProfile" disabled>
                <?= rui_icon('check') ?><span><?= rui_te('Salva modifiche', 'Save changes') ?></span>
              </button>
              <button type="button" class="btn btn-ghost btn-sm" id="resetProfile" hidden>
                <?= rui_te('Annulla', 'Cancel') ?>
              </button>
            </div>
          </form>
        </section>

        <section class="panel" id="security" aria-labelledby="h-security">
          <div class="panel-head">
            <h2 id="h-security"><?= rui_icon('shield-check') ?><?= rui_te('Sicurezza', 'Security') ?></h2>
            <p><?= rui_te('Proteggi l’accesso con una password forte e un secondo passaggio di verifica.', 'Protect sign-in with a strong password and a second verification step.') ?></p>
          </div>

          <div class="rows">
            <div class="row">
              <div class="row-icon"><?= rui_icon('lock') ?></div>
              <div class="row-body">
                <div class="row-title"><?= rui_te('Password', 'Password') ?></div>
                <div class="row-sub"><?= rui_te('Usa una password che non utilizzi altrove.', 'Use a password you don’t use anywhere else.') ?></div>
              </div>
              <div class="row-actions">
                <button type="button" class="btn btn-ghost btn-sm" data-open="passwordDialog">
                  <?= rui_te('Cambia password', 'Change password') ?>
                </button>
              </div>
            </div>

            <div id="totpRow"><div class="skeleton"></div></div>

            <div class="inline-setup" id="totpSetup" hidden>
              <p class="label"><?= rui_te('1. Scansiona il codice con la tua app di autenticazione', '1. Scan the code with your authenticator app') ?></p>
              <div class="qr-box" id="totpQr" hidden></div>
              <p class="hint"><?= rui_te('Oppure inserisci questa chiave manualmente:', 'Or enter this key manually:') ?></p>
              <div class="secret">
                <code id="totpSecret"></code>
                <button type="button" class="btn btn-ghost btn-sm" id="copySecret" aria-label="<?= rui_h(rui_t('Copia chiave', 'Copy key')) ?>">
                  <?= rui_icon('copy') ?>
                </button>
              </div>
              <form id="totpForm">
                <div class="field">
                  <label for="totpCode"><?= rui_te('2. Inserisci il codice a 6 cifre', '2. Enter the 6-digit code') ?></label>
                  <div class="input">
                    <input type="text" class="otp" id="totpCode" inputmode="numeric" maxlength="6" pattern="[0-9]{6}"
                      autocomplete="one-time-code" placeholder="000000" data-otp required>
                  </div>
                </div>
                <div class="form-actions">
                  <button type="submit" class="btn btn-sm"><?= rui_te('Conferma e attiva', 'Confirm and turn on') ?></button>
                  <button type="button" class="btn btn-ghost btn-sm" id="totpCancel"><?= rui_te('Annulla', 'Cancel') ?></button>
                </div>
              </form>
            </div>

            <div id="emailRow"><div class="skeleton"></div></div>

            <div class="inline-setup" id="emailSetup" hidden>
              <form id="emailFactorForm">
                <div class="field">
                  <label for="emailCode"><?= rui_te('Codice ricevuto via email', 'Code sent by email') ?></label>
                  <div class="input">
                    <input type="text" class="otp" id="emailCode" inputmode="numeric" maxlength="6" pattern="[0-9]{6}"
                      autocomplete="one-time-code" placeholder="000000" data-otp required>
                  </div>
                </div>
                <div class="form-actions">
                  <button type="submit" class="btn btn-sm"><?= rui_te('Conferma email', 'Confirm email') ?></button>
                  <button type="button" class="btn btn-ghost btn-sm" id="emailCancel"><?= rui_te('Annulla', 'Cancel') ?></button>
                </div>
              </form>
            </div>
          </div>

          <p class="subhead"><?= rui_te('Passkey', 'Passkeys') ?></p>
          <p class="hint" style="margin:0 0 6px">
            <?= rui_te(
              'Accedi con il blocco schermo, l’impronta o una chiave di sicurezza. Sono facoltative: puoi continuare a usare la password.',
              'Sign in with your screen lock, fingerprint or a security key. They are optional — you can keep using your password.'
            ) ?>
          </p>
          <div id="passkeyList" class="rows"><div class="skeleton"></div></div>
          <div style="margin-top:14px">
            <button type="button" class="btn btn-ghost btn-sm" id="addPasskey">
              <?= rui_icon('plus') ?><?= rui_te('Aggiungi una passkey', 'Add a passkey') ?>
            </button>
          </div>
        </section>

        <section class="panel" id="devices" aria-labelledby="h-devices">
          <div class="panel-head">
            <h2 id="h-devices"><?= rui_icon('monitor') ?><?= rui_te('Dispositivi e sessioni', 'Devices and sessions') ?></h2>
            <p>
              <?= rui_te(
                'I dispositivi da cui hai effettuato l’accesso. Se non ne riconosci uno, revocalo e cambia la password.',
                'The devices you’ve signed in from. If you don’t recognise one, revoke it and change your password.'
              ) ?>
            </p>
          </div>
          <div id="deviceList" class="rows">
            <div class="skeleton"></div>
            <div class="skeleton"></div>
          </div>
          <div style="margin-top:16px">
            <button type="button" class="btn btn-danger-ghost btn-sm" id="revokeAll">
              <?= rui_icon('logout') ?><?= rui_te('Esci da tutti i dispositivi', 'Sign out of all devices') ?>
            </button>
          </div>
        </section>

        <section class="panel" id="apps" aria-labelledby="h-apps">
          <div class="panel-head">
            <h2 id="h-apps"><?= rui_icon('link') ?><?= rui_te('App collegate', 'Connected apps') ?></h2>
            <p>
              <?= rui_te(
                'Servizi Rena e app di terze parti che hanno accesso al tuo account. Puoi revocare l’accesso quando vuoi.',
                'Rena services and third-party apps that can access your account. You can revoke access at any time.'
              ) ?>
            </p>
          </div>

          <p class="subhead" style="margin-top:0"><?= rui_te('Servizi Rena', 'Rena services') ?></p>
          <div id="renaList" class="rows"><div class="skeleton"></div></div>

          <p class="subhead"><?= rui_te('App di terze parti', 'Third-party apps') ?></p>
          <?php acct_alert('apps'); ?>
          <p class="hint" style="margin:-4px 0 10px">
            <?= rui_te(
              'Per ogni app puoi scegliere se il token di accesso scade (dopo 30 giorni) oppure no. Per impostazione predefinita non scade, così non devi riaccedere ogni volta.',
              'For each app you can choose whether the access token expires (after 30 days) or not. By default it does not expire, so you don’t have to sign in again every time.'
            ) ?>
          </p>
          <div id="oauthList" class="rows"><div class="skeleton"></div></div>
        </section>

        <section class="panel" id="preferences" aria-labelledby="h-prefs">
          <div class="panel-head">
            <h2 id="h-prefs"><?= rui_icon('sliders') ?><?= rui_te('Preferenze', 'Preferences') ?></h2>
          </div>
          <?php acct_alert('preferences'); ?>
          <div class="rows">
            <form method="POST" class="row" id="languageForm" style="flex-wrap:wrap">
              <input type="hidden" name="csrf" value="<?= rui_h($csrf) ?>">
              <input type="hidden" name="update_language" value="1">
              <div class="row-icon"><?= rui_icon('globe') ?></div>
              <div class="row-body">
                <div class="row-title"><?= rui_te('Lingua', 'Language') ?></div>
                <div class="row-sub"><?= rui_te('Rena ID userà questa lingua ogni volta che accedi, su qualsiasi dispositivo.', 'Rena ID will use this language whenever you sign in, on any device.') ?></div>
              </div>
              <div class="seg" style="margin:0;min-width:220px" role="radiogroup" aria-label="<?= rui_h(rui_t('Lingua', 'Language')) ?>">
                <label>
                  <input type="radio" name="preferred_language" value="it" <?= $preferredLanguage === 'it' ? 'checked' : '' ?>>
                  <span>Italiano</span>
                </label>
                <label>
                  <input type="radio" name="preferred_language" value="en" <?= $preferredLanguage === 'en' ? 'checked' : '' ?>>
                  <span>English</span>
                </label>
              </div>
            </form>

            <form method="POST" class="row" id="sessionForm">
              <input type="hidden" name="csrf" value="<?= rui_h($csrf) ?>">
              <input type="hidden" name="update_session_preference" value="1">
              <div class="row-icon"><?= rui_icon('clock') ?></div>
              <div class="row-body">
                <div class="row-title"><label for="keepSigned"><?= rui_te('Resta connesso', 'Stay signed in') ?></label></div>
                <div class="row-sub"><?= rui_te('Mantieni l’accesso su questo dispositivo per 30 giorni di inattività. Se lo disattivi, la sessione scade prima.', 'Stay signed in on this device for 30 days of inactivity. If you turn it off, your session expires sooner.') ?></div>
              </div>
              <span class="switch">
                <input type="checkbox" id="keepSigned" name="keep_signed_in" value="1" <?= !empty($user_data['keep_signed_in']) ? 'checked' : '' ?>>
                <i></i>
              </span>
            </form>
          </div>
        </section>

        <section class="panel danger" id="danger" aria-labelledby="h-danger">
          <div class="panel-head">
            <h2 id="h-danger" style="color:var(--bad)"><?= rui_icon('alert') ?><?= rui_te('Elimina account', 'Delete account') ?></h2>
            <p><?= rui_te('Elimina definitivamente il tuo Rena ID e tutti i dati collegati. Non si può annullare.', 'Permanently delete your Rena ID and all linked data. This can’t be undone.') ?></p>
          </div>
          <button type="button" class="btn btn-danger-ghost btn-sm" data-open="deleteDialog">
            <?= rui_icon('trash') ?><?= rui_te('Elimina il mio account', 'Delete my account') ?>
          </button>
        </section>

      </main>
    </div>
  </div>

  <footer class="site-footer">
    <a href="https://rena.altervista.org/privacy-policy.html"><?= rui_icon('shield') ?>Privacy Policy</a>
    <a href="https://rena.altervista.org/chi-siamo.html"><?= rui_icon('user') ?><?= rui_te('Chi siamo', 'About us') ?></a>
    <a href="https://rena.altervista.org/news.php"><?= rui_icon('news') ?>News</a>
  </footer>

  <dialog id="photoDialog" aria-labelledby="photoTitle">
    <div class="dlg">
      <button type="button" class="dlg-close" data-close aria-label="<?= rui_h(rui_t('Chiudi', 'Close')) ?>"><?= rui_icon('x') ?></button>
      <h2 id="photoTitle"><?= rui_te('Foto profilo', 'Profile photo') ?></h2>
      <?php acct_alert('photoDialog'); ?>
      <form method="POST" enctype="multipart/form-data" id="photoForm" data-busy>
        <input type="hidden" name="csrf" value="<?= rui_h($csrf) ?>">
        <input type="hidden" name="MAX_FILE_SIZE" value="5000000">
        <div style="display:grid;place-items:center;margin-top:8px">
          <?php if ($photoUrl): ?>
            <img class="photo-preview" id="photoPreview" src="<?= rui_h($photoUrl) ?>" alt="">
          <?php else: ?>
            <div class="photo-preview" id="photoPreview" aria-hidden="true"><?= rui_h($initial) ?></div>
          <?php endif; ?>
        </div>
        <label class="drop" id="drop" for="profile_photo">
          <?= rui_icon('upload') ?>
          <strong><?= rui_te('Scegli un’immagine', 'Choose an image') ?></strong>
          <span class="hint" style="margin:0"><?= rui_te('o trascinala qui · JPG, PNG, GIF · max 5 MB', 'or drag it here · JPG, PNG, GIF · 5 MB max') ?></span>
          <input type="file" id="profile_photo" name="profile_photo" accept="image/jpeg,image/png,image/gif" required>
        </label>
        <p class="hint" id="photoName" aria-live="polite" style="margin:-6px 0 0"></p>
        <div class="dlg-actions">
          <button type="button" class="btn btn-ghost" data-close><?= rui_te('Annulla', 'Cancel') ?></button>
          <button type="submit" name="upload_photo" value="1" class="btn" id="photoSave" disabled>
            <?= rui_te('Salva foto', 'Save photo') ?>
          </button>
        </div>
      </form>
      <?php if ($photoUrl): ?>
        <form method="POST" id="removePhotoForm" style="margin-top:14px;text-align:center">
          <input type="hidden" name="csrf" value="<?= rui_h($csrf) ?>">
          <button type="submit" name="remove_photo" value="1" class="link">
            <?= rui_te('Rimuovi la foto attuale', 'Remove current photo') ?>
          </button>
        </form>
      <?php endif; ?>
    </div>
  </dialog>

  <dialog id="passwordDialog" aria-labelledby="pwTitle">
    <div class="dlg">
      <button type="button" class="dlg-close" data-close aria-label="<?= rui_h(rui_t('Chiudi', 'Close')) ?>"><?= rui_icon('x') ?></button>
      <h2 id="pwTitle"><?= rui_te('Cambia password', 'Change password') ?></h2>
      <p class="dlg-text">
        <?= rui_te(
          'Dopo il cambio, gli altri dispositivi restano connessi: puoi disconnetterli dalla sezione Dispositivi.',
          'Other devices stay signed in after the change — you can sign them out from Devices.'
        ) ?>
      </p>
      <?php acct_alert('passwordDialog'); ?>
      <form method="POST" id="passwordForm" data-busy>
        <input type="hidden" name="csrf" value="<?= rui_h($csrf) ?>">

        <div class="field">
          <label for="pw_current"><?= rui_te('Password attuale', 'Current password') ?></label>
          <div class="input">
            <input type="password" id="pw_current" name="current_password" required autocomplete="current-password">
          </div>
          <div class="field-row">
            <span></span>
            <a href="password-forgot.php" class="link"><?= rui_te('Password dimenticata?', 'Forgot your password?') ?></a>
          </div>
        </div>

        <div class="field">
          <label for="pw_new"><?= rui_te('Nuova password', 'New password') ?></label>
          <div class="input">
            <input type="password" id="pw_new" name="new_password" required autocomplete="new-password">
          </div>
          <ul class="rules" id="pwRules">
            <li data-rule="length"><?= rui_icon('circle') ?><?= rui_te('Almeno 8 caratteri', 'At least 8 characters') ?></li>
            <li data-rule="number"><?= rui_icon('circle') ?><?= rui_te('Almeno un numero', 'At least one number') ?></li>
            <li data-rule="special"><?= rui_icon('circle') ?><?= rui_te('Almeno un carattere speciale (/, -, _)', 'At least one special character (/, -, _)') ?></li>
          </ul>
        </div>

        <div class="field">
          <label for="pw_confirm"><?= rui_te('Conferma nuova password', 'Confirm new password') ?></label>
          <div class="input">
            <input type="password" id="pw_confirm" name="confirm_password" required autocomplete="new-password">
          </div>
          <div class="match" id="pwMatch" aria-live="polite"></div>
        </div>

        <div class="dlg-actions">
          <button type="button" class="btn btn-ghost" data-close><?= rui_te('Annulla', 'Cancel') ?></button>
          <button type="submit" name="change_password" value="1" class="btn"><?= rui_te('Cambia password', 'Change password') ?></button>
        </div>
      </form>
    </div>
  </dialog>

  <dialog id="deleteDialog" aria-labelledby="delTitle">
    <div class="dlg">
      <button type="button" class="dlg-close" data-close aria-label="<?= rui_h(rui_t('Chiudi', 'Close')) ?>"><?= rui_icon('x') ?></button>
      <h2 id="delTitle" style="color:var(--bad)"><?= rui_te('Eliminare il tuo account?', 'Delete your account?') ?></h2>
      <div class="alert alert-error" style="margin-top:12px">
        <?= rui_icon('alert') ?>
        <div>
          <strong><?= rui_te('Questa azione è irreversibile.', 'This can’t be undone.') ?></strong>
          <ul class="warn-list">
            <li><?= rui_te('Tutti i tuoi dati personali vengono cancellati definitivamente.', 'All your personal data is permanently deleted.') ?></li>
            <li><?= rui_te('Non potrai più accedere con questo account né recuperarlo.', 'You won’t be able to sign in with this account or recover it.') ?></li>
            <li><?= rui_te('I servizi e le app collegate perdono l’accesso.', 'Connected services and apps lose access.') ?></li>
          </ul>
        </div>
      </div>
      <?php acct_alert('deleteDialog'); ?>
      <form method="POST" id="deleteForm" autocomplete="off" data-busy>
        <input type="hidden" name="csrf" value="<?= rui_h($csrf) ?>">

        <div class="field">
          <label for="delete_password"><?= rui_te('La tua password', 'Your password') ?></label>
          <div class="input">
            <input type="password" id="delete_password" name="delete_password" required autocomplete="current-password">
          </div>
        </div>

        <div class="field">
          <label for="delete_confirmation">
            <?= rui_te('Scrivi', 'Type') ?> <code>delete my account</code> <?= rui_te('per confermare', 'to confirm') ?>
          </label>
          <div class="input">
            <input type="text" id="delete_confirmation" name="delete_confirmation" required
              autocomplete="off" autocapitalize="none" spellcheck="false">
          </div>
        </div>

        <div class="dlg-actions">
          <button type="button" class="btn btn-ghost" data-close><?= rui_te('Annulla', 'Cancel') ?></button>
          <button type="submit" name="delete_account" value="1" class="btn btn-danger" id="deleteBtn" disabled>
            <?= rui_icon('trash') ?><?= rui_te('Elimina definitivamente', 'Delete permanently') ?>
          </button>
        </div>
      </form>
    </div>
  </dialog>

  <?php rui_context_menu(); rui_scripts(); ?>
  <script src="https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js"></script>
  <script>
    (function () {
      var R = RenaUI, $ = R.$, $$ = R.$$, el = R.el, t = R.t;
      R.initLang(<?= json_encode($preferredLanguage) ?>, true);

      var USERNAME = <?= json_encode($user_data['username']) ?>;
      var NAMES = <?= json_encode($serviceNames, JSON_UNESCAPED_SLASHES) ?>;
      var REOPEN = <?= json_encode(substr($errPanel, -6) === 'Dialog' ? $errPanel : '') ?>;
      var APP_PREFS = <?= json_encode((object)rena_oauth_app_prefs($db, $user_id), JSON_UNESCAPED_SLASHES) ?>;
      var APP_CSRF = <?= json_encode($csrf) ?>;
      var ERR_PROFILE = <?= json_encode($errPanel === 'profile') ?>;

      $('#backBtn').addEventListener('click', function () {
        if (document.referrer && history.length > 1) history.back();
        else location.href = 'https://rena.altervista.org';
      });

      $$('[data-open]').forEach(function (b) {
        b.addEventListener('click', function () { R.open(b.dataset.open); });
      });

      $$('dialog').forEach(function (d) {
        d.querySelectorAll('input[type=password]').forEach(function (i) {
          i.parentElement.append(R.pwToggle());
        });
      });

      var pc = $('#current_password');
      if (pc) pc.parentElement.append(R.pwToggle());

      if (REOPEN) R.open(REOPEN);

      var flash = $('#flash');
      if (flash) {
        setTimeout(function () {
          flash.style.transition = 'opacity .4s';
          flash.style.opacity = '0';
          setTimeout(function () { flash.remove(); }, 400);
        }, 6000);
      }

      var al = $('#addEmailLink');
      if (al) {
        al.addEventListener('click', function () {
          setTimeout(function () { $('#email').focus(); }, 300);
        });
      }

      var links = $$('.acct-nav a');
      var io = new IntersectionObserver(function (entries) {
        entries.forEach(function (en) {
          if (en.isIntersecting) {
            links.forEach(function (a) {
              a.setAttribute('aria-current', a.getAttribute('href') === '#' + en.target.id ? 'true' : 'false');
            });
          }
        });
      }, { rootMargin: '-35% 0px -55% 0px' });
      $$('.panel').forEach(function (p) { io.observe(p); });

      var pf = $('#profileForm'),
        u = $('#username'),
        em = $('#email'),
        cp = $('#confirmPw'),
        save = $('#saveProfile'),
        rs = $('#resetProfile');

      function dirty() {
        return u.value !== u.dataset.initial || em.value !== em.dataset.initial;
      }

      function syncProfile() {
        var d = dirty();
        cp.hidden = !d;
        rs.hidden = !d;
        save.disabled = !d;
        $('#current_password').required = d;
      }

      pf.addEventListener('input', syncProfile);
      rs.addEventListener('click', function () {
        u.value = u.dataset.initial;
        em.value = em.dataset.initial;
        syncProfile();
      });
      syncProfile();

      if (ERR_PROFILE) $('#current_password').focus();

      var pn = $('#pw_new'), pcf = $('#pw_confirm'), pm = $('#pwMatch');

      function pwMatch() {
        if (!pcf.value) {
          pm.textContent = '';
          pm.className = 'match';
          return;
        }
        var ok = pn.value === pcf.value;
        pm.className = 'match ' + (ok ? 'ok' : 'bad');
        pm.textContent = ok
          ? t('Le password coincidono', 'Passwords match')
          : t('Le password non coincidono', 'Passwords do not match');
      }

      pn.addEventListener('input', function () {
        R.paintRules($('#pwRules'), pn.value);
        pwMatch();
      });
      pcf.addEventListener('input', pwMatch);

      $('#passwordForm').addEventListener('submit', function (e) {
        if (!R.pwRules(pn.value).ok) {
          e.preventDefault();
          R.toast(t('La nuova password non soddisfa ancora i requisiti.', 'The new password doesn’t meet the requirements yet.'), 'error');
          pn.focus();
        } else if (pn.value !== pcf.value) {
          e.preventDefault();
          R.toast(t('Le password non coincidono', 'Passwords do not match'), 'error');
          pcf.focus();
        }
      });

      var file = $('#profile_photo'),
        prev = $('#photoPreview'),
        drop = $('#drop'),
        psave = $('#photoSave');

      function setFile(f) {
        var okType = f && /^image\/(jpeg|png|gif)$/.test(f.type);
        if (!f) return;

        if (!okType) {
          R.toast(t('Formato non consentito. Usa JPG, PNG o GIF.', 'Format not allowed. Use JPG, PNG or GIF.'), 'error');
          file.value = '';
          return;
        }
        if (f.size > 5 * 1024 * 1024) {
          R.toast(t('Il file è troppo grande. Massimo 5 MB.', 'The file is too large. 5 MB maximum.'), 'error');
          file.value = '';
          return;
        }

        var r = new FileReader();
        r.onload = function (e) {
          var img = el('img', { class: 'photo-preview', id: 'photoPreview', src: e.target.result, alt: '' });
          prev.replaceWith(img);
          prev = img;
        };
        r.readAsDataURL(f);
        $('#photoName').textContent = f.name;
        psave.disabled = false;
      }

      file.addEventListener('change', function () { setFile(file.files[0]); });

      ['dragenter', 'dragover'].forEach(function (n) {
        drop.addEventListener(n, function (e) {
          e.preventDefault();
          drop.classList.add('over');
        });
      });

      ['dragleave', 'drop'].forEach(function (n) {
        drop.addEventListener(n, function (e) {
          e.preventDefault();
          drop.classList.remove('over');
        });
      });

      drop.addEventListener('drop', function (e) {
        if (e.dataTransfer.files[0]) {
          file.files = e.dataTransfer.files;
          setFile(file.files[0]);
        }
      });

      var rpf = $('#removePhotoForm');
      if (rpf) {
        rpf.addEventListener('submit', function (e) {
          if (rpf.dataset.ok) return;
          e.preventDefault();
          R.confirm({
            title: t('Rimuovere la foto profilo?', 'Remove your profile photo?'),
            confirmLabel: t('Rimuovi', 'Remove'),
            danger: true
          }).then(function (ok) {
            if (ok) {
              rpf.dataset.ok = '1';
              var h = document.createElement('input');
              h.type = 'hidden';
              h.name = 'remove_photo';
              h.value = '1';
              rpf.append(h);
              rpf.submit();
            }
          });
        });
      }

      $('#languageForm').addEventListener('change', function () { this.submit(); });
      $('#sessionForm').addEventListener('change', function () { this.submit(); });

      var dc = $('#delete_confirmation'), dbtn = $('#deleteBtn');
      dc.addEventListener('input', function () {
        dbtn.disabled = dc.value.trim().toLowerCase() !== 'delete my account';
      });
      $('#deleteDialog').addEventListener('close', function () {
        $('#deleteForm').reset();
        dbtn.disabled = true;
      });

      function btn(label, cls, fn, icon) {
        var b = el('button', { type: 'button', class: 'btn btn-sm ' + (cls || 'btn-ghost') }, icon ? R.icon(icon) : null, label);
        b.addEventListener('click', function () { fn(b); });
        return b;
      }

      function passkeyIcon() {
        var tpl = document.createElement('template');
        tpl.innerHTML =
          '<svg class="icon" fill="currentColor" viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">' +
          '<path d="M63.28,202a15.29,15.29,0,0,1-7.7-2,14.84,14.84,0,0,1-5.52-20.46C69.34,147.36,128,72.25,256,72.25c55.47,0,104.12,14.57,144.53,43.29,33.26,23.57,51.9,50.25,60.78,63.1a14.79,14.79,0,0,1-4,20.79,15.52,15.52,0,0,1-21.24-4C420,172.32,371,102,256,102c-112.25,0-163,64.71-179.53,92.46A15,15,0,0,1,63.28,202Z"></path>' +
          '<path d="M320.49,496a15.31,15.31,0,0,1-3.79-.43c-92.85-23-127.52-115.82-128.93-119.68l-.22-.85c-.76-2.68-19.39-66.33,9.21-103.61,13.11-17,33.05-25.72,59.38-25.72,24.48,0,42.14,7.61,54.28,23.36,10,12.86,14,28.72,17.87,44,8.13,31.82,14,48.53,47.79,50.25,14.84.75,24.59-7.93,30.12-15.32,14.95-20.15,17.55-53,6.28-82C398,228.57,346.61,158,256,158c-38.68,0-74.22,12.43-102.72,35.79C129.69,213.14,111,240.46,102,268.54c-16.69,52.28,5.2,134.46,5.41,135.21A14.83,14.83,0,0,1,96.54,422a15.39,15.39,0,0,1-18.74-10.6c-1-3.75-24.38-91.4-5.1-151.82,21-65.47,85.81-131.47,183.33-131.47,45.07,0,87.65,15.32,123.19,44.25,27.52,22.5,50,52.72,61.76,82.93,14.95,38.57,10.94,81.86-10.19,110.14-14.08,18.86-34.13,28.72-56.34,27.65-57.86-2.9-68.26-43.29-75.84-72.75-7.8-30.22-12.79-44.79-42.58-44.79-16.36,0-27.85,4.5-35,13.82-9.75,12.75-10.51,32.68-9.43,47.14a152.44,152.44,0,0,0,5.1,29.79c2.38,6,33.37,82,107.59,100.39a14.88,14.88,0,0,1,11,18.11A15.36,15.36,0,0,1,320.49,496Z"></path>' +
          '<path d="M201.31,489.14a15.5,15.5,0,0,1-11.16-4.71c-37.16-39-58.18-82.61-66.09-137.14V347c-4.44-36.1,2.06-87.21,33.91-122.35,23.51-25.93,56.56-39.11,98.06-39.11,49.08,0,87.65,22.82,111.7,65.89,17.45,31.29,20.91,62.47,21,63.75a15.07,15.07,0,0,1-13.65,16.4,15.26,15.26,0,0,1-16.79-13.29h0A154,154,0,0,0,340.43,265c-18.64-32.89-47-49.61-84.51-49.61-32.4,0-57.75,9.75-75.19,29-25.14,27.75-30,70.5-26.55,98.78,6.93,48.22,25.46,86.58,58.18,120.86a14.7,14.7,0,0,1-.76,21.11A15.44,15.44,0,0,1,201.31,489.14Z"></path>' +
          '<path d="M372.5,446.18c-32.5,0-60.13-9-82.24-26.89-44.42-35.79-49.4-94.08-49.62-96.54a15.27,15.27,0,0,1,30.45-2.36c.11.86,4.55,48.54,38.79,76,20.26,16.18,47.34,22.6,80.71,18.85a15.2,15.2,0,0,1,16.91,13.18,14.92,14.92,0,0,1-13.44,16.5A187,187,0,0,1,372.5,446.18Z"></path>' +
          '<path d="M398.18,48.79C385.5,40.54,340.54,16,256,16c-88.74,0-133.81,27.11-143.78,34a11.59,11.59,0,0,0-1.84,1.4.36.36,0,0,1-.22.1,14.87,14.87,0,0,0-5.09,11.15A15.06,15.06,0,0,0,120.38,77.5a15.56,15.56,0,0,0,8.88-2.79c.43-.32,39.22-28.82,126.77-28.82S382.58,74.29,383,74.5a15.25,15.25,0,0,0,9.21,3A15.06,15.06,0,0,0,407.5,62.61,14.9,14.9,0,0,0,398.18,48.79Z"></path>' +
          '</svg>';

        var svg = tpl.content.firstChild, ref = R.icon('id');
        ['class', 'width', 'height', 'style'].forEach(function (a) {
          if (ref.hasAttribute(a)) svg.setAttribute(a, ref.getAttribute(a));
          else svg.removeAttribute(a);
        });
        svg.style.fill = '#fff';
        return svg;
      }

      function row(o) {
        return el('div', { class: 'row' },
          el('div', { class: 'row-icon' + (o.ok ? ' ok' : '') },
            o.icon === 'passkey' ? passkeyIcon() : R.icon(o.icon)),
          el('div', { class: 'row-body' },
            el('div', { class: 'row-title' },
              o.title,
              o.badge ? el('span', { class: 'badge ' + (o.ok ? 'badge-ok' : '') }, o.badge) : null),
            o.sub ? el('div', { class: 'row-sub' }, o.sub) : null,
            o.chips && o.chips.length
              ? el('div', { class: 'row-sub chips' }, o.chips.map(function (c) { return el('span', { class: 'chip' }, c); }))
              : null),
          el('div', { class: 'row-actions' }, o.actions || []));
      }

      function skeleton(n) {
        var f = document.createDocumentFragment();
        for (var i = 0; i < (n || 1); i++) f.append(el('div', { class: 'skeleton' }));
        return f;
      }

      function failBox(container, msg, retry) {
        container.replaceChildren(
          el('div', { class: 'empty' },
            el('p', { text: msg }),
            el('div', { style: 'margin-top:10px' }, btn(t('Riprova', 'Try again'), 'btn-ghost', retry, 'refresh'))));
      }

      function sName(h) { return NAMES[h] || h; }

      function tokenSwitch(app, never) {
        var input = el('input', { type: 'checkbox', 'aria-label': t('Il token non scade', 'Token never expires') });
        input.checked = never;

        var wrap = el('label', {
          class: 'row-sub',
          style: 'display:inline-flex;align-items:center;gap:8px;margin:0;cursor:pointer'
        },
          el('span', { text: t('Non scade', 'Never expires') }),
          el('span', { class: 'switch' }, input, el('i')));

        input.addEventListener('change', function () {
          var f = el('form', { method: 'POST', action: 'account.php#apps', hidden: true });
          [
            ['csrf', APP_CSRF],
            ['update_app_token_policy', '1'],
            ['client_id', app.client_id]
          ].forEach(function (p) {
            f.append(el('input', { type: 'hidden', name: p[0], value: p[1] }));
          });
          if (input.checked) {
            f.append(el('input', { type: 'hidden', name: 'token_never_expires', value: '1' }));
          }
          document.body.append(f);
          f.submit();
        });

        return wrap;
      }

      var svcCsrf = '';

      function loadServices() {
        ['renaList', 'oauthList', 'deviceList'].forEach(function (id) {
          $('#' + id).replaceChildren(skeleton(1));
        });

        R.api('account-services.php').then(function (d) {
          svcCsrf = d.csrf || '';

          var rena = $('#renaList'), oauth = $('#oauthList'), devs = $('#deviceList');
          rena.replaceChildren();
          oauth.replaceChildren();
          devs.replaceChildren();

          (d.internal || []).forEach(function (s) {
            rena.append(row({
              icon: 'id',
              title: sName(s.service_host),
              sub: s.session_count + ' ' + t('sessione/i attiva/e', 'active session(s)'),
              actions: [
                btn(t('Revoca', 'Revoke'), 'btn-danger-ghost', function () {
                  revoke({ action: 'revoke_internal', service_host: s.service_host }, sName(s.service_host));
                })
              ]
            }));
          });

          (d.external || []).forEach(function (s) {
            var never = Object.prototype.hasOwnProperty.call(APP_PREFS, s.client_id)
              ? !!APP_PREFS[s.client_id]
              : true;

            oauth.append(row({
              icon: 'link',
              title: s.name,
              sub: s.token_count + ' ' + t('token attivo/i · ', 'active token(s) · ') +
                (never ? t('non scade', 'never expires') : t('scadenza ', 'expires ') + s.expires_at),
              actions: [
                tokenSwitch(s, never),
                btn(t('Revoca', 'Revoke'), 'btn-danger-ghost', function () {
                  revoke({ action: 'revoke_external', client_id: s.client_id }, s.name);
                })
              ]
            }));
          });

          if (!rena.children.length) {
            rena.append(el('div', { class: 'empty', text: t('Nessun servizio Rena attivo.', 'No active Rena services.') }));
          }
          if (!oauth.children.length) {
            oauth.append(el('div', { class: 'empty', text: t('Nessuna app di terze parti ha accesso.', 'No third-party apps have access.') }));
          }

          var groups = {}, order = [];

          (d.devices || []).forEach(function (x) {
            var k = (x.device_name || '') + '|' + (x.ip_address || ''), g = groups[k];

            if (!g) {
              g = groups[k] = Object.assign({}, x, { ids: [], services: [], here: false });
              order.push(k);
            }

            g.ids.push(x.device_id);
            if (x.device_id === d.current_device_id) g.here = true;
            if (String(x.last_seen) > String(g.last_seen)) g.last_seen = x.last_seen;

            (x.services || []).forEach(function (sv) {
              var exists = g.services.some(function (y) {
                return y.service_name === sv.service_name && y.service_type === sv.service_type;
              });
              if (!exists) g.services.push(sv);
            });
          });

          order.map(function (k) { return groups[k]; }).forEach(function (dv) {
            var here = dv.here,
              mobile = /iPhone|iPad|Android|Mobile/i.test(dv.device_name || ''),
              hasApp = (dv.services || []).some(function (s) { return s.service_type !== 'Rena'; }),
              devName = dv.device_name;

            if (hasApp) {
              if (/iPhone|iPad|iPod|iOS/i.test(devName || '')) devName = 'iOS';
              else if (/Android/i.test(devName || '')) devName = 'Android';
            }

            var chips = (dv.services || []).map(function (s) {
              return (s.service_type === 'Rena' ? '' : t('App: ', 'App: ')) + sName(s.service_name);
            });

            devs.append(row({
              icon: mobile ? 'phone' : 'monitor',
              ok: here,
              title: devName,
              badge: here ? t('Questo dispositivo', 'This device') : null,
              sub: t('Ultimo accesso: ', 'Last active: ') + dv.last_seen + ' · IP ' + dv.ip_address,
              chips: chips,
              actions: [
                btn(here ? t('Esci', 'Sign out') : t('Revoca', 'Revoke'), 'btn-danger-ghost', function () {
                  revokeDevice(dv, here);
                })
              ]
            }));
          });

          if (!devs.children.length) {
            devs.append(el('div', { class: 'empty', text: t('Nessun dispositivo registrato.', 'No devices registered.') }));
          }
        }).catch(function (e) {
          ['renaList', 'oauthList', 'deviceList'].forEach(function (id) {
            failBox($('#' + id), t('Impossibile caricare: ', 'Could not load: ') + e.message, loadServices);
          });
        });
      }

      function revoke(payload, name) {
        R.confirm({
          title: t('Revocare l’accesso?', 'Revoke access?'),
          text: name + t(' non potrà più usare il tuo account finché non accedi di nuovo.', ' will no longer be able to use your account until you sign in again.'),
          confirmLabel: t('Revoca accesso', 'Revoke access'),
          danger: true
        }).then(function (ok) {
          if (!ok) return;
          R.api('account-services.php', Object.assign({ csrf: svcCsrf }, payload))
            .then(function () {
              R.toast(t('Accesso revocato.', 'Access revoked.'), 'ok');
              loadServices();
            })
            .catch(function (e) { R.toast(e.message, 'error'); });
        });
      }

      function revokeDevice(dv, here) {
        R.confirm({
          title: here
            ? t('Uscire da questo dispositivo?', 'Sign out of this device?')
            : t('Revocare il dispositivo?', 'Revoke this device?'),
          text: t('Verranno revocati anche gli accessi dei servizi collegati a questo dispositivo.', 'Access for services linked to this device will be revoked too.'),
          confirmLabel: here ? t('Esci', 'Sign out') : t('Revoca dispositivo', 'Revoke device'),
          danger: true
        }).then(function (ok) {
          if (!ok) return;

          if (here) {
            location.href = 'logout-id.php';
            return;
          }

          var cur = false;
          dv.ids.reduce(function (pr, id) {
            return pr.then(function () {
              return R.api('account-services.php', { action: 'revoke_device', device_id: id, csrf: svcCsrf })
                .then(function (r) { if (r.current) cur = true; });
            });
          }, Promise.resolve()).then(function () {
            if (cur) {
              location.href = 'logout-id.php';
              return;
            }
            R.toast(t('Dispositivo revocato.', 'Device revoked.'), 'ok');
            loadServices();
          }).catch(function (e) { R.toast(e.message, 'error'); });
        });
      }

      $('#revokeAll').addEventListener('click', function () {
        R.confirm({
          title: t('Uscire da tutti i dispositivi?', 'Sign out of all devices?'),
          text: t('Verrai disconnesso anche da qui e tutti i servizi perderanno l’accesso.', 'You’ll be signed out here too and every service will lose access.'),
          confirmLabel: t('Esci da tutto', 'Sign out of everything'),
          danger: true
        }).then(function (ok) {
          if (!ok) return;
          R.api('account-services.php', { action: 'revoke_all', csrf: svcCsrf })
            .then(function () { location.href = 'logout-id.php'; })
            .catch(function (e) { R.toast(e.message, 'error'); });
        });
      });

      var secCsrf = '';

      function sec(payload) {
        return R.api('security-settings.php', Object.assign({ csrf: secCsrf }, payload));
      }

      function loadSecurity() {
        R.api('security-settings.php').then(function (d) {
          secCsrf = d.csrf;

          var addr = d.email || '',
            hasMail = addr.indexOf('@') > 0,
            masked = hasMail ? addr.replace(/^(.{1,2}).*(@.*)$/, '$1•••$2') : '';

          $('#totpRow').replaceChildren(row({
            icon: 'shield-check',
            ok: !!d.enabled,
            title: t('App di autenticazione', 'Authenticator app'),
            badge: d.enabled ? t('Attiva', 'On') : t('Disattivata', 'Off'),
            sub: d.enabled
              ? t('Ti chiediamo un codice dell’app ad ogni accesso.', 'We ask for a code from your app at every sign-in.')
              : t('Usa Google Authenticator, 1Password o un’app simile per generare i codici.', 'Use Google Authenticator, 1Password or a similar app to generate codes.'),
            actions: [
              d.enabled
                ? btn(t('Disattiva', 'Turn off'), 'btn-danger-ghost', disableTotp)
                : btn(t('Attiva', 'Turn on'), 'btn-ghost', startTotp)
            ]
          }));

          var emailActions = !hasMail
            ? [btn(t('Aggiungi email', 'Add email'), 'btn-ghost', function () {
                location.hash = '#profile';
                setTimeout(function () { $('#email').focus(); }, 300);
              }, 'mail')]
            : [d.email_enabled
                ? btn(t('Disattiva', 'Turn off'), 'btn-danger-ghost', disableEmail)
                : btn(t('Attiva', 'Turn on'), 'btn-ghost', startEmail)];

          $('#emailRow').replaceChildren(row({
            icon: 'mail',
            ok: !!d.email_enabled,
            title: t('Codice via email', 'Email code'),
            badge: hasMail
              ? (d.email_enabled ? t('Attiva', 'On') : t('Disattivata', 'Off'))
              : null,
            sub: !hasMail
              ? t('Aggiungi prima un’email al tuo profilo.', 'Add an email to your profile first.')
              : (d.email_enabled
                ? t('Codici inviati a ', 'Codes are sent to ') + masked
                : t('Riceverai un codice a ', 'You’ll receive a code at ') + masked + t(' ad ogni accesso.', ' at every sign-in.')),
            actions: emailActions
          }));
        }).catch(function (e) {
          failBox($('#totpRow'), t('Impossibile caricare le impostazioni: ', 'Could not load settings: ') + e.message, loadSecurity);
          $('#emailRow').replaceChildren();
        });
      }

      function askPassword(title, text, extra) {
        return R.ask({
          title: title,
          text: text,
          confirmLabel: t('Continua', 'Continue'),
          fields: [{
            name: 'password',
            label: t('Password attuale', 'Current password'),
            type: 'password',
            autocomplete: 'current-password'
          }].concat(extra || [])
        });
      }

      function startTotp() {
        askPassword(
          t('Attiva la verifica con app', 'Turn on authenticator app'),
          t('Inserisci la password per iniziare la configurazione.', 'Enter your password to start setting up.')
        ).then(function (v) {
          if (!v) return;

          sec({ action: 'setup', password: v.password }).then(function (d) {
            $('#totpSecret').textContent = d.secret;

            var qrBox = $('#totpQr');
            qrBox.hidden = true;

            if (typeof qrcode === 'function') {
              var q = qrcode(0, 'M');
              q.addData(
                'otpauth://totp/Rena%20ID:' + encodeURIComponent(USERNAME) +
                '?secret=' + encodeURIComponent(d.secret) +
                '&issuer=Rena%20ID'
              );
              q.make();
              qrBox.innerHTML = q.createImgTag(5, 2, 'QR');
              qrBox.hidden = false;
            }

            $('#totpSetup').hidden = false;
            $('#totpCode').value = '';
            $('#totpCode').focus();
          }).catch(function (e) { R.toast(e.message, 'error'); });
        });
      }

      $('#copySecret').addEventListener('click', function () {
        if (navigator.clipboard) {
          navigator.clipboard.writeText($('#totpSecret').textContent).then(function () {
            R.toast(t('Chiave copiata.', 'Key copied.'), 'ok', 2500);
          });
        }
      });

      $('#totpCancel').addEventListener('click', function () { $('#totpSetup').hidden = true; });

      $('#totpForm').addEventListener('submit', function (e) {
        e.preventDefault();
        var b = this.querySelector('button[type=submit]');
        R.busy(b, true);

        sec({ action: 'enable', code: $('#totpCode').value })
          .then(function () {
            $('#totpSetup').hidden = true;
            R.toast(t('Verifica con app attivata.', 'Authenticator app turned on.'), 'ok');
            loadSecurity();
          })
          .catch(function (err) { R.toast(err.message, 'error'); })
          .finally(function () { R.busy(b, false); });
      });

      function disableTotp() {
        askPassword(
          t('Disattiva la verifica con app', 'Turn off authenticator app'),
          t('Conferma con la password e un codice dell’app.', 'Confirm with your password and a code from the app.'),
          [{
            name: 'code',
            label: t('Codice a 6 cifre', '6-digit code'),
            inputmode: 'numeric',
            maxlength: 6,
            autocomplete: 'one-time-code',
            otp: true
          }]
        ).then(function (v) {
          if (!v) return;
          sec({ action: 'disable', password: v.password, code: v.code })
            .then(function () {
              R.toast(t('Verifica con app disattivata.', 'Authenticator app turned off.'), 'ok');
              loadSecurity();
            })
            .catch(function (e) { R.toast(e.message, 'error'); });
        });
      }

      function startEmail() {
        askPassword(
          t('Attiva la verifica via email', 'Turn on email verification'),
          t('Invieremo un codice all’email del tuo profilo per confermare.', 'We’ll send a code to your profile email to confirm.')
        ).then(function (v) {
          if (!v) return;

          sec({ action: 'enable_email', password: v.password }).then(function (d) {
            $('#emailSetup').hidden = false;
            $('#emailCode').value = '';
            $('#emailCode').focus();
            R.toast(d.message || t('Codice inviato. Controlla la tua email.', 'Code sent. Check your email.'), 'ok');
          }).catch(function (e) { R.toast(e.message, 'error'); });
        });
      }

      $('#emailCancel').addEventListener('click', function () { $('#emailSetup').hidden = true; });

      $('#emailFactorForm').addEventListener('submit', function (e) {
        e.preventDefault();
        var b = this.querySelector('button[type=submit]');
        R.busy(b, true);

        sec({ action: 'confirm_email', code: $('#emailCode').value })
          .then(function () {
            $('#emailSetup').hidden = true;
            R.toast(t('Verifica via email attivata.', 'Email verification turned on.'), 'ok');
            loadSecurity();
          })
          .catch(function (err) { R.toast(err.message, 'error'); })
          .finally(function () { R.busy(b, false); });
      });

      function disableEmail() {
        askPassword(
          t('Disattiva la verifica via email', 'Turn off email verification'),
          t('Conferma con la password.', 'Confirm with your password.')
        ).then(function (v) {
          if (!v) return;
          sec({ action: 'disable_email', password: v.password })
            .then(function () {
              R.toast(t('Verifica via email disattivata.', 'Email verification turned off.'), 'ok');
              loadSecurity();
            })
            .catch(function (e) { R.toast(e.message, 'error'); });
        });
      }

      var pkCsrf = '';

      function pk(payload) {
        return R.api('passkey.php', Object.assign({ csrf: pkCsrf }, payload));
      }

      function loadPasskeys() {
        var list = $('#passkeyList');

        R.api('passkey.php', { action: 'list' }).then(function (d) {
          pkCsrf = d.csrf;
          list.replaceChildren();

          d.passkeys.forEach(function (p) {
            list.append(row({
              icon: 'passkey',
              title: p.device_name,
              sub: t('Aggiunta il ', 'Added ') + (p.created_at || '') +
                (p.last_used ? t(' · ultimo uso ', ' · last used ') + p.last_used : ''),
              actions: [
                btn(t('Rimuovi', 'Remove'), 'btn-danger-ghost', function () { removePasskey(p); })
              ]
            }));
          });

          if (!d.passkeys.length) {
            list.append(el('div', { class: 'empty', text: t('Non hai ancora registrato passkey.', 'You haven’t added any passkeys yet.') }));
          }
        }).catch(function (e) { failBox(list, e.message, loadPasskeys); });
      }

      $('#addPasskey').addEventListener('click', function () {
        if (!window.PublicKeyCredential || !navigator.credentials) {
          R.toast(t('Questo browser non supporta le passkey.', 'This browser does not support passkeys.'), 'error');
          return;
        }

        R.ask({
          title: t('Aggiungi una passkey', 'Add a passkey'),
          text: t('Dai un nome a questa passkey per riconoscerla (es. “iPhone” o “Chiave di sicurezza”).', 'Name this passkey so you can recognise it (e.g. “iPhone” or “Security key”).'),
          confirmLabel: t('Continua', 'Continue'),
          fields: [{ name: 'label', label: t('Nome', 'Name'), value: t('Questo dispositivo', 'This device') }]
        }).then(function (v) {
          if (!v) return;

          pk({ action: 'register_options' }).then(function (r) {
            var o = r.options;
            o.challenge = R.pkDecode(o.challenge);
            o.user.id = R.pkDecode(o.user.id);
            o.excludeCredentials = (o.excludeCredentials || []).map(function (x) {
              return Object.assign({}, x, { id: R.pkDecode(x.id) });
            });
            return navigator.credentials.create({ publicKey: o });
          }).then(function (c) {
            if (!c) throw new Error(t('Registrazione annullata', 'Registration cancelled'));

            return pk({
              action: 'register_verify',
              id: c.id,
              rawId: R.pkEncode(c.rawId),
              device_name: v.label,
              response: {
                clientDataJSON: R.pkEncode(c.response.clientDataJSON),
                attestationObject: R.pkEncode(c.response.attestationObject)
              }
            });
          }).then(function () {
            R.toast(t('Passkey aggiunta.', 'Passkey added.'), 'ok');
            loadPasskeys();
          }).catch(function (e) {
            if (e && e.name !== 'NotAllowedError') R.toast(e.message, 'error');
          });
        });
      });

      function removePasskey(p) {
        R.ask({
          title: t('Rimuovere la passkey?', 'Remove this passkey?'),
          text: p.device_name,
          confirmLabel: t('Rimuovi', 'Remove'),
          danger: true,
          fields: [{
            name: 'password',
            label: t('Password attuale', 'Current password'),
            type: 'password',
            autocomplete: 'current-password'
          }]
        }).then(function (v) {
          if (!v) return;
          pk({ action: 'remove', credential_id: p.credential_id, password: v.password })
            .then(function () {
              R.toast(t('Passkey rimossa.', 'Passkey removed.'), 'ok');
              loadPasskeys();
            })
            .catch(function (e) { R.toast(e.message, 'error'); });
        });
      }

      loadServices();
      loadSecurity();
      loadPasskeys();
    })();
  </script>
  <script src="API-extencion-domains.js"></script>
</body>

</html>

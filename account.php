<?php
session_start();

$welcome_message = "Benvenuto, ";
$email_not_set = "Email non impostata";

$db = new mysqli('localhost', 'username', 'password', 'my_rena');

if ($db->connect_error) {
    error_log("Database connection error: " . $db->connect_error);
    $error = "Errore di connessione al database. Riprova più tardi.";
}

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

$user_id = $_SESSION['user_id'];
$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['update_profile'])) {
        $new_username = trim($_POST['username']);
        $new_email = trim($_POST['email']);
        $current_password = $_POST['current_password'];
        $new_password = $_POST['new_password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';

        $sql = "SELECT password FROM users WHERE id = ?";
        $stmt = $db->prepare($sql);
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();

        if (password_verify($current_password, $user['password'])) {
            $updates = [];
            $types = "";
            $values = [];
            $update_username = false;

            if ($new_username !== $_SESSION['username']) {
                $check_sql = "SELECT id FROM users WHERE username = ? AND id != ?";
                $check_stmt = $db->prepare($check_sql);
                $check_stmt->bind_param("si", $new_username, $user_id);
                $check_stmt->execute();
                $check_result = $check_stmt->get_result();

                if ($check_result->num_rows > 0) {
                    $error = "Username già in uso!";
                } else {
                    $updates[] = "username = ?";
                    $types .= "s";
                    $values[] = $new_username;
                    $update_username = true;
                }
            }

            if (!empty($new_email)) {
                $updates[] = "email = ?";
                $types .= "s";
                $values[] = $new_email;
            }

            if (!empty($new_password)) {
                if ($new_password === $confirm_password) {
                    if (strlen($new_password) >= 6) {
                        $updates[] = "password = ?";
                        $types .= "s";
                        $values[] = password_hash($new_password, PASSWORD_DEFAULT);
                    } else {
                        $error = "La password deve essere di almeno 6 caratteri!";
                    }
                } else {
                    $error = "Le password non coincidono!";
                }
            }

            if (!empty($updates) && empty($error)) {
                $sql = "UPDATE users SET " . implode(', ', $updates) . " WHERE id = ?";
                $types .= "i";
                $values[] = $user_id;

                $stmt = $db->prepare($sql);
                $stmt->bind_param($types, ...$values);

                if ($stmt->execute()) {
                    $message = "Profilo aggiornato con successo!";
                    if ($update_username) {
                        $_SESSION['username'] = $new_username;
                    }
                } else {
                    $error = "Errore nell'aggiornamento del profilo: " . $stmt->error;
                }
            }
        } else {
            $error = "Password attuale non corretta!";
        }
    }

    if (isset($_POST['upload_photo']) && isset($_FILES['profile_photo'])) {
        $target_dir = "uploads/profile_photos/{$user_id}/";

        if (!file_exists($target_dir)) {
            if (!mkdir($target_dir, 0755, true)) {
                $error = "Impossibile creare la cartella di upload. Contatta l'amministratore.";
            }
        }

        if (empty($error)) {
            if (isset($_FILES["profile_photo"]["tmp_name"]) && $_FILES["profile_photo"]["error"] === UPLOAD_ERR_OK) {
                $check = getimagesize($_FILES["profile_photo"]["tmp_name"]);
                if ($check !== false) {
                    $mime_type = $check['mime'];
                    $allowed_mime_types = [
                        'image/jpeg' => 'jpg',
                        'image/png' => 'png',
                        'image/gif' => 'gif'
                    ];

                    if (array_key_exists($mime_type, $allowed_mime_types)) {
                        $safe_extension = $allowed_mime_types[$mime_type];

                        $version = 1;
                        $existing_files = glob($target_dir . "*.{$safe_extension}");
                        if (!empty($existing_files)) {
                            $versions = [];
                            foreach ($existing_files as $file) {
                                if (preg_match('/v(\d+)\.' . $safe_extension . '$/', $file, $matches)) {
                                    $versions[] = (int) $matches[1];
                                }
                            }
                            if (!empty($versions)) {
                                $version = max($versions) + 1;
                            }
                        }

                        $target_file = $target_dir . "v{$version}.{$safe_extension}";

                        if ($_FILES["profile_photo"]["size"] <= 5000000) {
                            if (move_uploaded_file($_FILES["profile_photo"]["tmp_name"], $target_file)) {
                                $base_path = "uploads/profile_photos/{$user_id}/";
                                $sql = "UPDATE users SET profile_photo = ? WHERE id = ?";
                                $stmt = $db->prepare($sql);
                                $stmt->bind_param("si", $base_path, $user_id);

                                if ($stmt->execute()) {
                                    $message = "Foto profilo aggiornata con successo!";
                                    $user_data['profile_photo'] = $target_file;
                                } else {
                                    $error = "Errore nel salvataggio della foto nel database: " . $stmt->error;
                                }
                            } else {
                                $error = "Errore nel caricamento della foto! Codice errore: " . $_FILES["profile_photo"]["error"];
                            }
                        } else {
                            $error = "Il file è troppo grande! Max 5MB.";
                        }
                    } else {
                        $error = "Tipo di file non consentito. Solo JPG, PNG e GIF sono ammessi.";
                    }
                } else {
                    $error = "Il file non è un'immagine valida!";
                }
            } else {
                $error_code = $_FILES["profile_photo"]["error"];
                switch ($error_code) {
                    case UPLOAD_ERR_INI_SIZE:
                        $error = "Il file caricato supera la direttiva upload_max_filesize in php.ini.";
                        break;
                    case UPLOAD_ERR_FORM_SIZE:
                        $error = "Il file caricato supera la direttiva MAX_FILE_SIZE specificata nel modulo HTML.";
                        break;
                    case UPLOAD_ERR_PARTIAL:
                        $error = "Il file caricato è stato caricato solo parzialmente.";
                        break;
                    case UPLOAD_ERR_NO_FILE:
                        $error = "Nessun file è stato selezionato per il caricamento.";
                        break;
                    case UPLOAD_ERR_NO_TMP_DIR:
                        $error = "Manca una cartella temporanea per il caricamento.";
                        break;
                    case UPLOAD_ERR_CANT_WRITE:
                        $error = "Impossibile scrivere il file su disco. Controlla i permessi della cartella temporanea.";
                        break;
                    case UPLOAD_ERR_EXTENSION:
                        $error = "Un'estensione PHP ha interrotto il caricamento del file.";
                        break;
                    default:
                        $error = "Errore sconosciuto nel caricamento del file: " . $error_code;
                        break;
                }
            }
        }
    }

    function compressImage($source, $quality = 75)
    {
        $info = getimagesize($source);
        if ($info['mime'] == 'image/jpeg') {
            $image = imagecreatefromjpeg($source);
            imagejpeg($image, $source, $quality);
        } elseif ($info['mime'] == 'image/png') {
            $image = imagecreatefrompng($source);
            imagepng($image, $source, round(9 * $quality / 100));
        }
        imagedestroy($image);
    }

    compressImage($target_file);

    function convertToWebP($source)
    {
        $output = str_replace(['.jpg', '.jpeg', '.png'], '.webp', $source);
        $info = getimagesize($source);

        if ($info['mime'] == 'image/jpeg') {
            $image = imagecreatefromjpeg($source);
        } elseif ($info['mime'] == 'image/png') {
            $image = imagecreatefrompng($source);
            imagepalettetotruecolor($image);
            imagealphablending($image, true);
            imagesavealpha($image, true);
        }

        imagewebp($image, $output, 80);
        imagedestroy($image);
        return $output;
    }

    $target_file = convertToWebP($target_file);

    header("Cache-Control: public, max-age=604800, immutable");
    header("Expires: " . gmdate('D, d M Y H:i:s', time() + 604800) . ' GMT');
}

function getLatestProfilePhoto($user_id, $db)
{
    $base_path = "uploads/profile_photos/{$user_id}/";

    if (!file_exists($base_path)) {
        return null;
    }

    $files = glob($base_path . "v*.*");
    if (empty($files)) {
        return null;
    }

    usort($files, function ($a, $b) {
        preg_match('/v(\d+)\./', $a, $a_matches);
        preg_match('/v(\d+)\./', $b, $b_matches);
        $a_ver = (int) ($a_matches[1] ?? 0);
        $b_ver = (int) ($b_matches[1] ?? 0);
        return $b_ver - $a_ver;
    });

    return $files[0];
}

$sql = "SELECT username, email, profile_photo, created_at FROM users WHERE id = ?";
$stmt = $db->prepare($sql);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$user_data = $result->fetch_assoc();

if (!empty($user_data['profile_photo'])) {
    $latest_photo = getLatestProfilePhoto($user_id, $db);
    if ($latest_photo) {
        $user_data['profile_photo'] = $latest_photo;
    } else {
        $user_data['profile_photo'] = null;
    }
}

if (isset($_POST['delete_account'])) {
    $delete_password = $_POST['delete_password'];
    $delete_confirmation = trim($_POST['delete_confirmation']);

    $sql = "SELECT username, email, profile_photo, created_at FROM users WHERE id = ?";
    $stmt = $db->prepare($sql);
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();

    if (password_verify($delete_password, $user['password'])) {
        if (strtolower($delete_confirmation) === "delete my account") {
            if (!empty($user['profile_photo']) && file_exists($user['profile_photo'])) {
                unlink($user['profile_photo']);
            }

            $sql = "DELETE FROM users WHERE id = ?";
            $stmt = $db->prepare($sql);
            $stmt->bind_param("i", $user_id);

            if ($stmt->execute()) {
                session_destroy();
                header("Location: login.php?account_deleted=1");
                exit();
            } else {
                $error = "Errore durante l'eliminazione dell'account: " . $stmt->error;
            }
        } else {
            $error = "Devi digitare esattamente 'delete my account' per confermare!";
        }
    } else {
        $error = "Password non corretta!";
    }
}

$sql = "SELECT username, email, profile_photo, created_at FROM users WHERE id = ?";
$stmt = $db->prepare($sql);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$user_data = $result->fetch_assoc();
?>

<!DOCTYPE html>
<html lang="it">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title id="page-title" data-translate-it="Gestione Account - My Rena ID"
    data-translate-en="Account Management - My Rena ID">Gestione Account - My Rena ID</title>
  <link rel="icon" type="image/x-icon" href="renaidlogo.png">
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: 'Open Sauce', sans-serif;
      background: black;
      min-height: 100vh;
      padding: 20px;
      color: #333;
    }

    .container {
      max-width: 900px;
      margin: 0 auto;
      background: black;
      backdrop-filter: blur(20px);
      border-radius: 24px;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
      overflow: hidden;
      border: 1px solid rgba(255, 255, 255, 0.2);
    }

    .header {
      padding: 40px;
      background: linear-gradient(135deg, #333333 0%, #1a1a1a 100%);
      color: white;
      position: relative;
      overflow: hidden;
    }

    .header::before {
      content: '';
      position: absolute;
      top: -50%;
      right: -10%;
      width: 200px;
      height: 200px;
      background: rgba(255, 255, 255, 0.1);
      border-radius: 50%;
      opacity: 0.5;
    }

    .profile-section {
      display: flex;
      align-items: center;
      gap: 24px;
      position: relative;
      z-index: 2;
    }

    .profile-photo-container {
      position: relative;
      cursor: pointer;
      transition: transform 0.3s ease;
    }

    .profile-photo-container:hover {
      transform: scale(1.05);
    }

    .profile-photo {
      width: 100px;
      height: 100px;
      border-radius: 50%;
      object-fit: cover;
      border: 4px solid rgba(255, 255, 255, 0.3);
      transition: all 0.3s ease;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
    }

    .default-avatar {
      width: 100px;
      height: 100px;
      border-radius: 50%;
      background: rgba(255, 255, 255, 0.2);
      display: flex;
      align-items: center;
      justify-content: center;
      color: white;
      font-size: 36px;
      font-weight: 600;
      border: 4px solid rgba(255, 255, 255, 0.3);
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
      transition: all 0.3s ease;
    }

    .photo-edit-overlay {
      position: absolute;
      bottom: -2px;
      right: -2px;
      background: #1a1a1a;
      color: white;
      width: 32px;
      height: 32px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 14px;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
      border: 3px solid #555555;
    }

    .user-info h2 {
      font-size: 28px;
      font-weight: 600;
      margin-bottom: 8px;
    }

    .user-info p {
      opacity: 0.9;
      font-size: 16px;
    }

    .logout-btn {
      position: absolute;
      top: 40px;
      right: 40px;
      background: rgba(255, 255, 255, 0.2);
      color: white;
      padding: 12px 24px;
      border: none;
      border-radius: 50px;
      cursor: pointer;
      font-size: 14px;
      font-weight: 500;
      transition: all 0.3s ease;
      text-decoration: none;
      display: flex;
      align-items: center;
      gap: 8px;
      z-index: 1000px;
    }

    .logout-btn:hover {
      background: rgba(255, 255, 255, 0.3);
      transform: translateY(-2px);
    }

    .main-content {
      padding: 40px;
    }

    .section {
      margin-bottom: 40px;
      background: #111111;
      color: white;
      border: 1px solid rgba(0, 0, 0, 0.05);
      border-radius: 16px;
      padding: 32px;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.05);
      border: 1px solid rgba(0, 0, 0, 0.05);
    }

    .section h3 {
      font-size: 20px;
      font-weight: 600;
      margin-bottom: 24px;
      color: white;
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .section-icon {
      color: #4f46e5;
      font-size: 20px;
    }

    .form-group {
      margin-bottom: 24px;
    }

    .form-group label {
      display: block;
      margin-bottom: 8px;
      font-weight: 500;
      color: #d1d5db;
      font-size: 14px;
    }

    .input-container {
      position: relative;
    }

    .form-group input[type="text"],
    .form-group input[type="password"],
    .form-group input[type="email"] {
      width: 100%;
      padding: 16px 20px;
      border: 2px solid #2a2a2a;
      border-radius: 12px;
      font-size: 16px;
      background: #1a1a1a;
      color: #ffffff;
      transition: all 0.3s ease;
      font-family: inherit;
    }

    .form-group input:focus {
      outline: none;
      border-color: white;
      background: #252525;
      color: #ffffff;
      box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.1);
    }

    .password-toggle {
      position: absolute;
      right: 16px;
      top: 50%;
      transform: translateY(-50%);
      cursor: pointer;
      color: #6b7280;
      transition: color 0.3s ease;
    }

    .password-toggle:hover {
      color: #4f46e5;
    }

    .btn {
      background: linear-gradient(135deg, #4a4a4a 0%, #2c2c2c 100%);
      color: white;
      padding: 16px 32px;
      border: none;
      border-radius: 12px;
      cursor: pointer;
      font-size: 16px;
      font-weight: 500;
      transition: all 0.3s ease;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      text-decoration: none;
      font-family: inherit;
    }

    .btn:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 25px rgba(74, 74, 74, 0.3);
    }

    .btn-secondary {
      background: #1a1a1a;
      border: 1px solid #2a2a2a;
      color: white;
    }

    .btn-secondary:hover {
      background: #252525;
      box-shadow: 0 8px 25px rgba(26, 26, 26, 0.5);
    }

    .btn-danger {
      background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
    }

    .btn-danger:hover {
      box-shadow: 0 8px 25px rgba(239, 68, 68, 0.3);
    }

    .btn-outline {
      background: transparent;
      border: 2px solid #4f46e5;
      color: #4f46e5;
    }

    .btn-outline:hover {
      background: #4f46e5;
      color: white;
    }

    .alert {
      padding: 16px 20px;
      border-radius: 12px;
      margin-bottom: 24px;
      display: flex;
      align-items: center;
      gap: 12px;
      font-weight: 500;
      animation: slideIn 0.3s ease;
    }

    @keyframes slideIn {
      from {
        opacity: 0;
        transform: translateY(-10px);
      }

      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    .alert-success {
      background: #d1fae5;
      color: #065f46;
      border: 1px solid #a7f3d0;
    }

    .alert-error {
      background: #fee2e2;
      color: #991b1b;
      border: 1px solid #fca5a5;
    }

    .form-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 24px;
    }

    .password-section {
      background: #1a1a1a;
      border-radius: 12px;
      padding: 24px;
      border: 2px dashed #2a2a2a;
      transition: all 0.3s ease;
    }

    .password-section.active {
      background: #252525;
      border-color: white;
    }

    .change-password-toggle {
      display: flex;
      align-items: center;
      gap: 12px;
      cursor: pointer;
      color: #ffffff;
      font-weight: 500;
      transition: color 0.3s ease;
    }

    .change-password-toggle:hover {
      color: #e5e5e5;
    }

    .password-fields {
      display: none;
      margin-top: 20px;
    }

    .password-fields.active {
      display: block;
      animation: slideIn 0.3s ease;
    }

    .forgot-password-link {
      color: #ffffff;
      text-decoration: none;
      font-size: 14px;
      font-weight: 500;
      margin-top: 8px;
      display: inline-block;
      transition: color 0.3s ease;
    }

    .forgot-password-link:hover {
      color: #e5e5e5;
      text-decoration: underline;
    }

    .modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.5);
      backdrop-filter: blur(8px);
      z-index: 1000;
      display: none;
      align-items: center;
      justify-content: center;
      opacity: 0;
      transition: opacity 0.3s ease;
    }

    .modal-overlay.active {
      display: flex;
      opacity: 1;
    }

    .modal {
      background: #111111;
      color: #e5e5e5;
      border-radius: 24px;
      padding: 40px;
      max-width: 500px;
      max-height: 90vh;
      min-height: 500px;
      overflow-y: auto;
      transform: scale(0.9);
      transition: transform 0.3s ease;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.2);
    }

    .modal-overlay.active .modal {
      transform: scale(1);
    }

    .modal h3 {
      color: #f87171;
      margin-bottom: 20px;
      font-size: 24px;
      font-weight: 600;
    }

    .delete-warning {
      background: #4c1d1d;
      border: 1px solid #7f1d1d;
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 24px;
      color: #fca5a5;
    }

    .delete-warning ul {
      margin-top: 12px;
      margin-left: 20px;
    }

    .delete-warning li {
      margin-bottom: 8px;
    }

    .modal-buttons {
      display: flex;
      gap: 16px;
      justify-content: flex-end;
      margin-top: 24px;
    }

    .photo-modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.8);
      backdrop-filter: blur(10px);
      z-index: 1001;
      display: none;
      align-items: center;
      justify-content: center;
      opacity: 0;
      transition: opacity 0.3s ease;
    }

    .photo-modal-overlay.active {
      display: flex;
      opacity: 1;
    }

    .photo-modal {
      text-align: center;
      transform: scale(0.9);
      transition: transform 0.3s ease;
    }

    .photo-modal-overlay.active .photo-modal {
      transform: scale(1);
    }

    .enlarged-photo {
      max-width: 400px;
      max-height: 400px;
      border-radius: 20px;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
      margin-bottom: 24px;
    }

    .enlarged-avatar {
      width: 300px;
      height: 300px;
      border-radius: 50%;
      background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
      display: flex;
      align-items: center;
      justify-content: center;
      color: white;
      font-size: 120px;
      font-weight: 600;
      margin-bottom: 24px;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
    }

    .photo-upload-form {
      background: #1A1A1A;
      color: white;
      padding: 24px;
      border-radius: 16px;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
      margin-top: 20px;
    }

    .file-input-wrapper {
      position: relative;
      display: inline-block;
      cursor: pointer;
      background: #111111;
      border: 2px dashed #6b7280;
      border-radius: 12px;
      padding: 24px;
      transition: all 0.3s ease;
      margin-bottom: 16px;
      width: 100%;
    }

    .photo-upload-form h4 {
      color: #ffffff !important;
      font-weight: 600;
    }

    .file-input-wrapper:hover {
      border-color: white;
      background: #1A1A1A;
    }

    .file-input-wrapper input[type="file"] {
      position: absolute;
      opacity: 0;
      width: 100%;
      height: 100%;
      cursor: pointer;
    }

    .file-input-content {
      text-align: center;
      color: #d1d5db;
    }

    .close-modal {
      position: absolute;
      top: 20px;
      right: 20px;
      background: rgba(255, 255, 255, 0.2);
      color: white;
      border: none;
      width: 40px;
      height: 40px;
      border-radius: 50%;
      cursor: pointer;
      font-size: 18px;
      transition: background 0.3s ease;
      z-index: 1000px;
    }

    .close-modal:hover {
      background: rgba(255, 255, 255, 0.3);
    }

    @media (max-width: 768px) {
      .container {
        margin: 10px;
        margin-top: 60px;
      }

      .header {
        padding: 30px 20px;
      }

      .profile-section {
        flex-direction: column;
        text-align: center;
        gap: 16px;
      }

      .logout-btn {
        position: static;
        margin-top: 20px;
      }

      .main-content {
        padding: 20px;
      }

      .section {
        padding: 24px 20px;
      }

      .form-row {
        grid-template-columns: 1fr;
      }

      .modal {
        margin: 20px;
        padding: 30px 20px;
      }
    }

    .container {
      backdrop-filter: blur(15px);
      -webkit-backdrop-filter: blur(15px);
      transition: backdrop-filter 0.3s ease;
    }

    .section form button[type="submit"] {
      margin-top: 24px;
    }

    @media (max-width: 768px) {
      .modal-buttons {
        flex-direction: column-reverse;
        gap: 12px;
      }

      .modal-buttons .btn {
        width: 100%;
        justify-content: center;
      }
    }

    .fas,
    .far,
    .fab {
      color: #ffffff !important;
    }

    .section-icon {
      color: #ffffff !important;
    }

    .password-toggle {
      color: #ffffff !important;
    }

    .password-toggle:hover {
      color: #e5e5e5 !important;
    }

    @media (max-width: 768px) {
      #updateProfileBtn {
        display: block;
        margin: 20px auto;
      }
    }

    @media (max-width: 768px) {
      div[style*="flex: 1; min-width: 0;"] {
        margin-top: 8px;
        width: 100%;
        padding-left: 24px;
      }
    }

    .site-footer {
      padding: 20px 0;
      position: relative;
      z-index: 10;
    }

    .footer-buttons {
      display: flex;
      justify-content: center;
      gap: 20px;
      max-width: 800px;
      margin: 0 auto;
      padding: 0 20px;
    }

    .footer-button {
      display: flex;
      align-items: center;
      padding: 15px 25px;
      background: rgba(255, 255, 255, 0.05);
      border-radius: 15px;
      color: white;
      text-decoration: none;
      transition: all 0.3s ease;
      border: 1px solid rgba(255, 255, 255, 0.1);
    }

    .footer-button:hover {
      transform: translateY(-3px);
      background: rgba(255, 255, 255, 0.1);
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
      border-color: rgba(255, 255, 255, 0.2);
    }

    .footer-button-svg {
      width: 24px;
      height: 24px;
      margin-right: 10px;
    }

    .footer-button span {
      font-size: 16px;
      font-weight: 500;
      letter-spacing: 0.5px;
    }

    @media (max-width: 600px) {
      .footer-buttons {
        flex-direction: column;
        align-items: center;
      }

      .footer-button {
        width: 100%;
        justify-content: center;
      }
    }

    .photo-modal .enlarged-photo {
      width: 300px;
      height: 300px;
      border-radius: 50%;
      object-fit: cover;
      border: 5px solid rgba(255, 255, 255, 0.2);
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
    }

    .photo-modal .enlarged-avatar {
      width: 300px;
      height: 300px;
      border-radius: 50%;
      background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
      display: flex;
      align-items: center;
      justify-content: center;
      color: white;
      font-size: 120px;
      font-weight: 600;
      border: 5px solid rgba(255, 255, 255, 0.2);
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
    }
  </style>
</head>

<body>
  <div class="container">
    <div class="header">
      <div class="profile-section">
        <div class="profile-photo-container" onclick="openPhotoModal()">
          <?php
                    $latest_photo = getLatestProfilePhoto($user_id, $db);
                    if ($latest_photo && file_exists($latest_photo)): ?>
          <img src="<?php echo htmlspecialchars($latest_photo); ?>?v=<?php echo time(); ?>" alt="Foto Profilo"
            class="profile-photo" id="currentPhoto">
          <?php else: ?>
          <div class="default-avatar" id="currentAvatar">
            <?php echo strtoupper(substr($user_data['username'], 0, 1)); ?>
          </div>
          <?php endif; ?>
          <div class="photo-edit-overlay">
            <i class="fas fa-camera"></i>
          </div>
        </div>
        <div class="user-info">
          <h2>
            <span id="welcome-message" data-translate-it="Benvenuto, " data-translate-en="Welcome, ">
              <?php echo $welcome_message; ?>
            </span>
            <?php echo htmlspecialchars($user_data['username']); ?>!
          </h2>
          <p>
            <?php if (!empty($user_data['email'])): ?>
            <?php echo htmlspecialchars($user_data['email']); ?>
            <?php else: ?>
            <span data-translate-it="Email non impostata" data-translate-en="Email not set">
              <?php echo $email_not_set; ?>
            </span>
            <?php endif; ?>
          </p>
        </div>
      </div>
      <a href="logout-id.php" class="logout-btn">
        <i class="fas fa-sign-out-alt"></i>
        Logout
      </a>
    </div>

    <div class="main-content">
      <?php if ($message): ?>
      <div class="alert alert-success">
        <i class="fas fa-check-circle"></i>
        <?php echo htmlspecialchars($message); ?>
      </div>
      <?php endif; ?>

      <?php if ($error): ?>
      <div class="alert alert-error">
        <i class="fas fa-exclamation-circle"></i>
        <?php echo htmlspecialchars($error); ?>
      </div>
      <?php endif; ?>

      <div class="section">
        <h3 data-translate-it="Informazioni Profilo" data-translate-en="Profile Info">
          <i class="fas fa-user section-icon"></i>
          <span>Informazioni Profilo</span>
        </h3>
        <form method="POST" autocomplete="off" id="profileForm">
          <div class="form-group">
            <label for="username">Username</label>
            <input type="text" id="username" name="username"
              value="<?php echo htmlspecialchars($user_data['username']); ?>" required autocomplete="new-username">
          </div>

          <div class="form-group">
            <label for="email">Email</label>
            <input type="email" id="email" name="email"
              value="<?php echo htmlspecialchars($user_data['email'] ?? ''); ?>" placeholder="tua@email.com"
              autocomplete="new-email" data-placeholder-en="your@email.com" data-placeholder-it="tua@email.com">
          </div>

          <div class="form-group">
            <label for="current_password" data-translate-it="Password Attuale"
              data-translate-en="Current Password">Password Attuale</label>
            <div class="input-container">
              <input type="password" id="current_password" name="current_password" required autocomplete="new-password">
              <i class="fas fa-eye password-toggle" onclick="togglePassword('current_password')"></i>
            </div>
            <a href="password-forgot.php" class="forgot-password-link" data-translate-en="Forgot your password?"
              data-translate-it="Password dimenticata?">
              <i class="fas fa-key"></i> Password dimenticata?
            </a>
          </div>

          <div class="password-section" id="passwordSection">
            <div class="change-password-toggle" onclick="togglePasswordFields()">
              <i class="fas fa-lock"></i>
              <span data-translate-it="Cambia Password" data-translate-en="Change Password">Cambia
                Password</span>
              <i class="fas fa-chevron-down" id="passwordChevron"></i>
            </div>

            <div class="password-fields" id="passwordFields">
              <div class="form-row">
                <div class="form-group">
                  <label for="new_password" data-translate-it="Nuova Password" data-translate-en="New Password">Nuova
                    Password</label>
                  <div class="input-container">
                    <input type="password" id="new_password" name="new_password" autocomplete="new-password">
                    <i class="fas fa-eye password-toggle" onclick="togglePassword('new_password')"></i>
                  </div>
                </div>

                <div class="form-group">
                  <label for="confirm_password" data-translate-it="Conferma Password"
                    data-translate-en="Confirm Password">Conferma Password</label>
                  <div class="input-container">
                    <input type="password" id="confirm_password" name="confirm_password" autocomplete="new-password">
                    <i class="fas fa-eye password-toggle" onclick="togglePassword('confirm_password')"></i>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <button type="submit" name="update_profile" class="btn" id="updateProfileBtn">
            <i class="fas fa-save"></i>
            <span id="saveChangesText" data-translate-it="Salva Modifiche" data-translate-en="Save Changes">Salva
              Modifiche</span>
          </button>
        </form>
      </div>

      <div
        style="background: #1a1a1a; border-radius: 12px; padding: 24px; margin-top: 24px; border: 1px solid rgba(255, 255, 255, 0.1);">
        <h4
          style="color: #ffffff; margin-bottom: 16px; display: flex; align-items: center; gap: 12px; font-size: 16px; font-weight: 600;">
          <svg fill="#ffffff" viewBox="0 0 1920 1920" xmlns="http://www.w3.org/2000/svg"
            style="width: 20px; height: 20px;">
            <g id="SVGRepo_bgCarrier" stroke-width="0"></g>
            <g id="SVGRepo_tracerCarrier" stroke-linecap="round" stroke-linejoin="round"></g>
            <g id="SVGRepo_iconCarrier">
              <path
                d="M960 0c530.193 0 960 429.807 960 960s-429.807 960-960 960S0 1490.193 0 960 429.807 0 960 0Zm223.797 707.147c-28.531-29.561-67.826-39.944-109.227-39.455-55.225.657-114.197 20.664-156.38 40.315-100.942 47.024-178.395 130.295-242.903 219.312-11.616 16.025-17.678 34.946 2.76 49.697 17.428 12.58 29.978 1.324 40.49-9.897l.69-.74c.801-.862 1.591-1.72 2.37-2.565 11.795-12.772 23.194-25.999 34.593-39.237l2.85-3.31 2.851-3.308c34.231-39.687 69.056-78.805 115.144-105.345 27.4-15.778 47.142 8.591 42.912 35.963-2.535 16.413-11.165 31.874-17.2 47.744-21.44 56.363-43.197 112.607-64.862 168.888-23.74 61.7-47.405 123.425-70.426 185.398l-2 5.38-1.998 5.375c-20.31 54.64-40.319 108.872-53.554 165.896-10.575 45.592-24.811 100.906-4.357 145.697 11.781 25.8 36.77 43.532 64.567 47.566 37.912 5.504 78.906 6.133 116.003-2.308 19.216-4.368 38.12-10.07 56.57-17.005 56.646-21.298 108.226-54.146 154.681-92.755 47.26-39.384 88.919-85.972 126.906-134.292 12.21-15.53 27.004-32.703 31.163-52.596 3.908-18.657-12.746-45.302-34.326-34.473-11.395 5.718-19.929 19.867-28.231 29.27-10.42 11.798-21.044 23.423-31.786 34.92-21.488 22.987-43.513 45.463-65.634 67.831-13.54 13.692-30.37 25.263-47.662 33.763-21.59 10.609-38.785-1.157-36.448-25.064 2.144-21.954 7.515-44.145 15.046-64.926 30.306-83.675 61.19-167.135 91.834-250.686 19.157-52.214 38.217-104.461 56.999-156.816 17.554-48.928 32.514-97.463 38.834-149.3 4.357-35.71-4.9-72.647-30.269-98.937Zm63.72-401.498c-91.342-35.538-200.232 25.112-218.574 121.757-13.25 69.784 13.336 131.23 67.998 157.155 105.765 50.16 232.284-29.954 232.29-147.084.005-64.997-28.612-111.165-81.715-131.828Z"
                fill-rule="evenodd"></path>
            </g>
          </svg>
          <span data-translate-it="Informazioni Account" data-translate-en="Account Information">Informazioni
            Account</span>
        </h4>
        <div style="color: #d1d5db; margin: 0;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"
              style="width: 16px; height: 16px; flex-shrink: 0;">
              <g id="SVGRepo_bgCarrier" stroke-width="0"></g>
              <g id="SVGRepo_tracerCarrier" stroke-linecap="round" stroke-linejoin="round"></g>
              <g id="SVGRepo_iconCarrier">
                <path
                  d="M7.75 2.5C7.75 2.08579 7.41421 1.75 7 1.75C6.58579 1.75 6.25 2.08579 6.25 2.5V4.07926C4.81067 4.19451 3.86577 4.47737 3.17157 5.17157C2.47737 5.86577 2.19451 6.81067 2.07926 8.25H21.9207C21.8055 6.81067 21.5226 5.86577 20.8284 5.17157C20.1342 4.47737 19.1893 4.19451 17.75 4.07926V2.5C17.75 2.08579 17.4142 1.75 17 1.75C16.5858 1.75 16.25 2.08579 16.25 2.5V4.0129C15.5847 4 14.839 4 14 4H10C9.16097 4 8.41527 4 7.75 4.0129V2.5Z"
                  fill="#ffffff"></path>
                <path fill-rule="evenodd" clip-rule="evenodd"
                  d="M22 12V14C22 17.7712 22 19.6569 20.8284 20.8284C19.6569 22 17.7712 22 14 22H10C6.22876 22 4.34315 22 3.17157 20.8284C2 19.6569 2 17.7712 2 14V12C2 11.161 2 10.4153 2.0129 9.75H21.9871C22 10.4153 22 11.161 22 12ZM16.5 18C17.3284 18 18 17.3284 18 16.5C18 15.6716 17.3284 15 16.5 15C15.6716 15 15 15.6716 15 16.5C15 17.3284 15.6716 18 16.5 18Z"
                  fill="#ffffff"></path>
              </g>
            </svg>
            <strong data-translate-it="Account creato il:" data-translate-en="Account created on:">Account
              creato il:</strong>
          </div>
          <div style="margin-top: 8px; margin-left: 24px;">
            <?php
                        if (!empty($user_data['created_at'])) {
                            $created_date = new DateTime($user_data['created_at']);
                            echo $created_date->format('d/m/Y') .
                                ' <span data-translate-it="alle" data-translate-en="at">alle</span> ' .
                                $created_date->format('H:i');
                        } else {
                            echo '<span data-translate-it="Data non disponibile" data-translate-en="Date not available">Data non disponibile</span>';
                        }
                        ?>
          </div>
        </div>
      </div>

      <div style="text-align: center; margin-top: 40px;">
        <button onclick="openDeleteModal()" class="btn btn-danger" data-translate-en="Delete Account"
          data-translate-it="Elimina Account">
          <i class="fas fa-trash-alt"></i>
          <span>Elimina Account</span>
        </button>
      </div>
    </div>
  </div>

  <div class="photo-modal-overlay" id="photoModal">
    <button class="close-modal" onclick="closePhotoModal()">
      <i class="fas fa-times"></i>
    </button>
    <div class="photo-modal">
      <?php if (!empty($user_data['profile_photo']) && file_exists($user_data['profile_photo'])): ?>
      <img src="<?php echo htmlspecialchars($user_data['profile_photo']); ?>" alt="Foto Profilo" class="enlarged-photo"
        style="width: 300px; height: 300px; border-radius: 50%; object-fit: cover;">
      <?php else: ?>
      <div class="enlarged-avatar">
        <?php echo strtoupper(substr($user_data['username'], 0, 1)); ?>
      </div>
      <?php endif; ?>

      <div class="photo-upload-form">
        <h4 style="margin-bottom: 20px; color: #1f2937; font-weight: 600;" data-translate-en="Change Profile Photo"
          data-translate-it="Cambia Foto Profilo">Cambia Foto Profilo
        </h4>
        <form method="POST" enctype="multipart/form-data" autocomplete="off" id="photoUploadForm">
          <div class="file-input-wrapper">
            <input type="file" id="profile_photo" name="profile_photo" accept="image/*" required
              onchange="previewImage(this)">
            <div class="file-input-content">
              <i class="fas fa-cloud-upload-alt" style="font-size: 24px; margin-bottom: 8px; color: #4f46e5;"></i>
              <p style="margin-bottom: 4px; font-weight: 500;" data-translate-en="Click to select an image"
                data-translate-it="Clicca per selezionare un'immagine">Clicca per selezionare
                un'immagine</p>
              <p style="font-size: 12px;">JPG, PNG, GIF - Max 5MB</p>
            </div>
          </div>

          <div style="display: flex; gap: 12px; justify-content: center;">
            <button type="submit" name="upload_photo" class="btn" id="uploadPhotoBtn" data-translate-en="Upload Photo"
              data-translate-it="Carica Foto">
              <i class="fas fa-upload"></i>
              <span>Carica Foto</span>
            </button>
            <button type="button" onclick="closePhotoModal()" class="btn btn-secondary" data-translate-en="Cancel"
              data-translate-it="Annulla">
              <i class="fas fa-times"></i>
              <span>Annulla</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>

  <div class="modal-overlay" id="deleteModal">
    <div class="modal">
      <h3 data-translate-en="Delete Account" data-translate-it="Elimina Account">
        <i class="fas fa-exclamation-triangle" style="color: #ed5252 !important; margin-right: 12px;"></i>
        <span>Elimina Account</span>
      </h3>

      <div class="delete-warning">
        <strong data-translate-it="Attenzione: Questa azione è irreversibile!"
          data-translate-en="Warning: This action is irreversible!">Attenzione: Questa azione è
          irreversibile!</strong>
        <p style="margin-top: 12px;" data-translate-it="Eliminando il tuo account:"
          data-translate-en="Deleting your account:">Eliminando il tuo account:</p>
        <ul>
          <li data-translate-it="Tutti i tuoi dati personali verranno permanentemente cancellati"
            data-translate-en="All your personal data will be permanently deleted">Tutti i tuoi dati
            personali verranno permanentemente cancellati</li>
          <li data-translate-it="Non potrai più accedere con questo account"
            data-translate-en="You will no longer be able to access this account">Non potrai più accedere
            con questo account</li>
          <li data-translate-it="Non sarà possibile recuperare i dati eliminati"
            data-translate-en="Deleted data cannot be recovered">Non sarà possibile recuperare i dati
            eliminati</li>
          <li data-translate-it="Tutte le tue informazioni verranno rimosse dai nostri server"
            data-translate-en="All your information will be removed from our servers">Tutte le tue
            informazioni verranno rimosse dai nostri server</li>
        </ul>
      </div>

      <form method="POST" id="deleteForm" autocomplete="off">
        <div class="form-group">
          <label for="delete_password" style="color: #dc2626; font-weight: 600;"
            data-translate-it="Inserisci la tua password per confermare"
            data-translate-en="Enter your password to confirm">Inserisci la tua password per
            confermare</label>
          <div class="input-container">
            <input type="password" id="delete_password" name="delete_password" required autocomplete="new-password"
              style="border-color: #fca5a5;">
            <i class="fas fa-eye password-toggle" onclick="togglePassword('delete_password')"></i>
          </div>
        </div>

        <div class="form-group">
          <label for="delete_confirmation" style="color: #dc2626; font-weight: 600;"
            data-translate-it="Digita &quot;delete my account&quot; per confermare definitivamente"
            data-translate-en="Type &quot;delete my account&quot; to confirm permanently">Digita "delete my
            account" per confermare definitivamente</label>
          <input type="text" id="delete_confirmation" name="delete_confirmation" required autocomplete="off"
            style="border-color: #fca5a5;" placeholder="delete my account">
        </div>

        <div class="modal-buttons">
          <button type="button" onclick="closeDeleteModal()" class="btn btn-secondary" data-translate-it="Annulla"
            data-translate-en="Cancel">
            <i class="fas fa-times"></i>
            <span>Annulla</span>
          </button>
          <button type="submit" name="delete_account" class="btn btn-danger" id="deleteAccountBtn"
            data-translate-it="Elimina Definitivamente" data-translate-en="Permanently Delete">
            <i class="fas fa-trash-alt"></i>
            <span>Elimina Definitivamente</span>
          </button>
        </div>
      </form>
    </div>
  </div>

  <footer class="site-footer">
    <div class="footer-buttons">
      <a href="https://rena.altervista.org/privacy-policy.html" class="footer-button">
        <svg class="footer-button-svg" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path
            d="M12 14.5V16.5M7 10.0288C7.47142 10 8.05259 10 8.8 10H15.2C15.9474 10 16.5286 10 17 10.0288M7 10.0288C6.41168 10.0647 5.99429 10.1455 5.63803 10.327C5.07354 10.6146 4.6146 11.0735 4.32698 11.638C4 12.2798 4 13.1198 4 14.8V16.2C4 17.8802 4 18.7202 4.32698 19.362C4.6146 19.9265 5.07354 20.3854 5.63803 20.673C6.27976 21 7.11984 21 8.8 21H15.2C16.8802 21 17.7202 21 18.362 20.673C18.9265 20.3854 19.3854 19.9265 19.673 19.362C20 18.7202 20 17.8802 20 16.2V14.8C20 13.1198 20 12.2798 19.673 11.638C19.3854 11.0735 18.9265 10.6146 18.362 10.327C18.0057 10.1455 17.5883 10.0647 17 10.0288M7 10.0288V8C7 5.23858 9.23858 3 12 3C14.7614 3 17 5.23858 17 8V10.0288"
            stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path>
        </svg>
        <span>Privacy Policy</span>
      </a>
    </div>
  </footer>

  <script>
    function togglePassword(fieldId) {
      const field = document.getElementById(fieldId);
      const toggle = field.nextElementSibling;

      if (field.type === 'password') {
        field.type = 'text';
        toggle.className = 'fas fa-eye-slash password-toggle';
      } else {
        field.type = 'password';
        toggle.className = 'fas fa-eye password-toggle';
      }
    }

    function togglePasswordFields() {
      const section = document.getElementById('passwordSection');
      const fields = document.getElementById('passwordFields');
      const chevron = document.getElementById('passwordChevron');

      if (fields.classList.contains('active')) {
        fields.classList.remove('active');
        section.classList.remove('active');
        chevron.className = 'fas fa-chevron-down';
      } else {
        fields.classList.add('active');
        section.classList.add('active');
        chevron.className = 'fas fa-chevron-up';
      }
    }

    function openPhotoModal() {
      document.getElementById('photoModal').classList.add('active');
      document.body.style.overflow = 'hidden';

      const currentPhotoElement = document.getElementById('currentPhoto');
      const enlargedPhotoElement = document.querySelector('.enlarged-photo');
      const enlargedAvatarElement = document.querySelector('.enlarged-avatar');

      if (currentPhotoElement && currentPhotoElement.tagName === 'IMG') {
        if (enlargedPhotoElement) {
          enlargedPhotoElement.src = currentPhotoElement.src;
          enlargedPhotoElement.style.display = 'block';
        }
        if (enlargedAvatarElement) {
          enlargedAvatarElement.style.display = 'none';
        }
      } else {
        if (enlargedPhotoElement) {
          enlargedPhotoElement.style.display = 'none';
        }
        if (enlargedAvatarElement) {
          enlargedAvatarElement.style.display = 'flex';
        }
      }
    }


    function closePhotoModal() {
      document.getElementById('photoModal').classList.remove('active');
      document.body.style.overflow = 'auto';
      document.getElementById('profile_photo').value = '';
    }

    function openDeleteModal() {
      document.getElementById('deleteModal').classList.add('active');
      document.body.style.overflow = 'hidden';
    }

    function closeDeleteModal() {
      document.getElementById('deleteModal').classList.remove('active');
      document.body.style.overflow = 'auto';
      document.getElementById('delete_password').value = '';
      document.getElementById('delete_confirmation').value = '';
    }

    function confirmDeletion() {
      const confirmation = document.getElementById('delete_confirmation').value.trim();
      if (confirmation.toLowerCase() !== 'delete my account') {
        alert('Devi digitare esattamente "delete my account" per confermare l\'eliminazione.');
        return false;
      }

      return confirm('Sei assolutamente sicuro di voler eliminare definitivamente il tuo account? Questa azione è irreversibile e tutti i tuoi dati verranno persi per sempre.');
    }

    function previewImage(input) {
      if (input.files && input.files[0]) {
        const reader = new FileReader();
        const fileSize = input.files[0].size / 1024 / 1024;

        if (fileSize > 5) {
          alert('Il file è troppo grande! La dimensione massima è 5MB.');
          input.value = '';
          return;
        }

        reader.onload = function (e) {
          const previewContainer = document.querySelector('.photo-modal');
          let preview = previewContainer.querySelector('.enlarged-photo, .enlarged-avatar');

          if (!preview || preview.classList.contains('enlarged-avatar')) {
            const img = document.createElement('img');
            img.src = e.target.result;
            img.className = 'enlarged-photo';
            img.style.objectFit = 'cover';

            if (preview) {
              preview.parentNode.replaceChild(img, preview);
            } else {
              previewContainer.insertBefore(img, previewContainer.firstChild);
            }
            preview = img;
          } else {
            preview.src = e.target.result;
          }
        }
        reader.readAsDataURL(input.files[0]);
      }
    }

    document.getElementById('photoModal').addEventListener('click', function (e) {
      if (e.target === this) {
        closePhotoModal();
      }
    });

    document.getElementById('deleteModal').addEventListener('click', function (e) {
      if (e.target === this) {
        closeDeleteModal();
      }
    });

    setTimeout(() => {
      const alerts = document.querySelectorAll('.alert');
      alerts.forEach(alert => {
        alert.style.opacity = '0';
        alert.style.transform = 'translateY(-10px)';
        setTimeout(() => {
          alert.style.display = 'none';
        }, 300);
      });
    }, 5000);

    document.addEventListener('DOMContentLoaded', function () {
      document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', function (e) {
          if (!this.id === 'deleteForm') {
            const submitBtn = this.querySelector('button[type="submit"]');
            if (submitBtn) {
              const originalText = submitBtn.innerHTML;
              submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Elaborazione...';
              submitBtn.disabled = true;

              setTimeout(() => {
                submitBtn.innerHTML = originalText;
                submitBtn.disabled = false;
              }, 5000);
            }
          }
        });
      });

      const passwordFields = document.querySelectorAll('input[type="password"]:not(#current_password)');
      passwordFields.forEach(field => {
        field.value = '';
        field.setAttribute('readonly', 'readonly');
        setTimeout(() => {
          field.removeAttribute('readonly');
        }, 100);
      });

      document.documentElement.style.scrollBehavior = 'smooth';
    });

    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') {
        if (document.getElementById('photoModal').classList.contains('active')) {
          closePhotoModal();
        }
        if (document.getElementById('deleteModal').classList.contains('active')) {
          closeDeleteModal();
        }
      }
    });
  </script>
  <style>
    a,
    button,
    text {
      cursor: url('cursore.png'), pointer;
    }

    body {
      cursor: url('cursore.png'), pointer;
    }

    * {
      scrollbar-width: none;
      -ms-overflow-style: none;
    }

    *::-webkit-scrollbar {
      display: none;
    }

    *:focus {
      outline: none;
    }

    button:focus,
    input:focus,
    textarea:focus {
      outline: none;
    }

    * {
      -webkit-tap-highlight-color: transparent;
    }

    ::selection {
      background-color: white;
      color: black;
    }
  </style>
  <img id="lingua" src="https://renadeveloper.altervista.org/bandierait.png" alt="Lingua"
    data-alt-src="https://renadeveloper.altervista.org/bandieraen.png">
<div id="error-popup"></div>

<div class="language-overlay" id="language-overlay"></div>
<div id="language-popup" class="language-popup">
    <span id="close-popup" class="close-popup">&times;</span>
    <h3 data-translate-en="Seleziona lingua" data-translate-it="Select language">Seleziona lingua</h3>
    
    <button class="language-btn" data-lang="it">
        <img src="https://renadeveloper.altervista.org/bandierait.png" alt="Italiano">
        <span>Italiano</span>
    </button>
    
    <button class="language-btn" data-lang="en">
        <img src="https://renadeveloper.altervista.org/bandieraen.png" alt="English">
        <span>English</span>
    </button>
</div>
  <style>
.language-popup {
    display: none;
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: 300px;
    background: rgba(0, 0, 0, 0.9);
    backdrop-filter: blur(15px);
    -webkit-backdrop-filter: blur(15px);
    border-radius: 16px;
    padding: 25px;
    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
    border: 1px solid rgba(255, 255, 255, 0.1);
    z-index: 1000;
    animation: fadeIn 0.3s ease-out;
}

@keyframes fadeIn {
    from { opacity: 0; transform: translate(-50%, -45%); }
    to { opacity: 1; transform: translate(-50%, -50%); }
}

.language-popup h3 {
    color: white;
    font-size: 18px;
    font-weight: 600;
    margin-bottom: 20px;
    text-align: center;
}

.language-btn {
    display: flex;
    align-items: center;
    width: 100%;
    padding: 12px 20px;
    margin-bottom: 12px;
    background: rgba(255, 255, 255, 0.05);
    color: white;
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 10px;
    font-size: 15px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.3s ease;
}

.language-btn:hover {
    background: rgba(255, 255, 255, 0.1);
    transform: translateY(-2px);
}

.language-btn.active {
    background: rgba(255, 255, 255, 0.15);
    border-color: white;
}

.language-btn img {
    width: 24px;
    margin-right: 12px;
    border-radius: 4px;
}

.close-popup {
    position: absolute;
    top: 15px;
    right: 15px;
    color: rgba(255, 255, 255, 0.6);
    font-size: 22px;
    cursor: pointer;
    transition: color 0.2s ease;
}

.close-popup:hover {
    color: white;
}

.language-overlay {
    display: none;
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.7);
    backdrop-filter: blur(5px);
    z-index: 999;
}

#lingua {
    cursor: pointer;
    width: 30px;
    position: absolute;
    top: 12px;
    right: 57px;
    transform: translateX(50%);
    border-radius: 20px;
    z-index: 1000;
}

@media screen and (max-width: 600px) {
    #lingua {
        margin-top: 30px;
        right: 50%;
    }
}
  </style>
  <script>
document.getElementById('lingua').addEventListener('click', function(e) {
    e.stopPropagation();
    document.getElementById('language-overlay').style.display = 'block';
    document.getElementById('language-popup').style.display = 'block';
});

function closeLanguagePopup() {
    document.getElementById('language-overlay').style.display = 'none';
    document.getElementById('language-popup').style.display = 'none';
}

document.getElementById('close-popup').addEventListener('click', closeLanguagePopup);
document.getElementById('language-overlay').addEventListener('click', closeLanguagePopup);

document.getElementById('language-popup').addEventListener('click', function(e) {
    e.stopPropagation();
});

function translatePage(lang) {
    localStorage.setItem('preferredLanguage', lang);
    
    document.querySelectorAll('[data-translate-it]').forEach(function(el) {
        el.textContent = el.getAttribute(`data-translate-${lang}`);
    });
    
    document.querySelectorAll('[data-placeholder-it]').forEach(function(el) {
        el.placeholder = el.getAttribute(`data-placeholder-${lang}`);
    });
    
    const flagImg = document.getElementById('lingua');
    flagImg.src = lang === 'it' 
        ? 'https://renadeveloper.altervista.org/bandierait.png'
        : 'https://renadeveloper.altervista.org/bandieraen.png';
    flagImg.alt = lang === 'it' ? 'Bandiera Italiana' : 'English Flag';
    
    document.title = lang === 'it' 
        ? 'Gestione Account - My Rena ID' 
        : 'Account Management - My Rena ID';
}

document.querySelectorAll('.language-btn').forEach(btn => {
    btn.addEventListener('click', function() {
        const lang = this.getAttribute('data-lang');
        translatePage(lang);
        closeLanguagePopup();
        
        document.querySelectorAll('.language-btn').forEach(b => b.classList.remove('active'));
        this.classList.add('active');
    });
});

document.addEventListener('DOMContentLoaded', function() {
    const savedLang = localStorage.getItem('preferredLanguage') || 'it';
    translatePage(savedLang);
    
    document.querySelector(`.language-btn[data-lang="${savedLang}"]`).classList.add('active');
});

document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        closeLanguagePopup();
    }
});

document.addEventListener('DOMContentLoaded', function() {
    const savedLang = localStorage.getItem('preferredLanguage') || 'it';
    translatePage(savedLang);

    document.querySelectorAll('.language-btn').forEach(btn => {
        if (btn.getAttribute('data-lang') === savedLang) {
            btn.classList.add('active');
        }
        
        btn.addEventListener('click', function() {
            const lang = this.getAttribute('data-lang');
            translatePage(lang);
            closeLanguagePopup();
            
            document.querySelectorAll('.language-btn').forEach(b => b.classList.remove('active'));
            this.classList.add('active');
        });
    });
});

document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        closeLanguagePopup();
    }
});
  </script>
</body>

</html>

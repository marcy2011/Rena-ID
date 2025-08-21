<?php
session_name('cross_domain_auth');
session_start();

header('Content-Type: application/json');
header("Access-Control-Allow-Origin: https://renadeveloper.altervista.org");
header("Access-Control-Allow-Origin: https://renaarcade.altervista.org");
header("Access-Control-Allow-Origin: https://renastore.altervista.org");
header("Access-Control-Allow-Origin: https://renasupporto.altervista.org");
header("Access-Control-Allow-Methods: GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");

if (!isset($_GET['token'])) {
  die(json_encode(['status' => 'error', 'message' => 'Token mancante']));
}

$token = $_GET['token'];

if (isset($_SESSION['cross_domain_token']) && $_SESSION['cross_domain_token'] === $token) {
  $host = "localhost";
  $user = "rena";
  $pass = "pXUbBf42ySR6";
  $dbname = "my_rena";

  $conn = new mysqli($host, $user, $pass, $dbname);

  $profile_photo = null;
  if (!$conn->connect_error) {
    $user_id = $_SESSION['user_id'];
    $sql = "SELECT profile_photo FROM users WHERE id = '$user_id'";
    $result = $conn->query($sql);

    if ($result->num_rows > 0) {
      $user = $result->fetch_assoc();
      if (!empty($user['profile_photo'])) {
        if (!empty($user['profile_photo'])) {
          if (filter_var($user['profile_photo'], FILTER_VALIDATE_URL)) {
            $profile_photo = $user['profile_photo'];
          } else if (strpos($user['profile_photo'], 'uploads/profile_photos/') !== false) {
            if (strpos($user['profile_photo'], 'https://') === 0 || strpos($user['profile_photo'], 'http://') === 0) {
              $profile_photo = $user['profile_photo'];
            } else {
              $relative_path = str_replace('uploads/profile_photos/', '', $user['profile_photo']);
              $profile_photo = 'https://rena.altervista.org/uploads/profile_photos/' . $relative_path;
            }
          } else {
            $profile_photo = 'https://rena.altervista.org/uploads/profile_photos/' . $user_id . '/' . $user['profile_photo'];
          }

          $file_path = $_SERVER['DOCUMENT_ROOT'] . '/uploads/profile_photos/' . $user_id . '/' . basename($user['profile_photo']);
          if (!file_exists($file_path)) {
            error_log("File immagine non trovato: " . $file_path);
            $profile_photo = null;
          }
        }
      }
    }
    $conn->close();
  }

  echo json_encode([
    'status' => 'success',
    'user_id' => $_SESSION['user_id'],
    'username' => $_SESSION['username'],
    'profile_photo' => $profile_photo
  ]);
} else {
  echo json_encode(['status' => 'error', 'message' => 'Token non valido']);
}
?>

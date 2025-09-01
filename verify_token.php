<?php
session_name('cross_domain_auth');
session_start();

header('Content-Type: application/json');
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Access-Control-Allow-Credentials: true');

$allowed_origins = [
  "https://renadeveloper.altervista.org",
  "https://renaarcade.altervista.org",
  "https://renastore.altervista.org",
  "https://renasupporto.altervista.org"
];

if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(200);
    exit(0);
}

if (isset($_SERVER['HTTP_ORIGIN']) && in_array($_SERVER['HTTP_ORIGIN'], $allowed_origins)) {
    header("Access-Control-Allow-Origin: " . $_SERVER['HTTP_ORIGIN']);
    header("Vary: Origin");
}

if (!isset($_GET['token'])) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Token mancante']);
    exit;
}

$token = $_GET['token'];

try {
    if (isset($_SESSION['cross_domain_token']) && $_SESSION['cross_domain_token'] === $token) {
        $host = "localhost";
        $user = "rena";
        $pass = "PASS";
        $dbname = "my_rena";

        $conn = new mysqli($host, $user, $pass, $dbname);

        $profile_photo = null;
        if (!$conn->connect_error) {
            $user_id = $_SESSION['user_id'];
            $sql = "SELECT profile_photo FROM users WHERE id = ?";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows > 0) {
                $user = $result->fetch_assoc();
                if (!empty($user['profile_photo'])) {
                    $profile_photo = 'https://rena.altervista.org/uploads/profile_photos/' . $user_id . '/' . $user['profile_photo'];
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
        http_response_code(401);
        echo json_encode(['status' => 'error', 'message' => 'Token non valido']);
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Errore del server: ' . $e->getMessage()]);
}
?>

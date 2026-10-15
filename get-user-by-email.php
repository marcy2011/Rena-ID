<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

$db = new mysqli('localhost', 'username', 'password', 'my_rena');

if ($db->connect_error) {
    http_response_code(500);
    echo json_encode(['error' => true, 'message' => 'Database connection failed']);
    exit();
}

$email = '';
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['email'])) {
    $email = $_GET['email'];
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $email = $input['email'] ?? '';
}

if (empty($email)) {
    http_response_code(400);
    echo json_encode(['error' => true, 'message' => 'Email is required']);
    exit();
}

$email = $db->real_escape_string(trim($email));
$sql = "SELECT id, username, email, profile_photo, created_at, source FROM users WHERE email = '$email'";
$result = $db->query($sql);

if ($result === false) {
    http_response_code(500);
    echo json_encode(['error' => true, 'message' => 'Database query failed']);
    $db->close();
    exit();
}

if ($result->num_rows > 0) {
    $user = $result->fetch_assoc();
    echo json_encode([
        'exists' => true,
        'user' => $user
    ]);
} else {
    echo json_encode([
        'exists' => false
    ]);
}

$db->close();
?>
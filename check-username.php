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

$username = '';
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['username'])) {
    $username = $_GET['username'];
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $username = $input['username'] ?? '';
}

if (empty($username)) {
    http_response_code(400);
    echo json_encode(['error' => true, 'message' => 'Username is required']);
    exit();
}

$username = $db->real_escape_string(trim($username));
$sql = "SELECT username FROM users WHERE username = '$username'";
$result = $db->query($sql);

if ($result === false) {
    http_response_code(500);
    echo json_encode(['error' => true, 'message' => 'Database query failed']);
    $db->close();
    exit();
}

echo json_encode([
    'available' => ($result->num_rows === 0),
    'username' => $username
]);

$db->close();
?>
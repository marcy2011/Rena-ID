<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => true, 'message' => 'Method not allowed']);
    exit();
}

$db = new mysqli('localhost', 'username', 'password', 'my_rena');

if ($db->connect_error) {
    http_response_code(500);
    echo json_encode(['error' => true, 'message' => 'Database connection failed']);
    exit();
}

$input = json_decode(file_get_contents('php://input'), true);

$user_id = $input['user_id'] ?? 0;
$profile_photo = $input['profile_photo'] ?? null;

if (empty($user_id)) {
    http_response_code(400);
    echo json_encode(['error' => true, 'message' => 'User ID is required']);
    $db->close();
    exit();
}

$user_id = intval($user_id);
$photo_value = $profile_photo ? "'" . $db->real_escape_string($profile_photo) . "'" : 'NULL';

$sql = "UPDATE users SET profile_photo = $photo_value WHERE id = $user_id";

if ($db->query($sql) === TRUE) {
    if ($db->affected_rows > 0) {
        echo json_encode(['success' => true, 'message' => 'Profile photo updated']);
    } else {
        echo json_encode(['success' => true, 'message' => 'No changes made']);
    }
} else {
    http_response_code(500);
    echo json_encode(['error' => true, 'message' => 'Failed to update profile photo']);
}

$db->close();
?>
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

$username = $input['username'] ?? '';
$email = $input['email'] ?? '';
$source = $input['source'] ?? 'manual';
$profile_photo = $input['profile_photo'] ?? null;

if (empty($username)) {
    http_response_code(400);
    echo json_encode(['error' => true, 'message' => 'Username is required']);
    $db->close();
    exit();
}

$username = $db->real_escape_string(trim($username));
$email = $db->real_escape_string(trim($email));
$source = $db->real_escape_string(trim($source));
$profile_photo = $profile_photo ? $db->real_escape_string($profile_photo) : null;

$check_sql = "SELECT id FROM users WHERE username = '$username'";
$result = $db->query($check_sql);

if ($result->num_rows > 0) {
    http_response_code(409);
    echo json_encode(['error' => true, 'message' => 'Username already exists']);
    $db->close();
    exit();
}

if (!empty($email)) {
    $check_email_sql = "SELECT id FROM users WHERE email = '$email'";
    $email_result = $db->query($check_email_sql);
    
    if ($email_result->num_rows > 0) {
        http_response_code(409);
        echo json_encode(['error' => true, 'message' => 'Email already exists']);
        $db->close();
        exit();
    }
}

$password_value = ($source === 'base44_google') ? 'NULL' : "'" . password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT) . "'";
$email_value = empty($email) ? 'NULL' : "'$email'";
$photo_value = $profile_photo ? "'$profile_photo'" : 'NULL';

$sql = "INSERT INTO users (username, email, password, profile_photo, created_at, source) 
        VALUES ('$username', $email_value, $password_value, $photo_value, NOW(), '$source')";

if ($db->query($sql) === TRUE) {
    $user_id = $db->insert_id;
    
    $token = bin2hex(random_bytes(32));
    $token_expiry = date('Y-m-d H:i:s', strtotime('+30 days'));
    
    $token_sql = "INSERT INTO user_tokens (user_id, token, expires_at) 
                  VALUES ($user_id, '$token', '$token_expiry')
                  ON DUPLICATE KEY UPDATE token = '$token', expires_at = '$token_expiry'";
    $db->query($token_sql);
    
    echo json_encode([
        'success' => true,
        'user_id' => $user_id,
        'username' => $username,
        'token' => $token,
        'message' => 'User created successfully'
    ]);
} else {
    http_response_code(500);
    echo json_encode(['error' => true, 'message' => 'Failed to create user: ' . $db->error]);
}

$db->close();
?>
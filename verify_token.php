<?php
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Access-Control-Allow-Credentials: true');

$allowed_origins = [
    'https://renadeveloper.altervista.org',
    'https://renaarcade.altervista.org',
    'https://renaai.altervista.org',
    'https://renastore.altervista.org',
    'https://renasupporto.altervista.org',
];
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin !== '' && in_array($origin, $allowed_origins, true)) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Vary: Origin');
}

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['status' => 'error', 'valid' => false, 'message' => 'Metodo non consentito']);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);
$token = is_array($input) ? ($input['token'] ?? '') : '';
if (!is_string($token) || $token === '') {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'valid' => false, 'message' => 'Token mancante']);
    exit;
}

try {
    require_once __DIR__ . '/config_id.php';
    require_once __DIR__ . '/rena-security.php';
    $db = db();
    rena_security_schema($db);
    $tokenHash = hash('sha256', $token);
    $sessionStmt = $db->prepare('SELECT user_id, device_id FROM rena_service_sessions WHERE token_hash = ? AND expires_at > NOW()');
    $sessionStmt->bind_param('s', $tokenHash);
    $sessionStmt->execute();
    $serviceSession = $sessionStmt->get_result()->fetch_assoc();
    $sessionStmt->close();

    if (!$serviceSession) {
        http_response_code(401);
        echo json_encode(['status' => 'error', 'valid' => false, 'message' => 'Token non valido o revocato']);
        exit;
    }
    $userId = (int)$serviceSession['user_id'];
    if (!empty($serviceSession['device_id'])) {
        $touch = $db->prepare('UPDATE rena_device_sessions SET last_seen = NOW() WHERE device_id = ? AND user_id = ? AND revoked_at IS NULL');
        $touch->bind_param('si', $serviceSession['device_id'], $userId); $touch->execute(); $touch->close();
    }
    $stmt = db()->prepare('SELECT username, profile_photo, preferred_language FROM users WHERE id = ?');
    $stmt->bind_param('i', $userId);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    if (!$user) {
        http_response_code(401);
        echo json_encode(['status' => 'error', 'valid' => false, 'message' => 'Utente non trovato']);
        exit;
    }

    $profilePhoto = null;
    if (!empty($user['profile_photo'])) {
        $profilePhoto = preg_match('#^https?://#i', $user['profile_photo'])
            ? $user['profile_photo']
            : 'https://rena.altervista.org/' . ltrim($user['profile_photo'], '/');
    }
    echo json_encode([
        'status' => 'success',
        'valid' => true,
        'user_id' => $userId,
        'username' => $user['username'],
        'profile_photo' => $profilePhoto,
        'preferred_language' => in_array(($user['preferred_language'] ?? 'it'), ['it', 'en'], true) ? $user['preferred_language'] : 'it',
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
} catch (Throwable $e) {
    error_log('Errore verify_token.php: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'valid' => false, 'message' => 'Errore del server']);
}
?>

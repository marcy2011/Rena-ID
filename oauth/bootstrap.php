<?php
function rena_db() {
    static $db = null;
    if ($db === null) {
        mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
        $db = new mysqli('localhost', 'DB_USER', 'DB_PASS', 'my_rena');
        $db->set_charset('utf8mb4');
    }
    return $db;
}

function rena_json($data, $status = 200) {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('Pragma: no-cache');
    echo json_encode($data);
    exit;
}

function rena_oauth_error($error, $description, $status = 400) {
    rena_json(['error' => $error, 'error_description' => $description], $status);
}

function rena_hash_token($token) {
    return hash('sha256', $token);
}

function rena_get_client($clientId) {
    if (!is_string($clientId) || !preg_match('/^[A-Za-z0-9_\-]{1,40}$/', $clientId)) return null;
    $stmt = rena_db()->prepare('SELECT client_id, client_secret_hash, name, redirect_uris FROM oauth_clients WHERE client_id = ?');
    $stmt->bind_param('s', $clientId);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    return $row ?: null;
}

function rena_redirect_allowed($client, $uri) {
    $list = json_decode($client['redirect_uris'], true);
    return is_array($list) && is_string($uri) && in_array($uri, $list, true);
}

function rena_photo_url($userId, $photo) {
    if (empty($photo)) return null;
    if (preg_match('#^https?://#i', $photo)) return $photo;
    if (strpos($photo, 'uploads/profile_photos/') !== false) {
        return 'https://rena.altervista.org/uploads/profile_photos/' . str_replace('uploads/profile_photos/', '', $photo);
    }
    return 'https://rena.altervista.org/uploads/profile_photos/' . $userId . '/' . $photo;
}

function rena_b64url($raw) {
    return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
}

function rena_gc() {
    $db = rena_db();
    $db->query('DELETE FROM oauth_codes WHERE expires_at < (NOW() - INTERVAL 1 DAY)');
    $db->query('DELETE FROM oauth_tokens WHERE expires_at < NOW()');
}

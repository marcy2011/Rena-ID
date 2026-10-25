<?php
require_once __DIR__ . '/rena-session.php';
rena_session_start();
require __DIR__ . '/config_id.php';
require_once __DIR__ . '/rena-security.php';
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

function respond(array $data, int $status = 200): void {
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

$uid = (int)($_SESSION['user_id'] ?? 0);
if (!$uid) respond(['success' => false, 'error' => 'Sessione scaduta'], 401);
if (empty($_SESSION['services_csrf'])) $_SESSION['services_csrf'] = bin2hex(random_bytes(32));
$db = db();
rena_security_schema($db);

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $internal = [];
    $stmt = $db->prepare('SELECT service_host, MAX(created_at) AS last_used, COUNT(*) AS session_count FROM rena_service_sessions WHERE user_id = ? AND expires_at > NOW() GROUP BY service_host ORDER BY last_used DESC');
    $stmt->bind_param('i', $uid);
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) $internal[] = $row;
    $stmt->close();

    $external = [];
    $stmt = $db->prepare('SELECT c.client_id, c.name, MAX(t.expires_at) AS expires_at, COUNT(*) AS token_count FROM oauth_tokens t JOIN oauth_clients c ON c.client_id = t.client_id WHERE t.user_id = ? AND t.expires_at > NOW() GROUP BY c.client_id, c.name ORDER BY expires_at DESC');
    $stmt->bind_param('i', $uid);
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) $external[] = $row;
    $stmt->close();

    $devices = [];
    $stmt = $db->prepare('SELECT device_id, device_name, user_agent, ip_address, created_at, last_seen FROM rena_device_sessions WHERE user_id = ? AND revoked_at IS NULL AND last_seen >= NOW() - INTERVAL 180 DAY ORDER BY last_seen DESC');
    $stmt->bind_param('i', $uid); $stmt->execute(); $result = $stmt->get_result();
    while ($device = $result->fetch_assoc()) {
        $device['services'] = [];
        $devices[$device['device_id']] = $device;
    }
    $stmt->close();
    if ($devices) {
        $stmt = $db->prepare('SELECT device_id, service_host AS service_name, created_at, expires_at, "Rena" AS service_type FROM rena_service_sessions WHERE user_id = ? AND expires_at > NOW() AND device_id IS NOT NULL');
        $stmt->bind_param('i', $uid); $stmt->execute(); $result = $stmt->get_result();
        while ($service = $result->fetch_assoc()) if (isset($devices[$service['device_id']])) $devices[$service['device_id']]['services'][] = $service;
        $stmt->close();
        $stmt = $db->prepare('SELECT t.device_id, c.name AS service_name, t.expires_at, "OAuth" AS service_type FROM oauth_tokens t JOIN oauth_clients c ON c.client_id = t.client_id WHERE t.user_id = ? AND t.expires_at > NOW() AND t.device_id IS NOT NULL');
        $stmt->bind_param('i', $uid); $stmt->execute(); $result = $stmt->get_result();
        while ($service = $result->fetch_assoc()) if (isset($devices[$service['device_id']])) $devices[$service['device_id']]['services'][] = $service;
        $stmt->close();
    }
    respond(['success' => true, 'csrf' => $_SESSION['services_csrf'], 'internal' => $internal, 'external' => $external, 'devices' => array_values($devices), 'current_device_id' => (string)($_SESSION['device_id'] ?? '')]);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') respond(['success' => false, 'error' => 'Metodo non supportato'], 405);
$input = json_decode(file_get_contents('php://input'), true);
if (!is_array($input) || !hash_equals($_SESSION['services_csrf'], (string)($input['csrf'] ?? ''))) respond(['success' => false, 'error' => 'Sessione scaduta, ricarica la pagina'], 403);
$action = (string)($input['action'] ?? '');

if ($action === 'csrf') respond(['success' => true, 'csrf' => $_SESSION['services_csrf']]);
if ($action === 'revoke_internal') {
    $host = strtolower(trim((string)($input['service_host'] ?? '')));
    if (!preg_match('/^(?:[a-z0-9-]+\.)*rena(?:developer|store|arcade|ai|supporto)?\.altervista\.org$/', $host)) respond(['success' => false, 'error' => 'Servizio non valido'], 400);
    $stmt = $db->prepare('DELETE FROM rena_service_sessions WHERE user_id = ? AND service_host = ?');
    $stmt->bind_param('is', $uid, $host);
    $stmt->execute();
    $stmt->close();
    respond(['success' => true]);
}
if ($action === 'revoke_device' || $action === 'revoke_all') {
    $deviceId = (string)($input['device_id'] ?? '');
    if ($action === 'revoke_device') {
        $stmt = $db->prepare('SELECT device_id FROM rena_device_sessions WHERE device_id = ? AND user_id = ?');
        $stmt->bind_param('si', $deviceId, $uid); $stmt->execute(); $exists = (bool)$stmt->get_result()->fetch_assoc(); $stmt->close();
        if (!$exists) respond(['success' => false, 'error' => 'Dispositivo non trovato'], 404);
        $stmt = $db->prepare('DELETE FROM rena_service_sessions WHERE user_id = ? AND device_id = ?');
        $stmt->bind_param('is', $uid, $deviceId); $stmt->execute(); $stmt->close();
        $stmt = $db->prepare('DELETE FROM oauth_tokens WHERE user_id = ? AND device_id = ?');
        $stmt->bind_param('is', $uid, $deviceId); $stmt->execute(); $stmt->close();
        $stmt = $db->prepare('UPDATE rena_device_sessions SET revoked_at = NOW() WHERE device_id = ? AND user_id = ?');
        $stmt->bind_param('si', $deviceId, $uid); $stmt->execute(); $stmt->close();
        respond(['success' => true, 'current' => hash_equals((string)($_SESSION['device_id'] ?? ''), $deviceId)]);
    }
    $stmt = $db->prepare('DELETE FROM rena_service_sessions WHERE user_id = ?'); $stmt->bind_param('i', $uid); $stmt->execute(); $stmt->close();
    $stmt = $db->prepare('DELETE FROM oauth_tokens WHERE user_id = ?'); $stmt->bind_param('i', $uid); $stmt->execute(); $stmt->close();
    $stmt = $db->prepare('UPDATE rena_device_sessions SET revoked_at = NOW() WHERE user_id = ? AND revoked_at IS NULL'); $stmt->bind_param('i', $uid); $stmt->execute(); $stmt->close();
    respond(['success' => true, 'current' => true]);
}
if ($action === 'revoke_external') {
    $clientId = (string)($input['client_id'] ?? '');
    $stmt = $db->prepare('SELECT client_id FROM oauth_clients WHERE client_id = ?');
    $stmt->bind_param('s', $clientId);
    $stmt->execute();
    $exists = (bool)$stmt->get_result()->fetch_assoc();
    $stmt->close();
    if (!$exists) respond(['success' => false, 'error' => 'Servizio non trovato'], 404);
    $stmt = $db->prepare('DELETE FROM oauth_tokens WHERE user_id = ? AND client_id = ?');
    $stmt->bind_param('is', $uid, $clientId);
    $stmt->execute();
    $stmt->close();
    respond(['success' => true]);
}
respond(['success' => false, 'error' => 'Azione sconosciuta'], 400);

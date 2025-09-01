<?php
header('Content-Type: application/json');
header("Access-Control-Allow-Origin: https://renadeveloper.altervista.org"); 
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");

if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(200);
    exit(0);
}

$host = "localhost";
$user = "rena";
$pass = "PASS";
$dbname = "my_rena";

$conn = new mysqli($host, $user, $pass, $dbname);
if ($conn->connect_error) {
    die(json_encode(["error" => "Connessione al database fallita"]));
}

function verifyApiToken() {
    $headers = getallheaders();
    $token = isset($headers['Authorization']) ? str_replace('Bearer ', '', $headers['Authorization']) : '';
    
    if (empty($token)) {
        return false;
    }
    
    session_id('cross_domain_auth');
    session_start();
    
    $isValid = isset($_SESSION['cross_domain_token']) && $_SESSION['cross_domain_token'] === $token;
    
    session_write_close();
    session_id(session_create_id());
    session_start();
    
    return $isValid;
}

function getProfilePhotoUrl($user_id, $profile_photo) {
    if (empty($profile_photo)) {
        return null;
    }
    
    if (filter_var($profile_photo, FILTER_VALIDATE_URL)) {
        return $profile_photo;
    }
    
    if (strpos($profile_photo, 'uploads/profile_photos/') !== false) {
        if (strpos($profile_photo, 'https://') === 0 || strpos($profile_photo, 'http://') === 0) {
            return $profile_photo;
        }
        
        $relative_path = str_replace('uploads/profile_photos/', '', $profile_photo);
        return 'https://rena.altervista.org/uploads/profile_photos/' . $relative_path;
    }
    
    return 'https://rena.altervista.org/uploads/profile_photos/' . $user_id . '/' . $profile_photo;
}

if (isset($_GET['action']) && $_GET['action'] === 'get_user_data') {
    if (!verifyApiToken()) {
        echo json_encode(['error' => 'Token non valido']);
        exit();
    }
    
    session_id('cross_domain_auth');
    session_start();
    
    $user_id = $_SESSION['user_id'];
    
    $sql = "SELECT id, username, profile_photo FROM users WHERE id = '$user_id'";
    $result = $conn->query($sql);
    
    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        
        $profile_photo = getProfilePhotoUrl($user['id'], $user['profile_photo']);
        
        $userData = [
            'user_id' => $user['id'],
            'username' => $user['username'],
            'profile_photo' => $profile_photo
        ];
        
        echo json_encode($userData);
    } else {
        echo json_encode(['error' => 'Utente non trovato']);
    }
    
    session_write_close();
    exit();
}

$whitelist = include 'redirect_whitelist.php';

function isAllowedRedirect($url, $whitelist) {
    if (empty($url)) return false;

    $parsed = parse_url($url);
    $cleanUrl = ($parsed['scheme'] ?? 'https') . '://' .
        ($parsed['host'] ?? 'rena.altervista.org') .
        rtrim($parsed['path'] ?? '', '/');

    foreach ($whitelist as $allowed) {
        $parsedAllowed = parse_url($allowed);
        $cleanAllowed = ($parsedAllowed['scheme'] ?? 'https') . '://' .
            ($parsedAllowed['host'] ?? 'rena.altervista.org') .
            rtrim($parsedAllowed['path'] ?? '', '/');

        if ($cleanUrl === $cleanAllowed) {
            return true;
        }
    }
    return false;
}

if (isset($_GET['action']) && $_GET['action'] === 'check_redirect') {
    $url = $_GET['url'] ?? '';
    echo json_encode(['allowed' => isAllowedRedirect($url, $whitelist)]);
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'login') {
    $username = $conn->real_escape_string($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    $sql = "SELECT id, username, email, profile_photo FROM users WHERE username = '$username' AND password = '$password'";
    $result = $conn->query($sql);

    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        
        $profile_photo = getProfilePhotoUrl($user['id'], $user['profile_photo']);
        
        $redirect = 'dashboard.html';
        if (!empty($_POST['redirect_url']) && isAllowedRedirect($_POST['redirect_url'], $whitelist)) {
            $redirect = $_POST['redirect_url'];
        }

        echo json_encode([
            'success' => true,
            'user' => [
                'id' => $user['id'],
                'username' => $user['username'],
                'email' => $user['email'],
                'profile_photo' => $profile_photo
            ],
            'redirect' => $redirect
        ]);
    } else {
        echo json_encode(['error' => 'Credenziali non valide']);
    }
    exit();
}

if (isset($_GET['action']) && $_GET['action'] === 'get_all_users') {
    $query = "SELECT id, username, email, profile_photo FROM users";
    $result = $conn->query($query);

    $data = [];
    while ($row = $result->fetch_assoc()) {
        if (!empty($row['profile_photo'])) {
            $row['profile_photo'] = getProfilePhotoUrl($row['id'], $row['profile_photo']);
        }
        $data[] = $row;
    }
    echo json_encode($data);
    exit();
}

$query = "SELECT id, username, email, profile_photo FROM users";
$result = $conn->query($query);

$data = [];
while ($row = $result->fetch_assoc()) {
    if (!empty($row['profile_photo'])) {
        $row['profile_photo'] = getProfilePhotoUrl($row['id'], $row['profile_photo']);
    }
    $data[] = $row;
}
echo json_encode($data);

$conn->close();
?>

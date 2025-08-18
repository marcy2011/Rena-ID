<?php
header('Content-Type: application/json');
header("Access-Control-Allow-Origin: https://tuosecondodominio.com"); 
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");

$host = "localhost";
$user = "rena";
$pass = "pXUbBf42ySR6";
$dbname = "my_rena";

$conn = new mysqli($host, $user, $pass, $dbname);
if ($conn->connect_error) {
    die(json_encode(["error" => "Connessione al database fallita"]));
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

    $sql = "SELECT id, username, email FROM users WHERE username = '$username' AND password = '$password'";
    $result = $conn->query($sql);

    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        
        $redirect = 'dashboard.html';
        if (!empty($_POST['redirect_url']) && isAllowedRedirect($_POST['redirect_url'], $whitelist)) {
            $redirect = $_POST['redirect_url'];
        }

        echo json_encode([
            'success' => true,
            'user' => $user,
            'redirect' => $redirect
        ]);
    } else {
        echo json_encode(['error' => 'Credenziali non valide']);
    }
    exit();
}

$query = "SELECT * FROM users";
$result = $conn->query($query);

$data = [];
while ($row = $result->fetch_assoc()) {
    $data[] = $row;
}
echo json_encode($data);

$conn->close();
?>

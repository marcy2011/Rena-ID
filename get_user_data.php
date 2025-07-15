<?php
ob_start();

session_start();

ob_clean();

header('Content-Type: application/json; charset=utf-8');

header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

$response = array();

try {
    if (isset($_SESSION['user_id']) && !empty($_SESSION['user_id'])) {
        $response['logged_in'] = true;
        $response['username'] = isset($_SESSION['username']) ? $_SESSION['username'] : 'Utente';
        $response['profile_pic'] = isset($_SESSION['profile_pic']) ? $_SESSION['profile_pic'] : null;
        $response['user_id'] = $_SESSION['user_id'];
    } else {
        $response['logged_in'] = false;
    }
    
    $response['debug'] = array(
        'session_id' => session_id(),
        'session_data' => $_SESSION,
        'timestamp' => date('Y-m-d H:i:s')
    );
    
} catch (Exception $e) {
    $response['logged_in'] = false;
    $response['error'] = $e->getMessage();
}

echo json_encode($response);

ob_end_flush();
?>

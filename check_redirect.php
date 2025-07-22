<?php
session_start();
$whitelist = include 'redirect_whitelist.php';

function isAllowedRedirect($url, $whitelist) {
    if (empty($url)) return false;
    
    $parsed = parse_url($url);
    $cleanUrl = ($parsed['scheme'] ?? 'https') . '://' . 
                ($parsed['host'] ?? 'rena.altervista.org') . 
                ($parsed['path'] ?? '');
    
    foreach ($whitelist as $allowed) {
        if ($cleanUrl === $allowed) {
            return true;
        }
    }
    return false;
}

header('Content-Type: application/json');
$url = $_GET['url'] ?? '';
echo json_encode(['allowed' => isAllowedRedirect($url, $whitelist)]);
<?php
const RENA_SESSION_LIFETIME = 2592000;
const RENA_SESSION_SHORT_IDLE = 1440;

function rena_session_start(): bool
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return true;
    }

    $dir = __DIR__ . '/sessions_private';
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
    if (is_dir($dir) && is_writable($dir)) {
        $ht = $dir . '/.htaccess';
        if (!file_exists($ht)) {
            @file_put_contents($ht, "Require all denied\nDeny from all\n");
        }
        session_save_path($dir);
    }

    ini_set('session.gc_maxlifetime', (string)RENA_SESSION_LIFETIME);
    ini_set('session.gc_probability', '1');
    ini_set('session.gc_divisor', '100');

    $persistentCookie = ($_COOKIE['rena_keep_signed_in'] ?? '') === '1';

    $started = session_start();
    if (!$started) {
        return false;
    }

    if (empty($_SESSION['rena_keep_signed_in'])) {
        $last = (int)($_SESSION['rena_last_activity'] ?? 0);
        if ($last && time() - $last > RENA_SESSION_SHORT_IDLE) {
            $_SESSION = [];
        }
        $_SESSION['rena_last_activity'] = time();
    }

    if ($persistentCookie && !headers_sent() && !empty($_SESSION['rena_keep_signed_in'])) {
        $params = session_get_cookie_params();
        $expires = time() + RENA_SESSION_LIFETIME;
        setcookie('rena_keep_signed_in', '1', [
            'expires' => $expires,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Lax'
        ]);
        setcookie(session_name(), session_id(), [
            'expires' => $expires,
            'path' => $params['path'],
            'domain' => $params['domain'],
            'secure' => true,
            'httponly' => $params['httponly'],
            'samesite' => ($params['samesite'] ?? '') ?: 'Lax'
        ]);
    }

    return $started;
}

function rena_set_session_persistence(bool $enabled): void
{
    $_SESSION['rena_keep_signed_in'] = $enabled;
    if (session_status() !== PHP_SESSION_ACTIVE || headers_sent()) {
        return;
    }

    $params = session_get_cookie_params();
    $expires = $enabled ? time() + RENA_SESSION_LIFETIME : 0;
    setcookie('rena_keep_signed_in', $enabled ? '1' : '', [
        'expires' => $enabled ? $expires : time() - 3600,
        'path' => '/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Lax'
    ]);
    setcookie(session_name(), session_id(), [
        'expires' => $expires,
        'path' => $params['path'],
        'domain' => $params['domain'],
        'secure' => true,
        'httponly' => $params['httponly'],
        'samesite' => ($params['samesite'] ?? '') ?: 'Lax'
    ]);
}

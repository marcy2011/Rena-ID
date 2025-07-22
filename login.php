<?php
session_start();
$db = new mysqli('localhost', 'username', 'password', 'my_rena');

$whitelist = include 'redirect_whitelist.php';

function isAllowedRedirect($url, $whitelist)
{
    if (empty($url))
        return false;

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

if (isset($_GET['redirect']) && !empty($_GET['redirect'])) {
    $cleanRedirect = filter_var($_GET['redirect'], FILTER_SANITIZE_URL);
    if (isAllowedRedirect($cleanRedirect, $whitelist)) {
        $_SESSION['redirect_after_login'] = $cleanRedirect;
        error_log("Redirect URL impostato: " . $cleanRedirect);
    } else {
        error_log("Redirect non permesso: " . $cleanRedirect);
        $_SESSION['redirect_after_login'] = 'account.php';
    }
} elseif (isset($_SERVER['HTTP_REFERER']) && !empty($_SERVER['HTTP_REFERER'])) {
    $referer = filter_var($_SERVER['HTTP_REFERER'], FILTER_SANITIZE_URL);
    if (isAllowedRedirect($referer, $whitelist)) {
        $_SESSION['redirect_after_login'] = $referer;
        error_log("HTTP_REFERER impostato come redirect: " . $referer);
    } else {
        error_log("HTTP_REFERER non permesso: " . $referer);
        $_SESSION['redirect_after_login'] = 'account.php';
    }
} else {
    $_SESSION['redirect_after_login'] = 'account.php';
    error_log("Nessun redirect specificato, uso default");
}

if (isset($_SERVER['HTTP_REFERER'])) {
    error_log("HTTP_REFERER: " . $_SERVER['HTTP_REFERER']);
    if (isAllowedRedirect($_SERVER['HTTP_REFERER'], $whitelist)) {
        $_SESSION['redirect_after_login'] = $_SERVER['HTTP_REFERER'];
        error_log("HTTP_REFERER allowed as redirect");
    }
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $db->real_escape_string($_POST['username']);
    $password = $_POST['password'];

    $sql = "SELECT id, username, password FROM users WHERE username = '$username'";
    $result = $db->query($sql);

    if ($result->num_rows == 1) {
        $user = $result->fetch_assoc();
        if (password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];

            $redirect_url = 'account.php';

            if (!empty($_POST['redirect_url']) && isAllowedRedirect($_POST['redirect_url'], $whitelist)) {
                $redirect_url = $_POST['redirect_url'];
            } elseif (!empty($_SESSION['redirect_after_login']) && isAllowedRedirect($_SESSION['redirect_after_login'], $whitelist)) {
                $redirect_url = $_SESSION['redirect_after_login'];
            }

            unset($_SESSION['redirect_after_login']);

            header('Location: ' . $redirect_url);
            exit();
        } else {
            $error_message = "Password non valida";
        }
    } else {
        $error_message = "Username non trovato";
    }
}
$db->close();
?>

<!DOCTYPE html>
<html lang="it">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/x-icon" href="logo.png">
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <title id="page-title">Rena - Accedi a Rena ID</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        .hidden {
            display: none !important;
        }

        body {
            font-family: 'Inter', sans-serif;
            background: black;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            color: white;
            cursor: url('cursore.png'), pointer;
        }

        .login-container {
            background: rgba(0, 0, 0, 0.7);
            backdrop-filter: blur(15px);
            -webkit-backdrop-filter: blur(15px);
            border-radius: 24px;
            width: 400px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.1);
            text-align: center;
        }

        .logo-container {
            margin-bottom: 30px;
        }

        .logo-container svg {
            width: 80px;
            height: 80px;
        }

        h1 {
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 30px;
            color: white;
        }

        .form-group {
            margin-bottom: 20px;
            text-align: left;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: #d1d5db;
            font-size: 14px;
        }

        .input-container {
            position: relative;
        }

        .form-group input[type="text"],
        .form-group input[type="password"] {
            width: 100%;
            padding: 14px 20px;
            border: 2px solid #2a2a2a;
            border-radius: 12px;
            font-size: 16px;
            background: #1a1a1a;
            color: white;
            transition: all 0.3s ease;
            font-family: inherit;
        }

        .form-group input:focus {
            outline: none;
            border-color: white;
            background: #252525;
            box-shadow: 0 0 0 3px rgba(255, 255, 255, 0.1);
        }

        .password-toggle {
            position: absolute;
            right: 16px;
            top: 50%;
            transform: translateY(-50%);
            cursor: pointer;
            color: #6b7280;
            transition: color 0.3s ease;
        }

        .password-toggle:hover {
            color: white;
        }

        .btn {
            background: linear-gradient(135deg, #4a4a4a 0%, #2c2c2c 100%);
            color: white;
            padding: 14px 32px;
            border: none;
            border-radius: 12px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 500;
            transition: all 0.3s ease;
            width: 100%;
            margin-top: 10px;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(74, 74, 74, 0.3);
        }

        .register-link {
            display: block;
            margin-top: 20px;
            font-size: 14px;
            transition: color 0.3s ease;
            text-decoration: none;
        }

        .register-link .normal-text {
            color: #d1d5db;
            font-weight: normal;
        }

        .register-link .bold-text {
            color: white;
            font-weight: 600;
        }

        .register-link:hover {
            text-decoration: underline;
            color: white;
        }

        .forgot-password-link {
            display: inline-block;
            margin-top: 8px;
            color: #d1d5db;
            text-decoration: none;
            font-size: 14px;
            font-weight: 500;
            transition: color 0.3s ease;
        }

        .forgot-password-link i {
            color: #d1d5db !important;
            margin-right: 5px;
            font-size: 14px;
            display: inline-block;
        }

        .forgot-password-link:hover {
            color: white;
            text-decoration: underline;
        }

        .forgot-password-link:hover i {
            color: white !important;
        }

        #error-popup {
            position: fixed;
            top: -50px;
            left: 50%;
            transform: translateX(-50%);
            background: #ff4444;
            color: white;
            padding: 12px 24px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
            transition: top 0.5s ease-in-out;
            z-index: 1000;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        #error-popup i {
            font-size: 18px;
        }

        #lingua {
            cursor: pointer;
            width: 30px;
            position: absolute;
            top: 12px;
            right: 57px;
            transform: translateX(50%);
            border-radius: 20px;
        }

        .language-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            backdrop-filter: blur(5px);
            z-index: 999;
        }

        .language-popup {
            display: none;
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            width: 300px;
            background: rgba(0, 0, 0, 0.9);
            backdrop-filter: blur(15px);
            -webkit-backdrop-filter: blur(15px);
            border-radius: 16px;
            padding: 25px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.1);
            z-index: 1000;
            animation: fadeIn 0.3s ease-out;
        }

        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translate(-50%, -45%);
            }

            to {
                opacity: 1;
                transform: translate(-50%, -50%);
            }
        }

        .language-popup h3 {
            color: white;
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 20px;
            text-align: center;
        }

        .language-btn {
            display: flex;
            align-items: center;
            width: 100%;
            padding: 12px 20px;
            margin-bottom: 12px;
            background: rgba(255, 255, 255, 0.05);
            color: white;
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            font-size: 15px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .language-btn:hover {
            background: rgba(255, 255, 255, 0.1);
            transform: translateY(-2px);
        }

        .language-btn.active {
            background: rgba(255, 255, 255, 0.15);
            border-color: white;
        }

        .language-btn img {
            width: 24px;
            margin-right: 12px;
            border-radius: 4px;
        }

        .close-popup {
            position: absolute;
            top: 15px;
            right: 15px;
            color: rgba(255, 255, 255, 0.6);
            font-size: 22px;
            cursor: pointer;
            transition: color 0.2s ease;
        }

        .close-popup:hover {
            color: white;
        }

        @media (max-width: 600px) {
            .login-container {
                width: 90%;
                padding: 30px 20px;
            }

            body {
                padding: 20px 0;
                background: black;
            }

            #lingua {
                margin-top: 30px;
                right: 50%;
            }
        }

        input:-webkit-autofill,
        input:-webkit-autofill:hover,
        input:-webkit-autofill:focus,
        input:-webkit-autofill:active {
            -webkit-text-fill-color: white !important;
            -webkit-box-shadow: 0 0 0 50px #1a1a1a inset !important;
            transition: background-color 5000s ease-in-out 0s !important;
        }

        a,
        button,
        text {
            cursor: url('cursore.png'), pointer;
        }

        * {
            scrollbar-width: none;
            -ms-overflow-style: none;
        }

        *::-webkit-scrollbar {
            display: none;
        }

        *:focus {
            outline: none;
        }

        button:focus,
        input:focus,
        textarea:focus {
            outline: none;
        }

        * {
            -webkit-tap-highlight-color: transparent;
        }

        ::selection {
            background-color: white;
            color: black;
        }
    </style>
</head>

<body>
    <div id="error-popup"></div>

    <div class="login-container">
        <div class="logo-container">
            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" stroke="#ffffff">
                <g id="SVGRepo_bgCarrier" stroke-width="0"></g>
                <g id="SVGRepo_tracerCarrier" stroke-linecap="round" stroke-linejoin="round"></g>
                <g id="SVGRepo_iconCarrier">
                    <circle opacity="0.5" cx="12" cy="9" r="3" stroke="#ffffff" stroke-width="1.5"></circle>
                    <circle cx="12" cy="12" r="10" stroke="#ffffff" stroke-width="1.5"></circle>
                    <path opacity="0.5"
                        d="M17.9691 20C17.81 17.1085 16.9247 15 11.9999 15C7.07521 15 6.18991 17.1085 6.03076 20"
                        stroke="#ffffff" stroke-width="1.5" stroke-linecap="round"></path>
                </g>
            </svg>
        </div>

        <h1 data-translate-en="Log In to Rena ID" data-translate-it="Accedi a Rena ID">Accedi a Rena ID</h1>

        <form method="post" action="">
            <input type="hidden" name="redirect_url" value="<?php
            echo isset($_SESSION['redirect_after_login']) ? htmlspecialchars($_SESSION['redirect_after_login']) : 'account.php';
            ?>">
            <div class="form-group">
                <label for="username">Username</label>
                <div class="input-container">
                    <input type="text" id="username" name="username" placeholder="Il tuo username" required
                        data-placeholder-en="Your username" data-placeholder-it="Il tuo username">
                </div>
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <div class="input-container">
                    <input type="password" id="password" name="password" placeholder="La tua password" required
                        data-placeholder-en="Your password" data-placeholder-it="La tua password">
                    <i class="fas fa-eye password-toggle" id="toggle-password"></i>
                </div>
                <a href="password-forgot.php" class="forgot-password-link">
                    <i class="fas fa-key"></i>
                    <span data-translate-en="Forgot your password?" data-translate-it="Password dimenticata?">Password
                        dimenticata?</span>
                </a>
            </div>

            <button type="submit" class="btn">
                <i class="fas fa-sign-in-alt"></i> <span data-translate-en="Log In"
                    data-translate-it="Accedi">Accedi</span>
            </button>

            <a href="register.php" class="register-link">
                <span class="normal-text" data-translate-it="Non hai un account?"
                    data-translate-en="Don't you have an account?">Non hai un account? </span>
                <span class="bold-text" data-translate-it="Registrati" data-translate-en="Sign Up">Registrati</span>
            </a>
        </form>
    </div>

    <img id="lingua" src="https://renadeveloper.altervista.org/bandierait.png" alt="Lingua"
        data-alt-src="https://renadeveloper.altervista.org/bandieraen.png">

    <div class="language-overlay" id="language-overlay"></div>
    <div id="language-popup" class="language-popup">
        <span id="close-popup" class="close-popup">&times;</span>
        <h3 data-translate-en="Select language" data-translate-it="Seleziona lingua">Seleziona lingua</h3>

        <button class="language-btn" data-lang="it">
            <img src="https://renadeveloper.altervista.org/bandierait.png" alt="Italiano">
            <span>Italiano</span>
        </button>

        <button class="language-btn" data-lang="en">
            <img src="https://renadeveloper.altervista.org/bandieraen.png" alt="English">
            <span>English</span>
        </button>
    </div>

    <script>
        let currentLang = 'it';

        function translatePage(lang) {
            currentLang = lang;
            localStorage.setItem('preferredLanguage', lang);

            document.querySelectorAll('[data-translate-it]').forEach(function (el) {
                el.textContent = lang === 'it' ? el.getAttribute('data-translate-it') : el.getAttribute('data-translate-en');
            });

            document.querySelectorAll('[data-placeholder-it]').forEach(function (el) {
                el.setAttribute('placeholder', lang === 'it' ? el.getAttribute('data-placeholder-it') : el.getAttribute('data-placeholder-en'));
            });

            document.getElementById('page-title').textContent = lang === 'it' ? 'Rena - Accedi a Rena ID' : 'Rena - Log In to Rena ID';

            const flagImg = document.getElementById('lingua');
            flagImg.src = lang === 'it'
                ? 'https://renadeveloper.altervista.org/bandierait.png'
                : 'https://renadeveloper.altervista.org/bandieraen.png';
            flagImg.setAttribute('data-lang', lang);
        }

        function openLanguagePopup() {
            document.getElementById('language-overlay').style.display = 'block';
            document.getElementById('language-popup').style.display = 'block';
        }

        function closeLanguagePopup() {
            document.getElementById('language-overlay').style.display = 'none';
            document.getElementById('language-popup').style.display = 'none';
        }

        function showError(message) {
            const popup = document.getElementById('error-popup');
            popup.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${message}`;
            popup.style.top = '20px';
            setTimeout(() => {
                popup.style.top = '-50px';
            }, 5000);
        }

        function togglePassword() {
            const passwordInput = document.getElementById('password');
            const toggleIcon = document.getElementById('toggle-password');

            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                toggleIcon.classList.remove('fa-eye');
                toggleIcon.classList.add('fa-eye-slash');
            } else {
                passwordInput.type = 'password';
                toggleIcon.classList.remove('fa-eye-slash');
                toggleIcon.classList.add('fa-eye');
            }
        }

        document.addEventListener('DOMContentLoaded', function () {
            const savedLang = localStorage.getItem('preferredLanguage') || 'it';
            translatePage(savedLang);

            document.getElementById('lingua').addEventListener('click', function (e) {
                e.stopPropagation();
                openLanguagePopup();
            });

            document.getElementById('close-popup').addEventListener('click', closeLanguagePopup);
            document.getElementById('language-overlay').addEventListener('click', closeLanguagePopup);

            document.getElementById('language-popup').addEventListener('click', function (e) {
                e.stopPropagation();
            });

            document.querySelectorAll('.language-btn').forEach(function (btn) {
                if (btn.getAttribute('data-lang') === savedLang) {
                    btn.classList.add('active');
                }

                btn.addEventListener('click', function () {
                    const lang = this.getAttribute('data-lang');
                    translatePage(lang);
                    closeLanguagePopup();

                    document.querySelectorAll('.language-btn').forEach(b => b.classList.remove('active'));
                    this.classList.add('active');
                });
            });

            document.getElementById('toggle-password').addEventListener('click', togglePassword);

            const urlParams = new URLSearchParams(window.location.search);
            const redirectParam = urlParams.get('redirect');

            if (redirectParam) {
                fetch('check_redirect.php?url=' + encodeURIComponent(redirectParam))
                    .then(response => response.json())
                    .then(data => {
                        if (data.allowed) {
                            let redirectInput = document.querySelector('input[name="redirect_url"]');
                            if (!redirectInput) {
                                redirectInput = document.createElement('input');
                                redirectInput.type = 'hidden';
                                redirectInput.name = 'redirect_url';
                                document.querySelector('form').appendChild(redirectInput);
                            }
                            redirectInput.value = redirectParam;
                            console.log('Redirect URL impostato:', redirectParam);
                        }
                    })
                    .catch(error => {
                        console.error('Errore nel controllo del redirect:', error);
                    });
            } else if (document.referrer) {
                fetch('check_redirect.php?url=' + encodeURIComponent(document.referrer))
                    .then(response => response.json())
                    .then(data => {
                        if (data.allowed) {
                            let redirectInput = document.querySelector('input[name="redirect_url"]');
                            if (!redirectInput) {
                                redirectInput = document.createElement('input');
                                redirectInput.type = 'hidden';
                                redirectInput.name = 'redirect_url';
                                document.querySelector('form').appendChild(redirectInput);
                            }
                            redirectInput.value = document.referrer;
                            console.log('HTTP Referer impostato come redirect:', document.referrer);
                        }
                    });
            }

            <?php if (isset($error_message)): ?>
                showError('<?php echo addslashes($error_message); ?>');
            <?php endif; ?>
        });
    </script>
</body>

</html>

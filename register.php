<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

session_start();

$error_message = '';

$db = new mysqli('localhost', 'username', 'password', 'my_rena');

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $db->real_escape_string($_POST['username']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];

    if ($password !== $confirm_password) {
        $error_message = "Le password non coincidono";
    } else {
        if (strlen($password) < 8) {
            $error_message = "La password deve essere di almeno 8 caratteri";
        } elseif (!preg_match('/[0-9]/', $password)) {
            $error_message = "La password deve contenere almeno un numero";
        } elseif (!preg_match('/[\/\-_]/', $password)) {
            $error_message = "La password deve contenere almeno un carattere speciale (/, -, _)";
        } else {
            $password_hash = password_hash($password, PASSWORD_DEFAULT);

            $check_sql = "SELECT username FROM users WHERE username = '$username'";
            $result = $db->query($check_sql);

            if ($result->num_rows > 0) {
                $error_message = "Username già utilizzato";
            } else {
                $sql = "INSERT INTO users (username, password) VALUES ('$username', '$password_hash')";
                if ($db->query($sql) === TRUE) {
                    $user_id = $db->insert_id;
                    $_SESSION['user_id'] = $user_id;
                    $_SESSION['username'] = $username;
                    
                    $is_external_domain = false;
                    $external_domain = '';
                    
                    if (isset($_GET['external_domain']) && !empty($_GET['external_domain'])) {
                        $external_domain = filter_var($_GET['external_domain'], FILTER_SANITIZE_URL);
                        $is_external_domain = true;
                    }
                    
                    if ($is_external_domain && !empty($external_domain)) {
                        $token = bin2hex(random_bytes(32));
                        $_SESSION['cross_domain_token'] = $token;
                        
                        $user_data = [
                            'status' => 'success',
                            'user_id' => $user_id,
                            'username' => $username,
                            'profile_pic' => null,
                            'token' => $token
                        ];
                        
                        echo "<!DOCTYPE html>
                        <html>
                        <head>
                            <title>Registrazione completata</title>
                        </head>
                        <body>
                            <script>
                                window.onload = function() {
                                    if (window.opener) {
                                        window.opener.postMessage(" . json_encode($user_data) . ", '" . $external_domain . "');
                                        setTimeout(function() {
                                            window.close();
                                        }, 500);
                                    } else {
                                        window.location.href = '" . $external_domain . "?token=' + encodeURIComponent('" . $token . "') + 
                                            '&user_id=' + encodeURIComponent('" . $user_id . "') + 
                                            '&username=' + encodeURIComponent('" . $username . "');
                                    }
                                }
                            </script>
                            <p style='text-align:center; font-family: Arial; padding: 20px;'>
                                Account creato con successo! Questa finestra si chiuderà automaticamente...
                            </p>
                        </body>
                        </html>";
                        exit();
                    } else {
                        header("Location: account.php");
                        exit();
                    }
                } else {
                    $error_message = "Errore durante la registrazione: " . $db->error;
                }
            }
        }
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
    <title id="page-title">Rena - Crea Rena ID</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', sans-serif;
            background: black;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            color: white;
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

        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }

        .register-link {
            display: block;
            margin-top: 20px;
            color: #d1d5db;
            text-decoration: none;
            font-size: 14px;
            transition: color 0.3s ease;
        }

        .register-link:hover {
            color: white;
            text-decoration: underline;
        }

        .register-link span {
            font-weight: 600;
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

        .forgot-password-link:hover {
            color: white;
            text-decoration: underline;
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

        @media (max-width: 600px) {
            .login-container {
                width: 90%;
                padding: 30px 20px;
            }

            body {
                padding: 20px 0;
                background: black;
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

        .register-link {
            display: block;
            margin-top: 20px;
            font-size: 14px;
            transition: color 0.3s ease;
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

        .password-match {
            font-size: 12px;
            margin-top: 5px;
            display: none;
        }

        .password-match.valid {
            color: #4ade80;
            display: block;
        }

        .password-match.invalid {
            color: #f87171;
            display: block;
        }

        .password-requirements {
            font-size: 12px;
            margin-top: 8px;
            color: #6b7280;
            text-align: left;
        }

        .password-requirements ul {
            list-style: none;
            padding-left: 0;
            margin-top: 5px;
        }

        .password-requirements li {
            margin-bottom: 3px;
            display: flex;
            align-items: center;
        }

        .password-requirements li i {
            margin-right: 5px;
            font-size: 10px;
            width: 12px;
        }

        .requirement-met {
            color: #4ade80;
        }

        .requirement-not-met {
            color: #f87171;
        }

        .requirement-partial {
            color: #fbbf24;
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

        <h1 data-translate-en="Create Rena ID" data-translate-it="Crea Rena ID">Crea Rena ID</h1>

        <form method="post" action="" id="register-form">
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
                <div class="password-requirements">
                    <span data-translate-en="Password requirements:" data-translate-it="Requisiti password:">Requisiti password:</span>
                    <ul>
                        <li id="req-length">
                            <i class="fas fa-circle requirement-not-met"></i>
                            <span data-translate-en="At least 8 characters" data-translate-it="Almeno 8 caratteri">Almeno 8 caratteri</span>
                        </li>
                        <li id="req-number">
                            <i class="fas fa-circle requirement-not-met"></i>
                            <span data-translate-en="At least one number" data-translate-it="Almeno un numero">Almeno un numero</span>
                        </li>
                        <li id="req-special">
                            <i class="fas fa-circle requirement-not-met"></i>
                            <span data-translate-en="At least one special character (/, -, _)" data-translate-it="Almeno un carattere speciale (/, -, _)">Almeno un carattere speciale (/, -, _)</span>
                        </li>
                    </ul>
                </div>
            </div>

            <div class="form-group">
                <label for="confirm_password">Conferma Password</label>
                <div class="input-container">
                    <input type="password" id="confirm_password" name="confirm_password" placeholder="Conferma la tua password" required
                        data-placeholder-en="Confirm your password" data-placeholder-it="Conferma la tua password">
                    <i class="fas fa-eye password-toggle" id="toggle-confirm-password"></i>
                </div>
                <div id="password-match-message" class="password-match"></div>
            </div>

            <button type="submit" class="btn" id="submit-btn" disabled>
                <i class="fas fa-user-plus"></i> <span data-translate-en="Sign Up"
                    data-translate-it="Registrati">Registrati</span>
            </button>

            <a href="login.php" class="register-link">
                <span class="normal-text" data-translate-it="Hai già un account?"
                    data-translate-en="Already have an account?"></span>
                <span class="bold-text" data-translate-it="Accedi" data-translate-en="Sign in"></span>
            </a>

        </form>
    </div>

    <script>
        function showError(message) {
            const popup = document.getElementById('error-popup');
            popup.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${message}`;
            popup.style.top = '20px';
            setTimeout(() => {
                popup.style.top = '-50px';
            }, 10000);
        }

        <?php
        if ($error_message) {
            echo "showError('" . addslashes($error_message) . "');";
        }
        ?>
    </script>
    <style>
        a,
        button,
        text {
            cursor: url('cursore.png'), pointer;
        }

        body {
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
    <img id="lingua" src="https://renadeveloper.altervista.org/bandierait.png" alt="Lingua"
        data-alt-src="https://renadeveloper.altervista.org/bandieraen.png">
    <script>
        document.getElementById('lingua').addEventListener('click', function () {
            var img = this;
            var currentLang = img.getAttribute('data-lang') || 'it';
            var newLang = currentLang === 'it' ? 'en' : 'it';

            translatePage(newLang);
        });
    </script>
    <style>
        #lingua {
            cursor: pointer;
            width: 30px;
            position: absolute;
            top: 12px;
            right: 57px;
            transform: translateX(50%);
            border-radius: 20px;
        }

        @media screen and (max-width: 600px) {
            #lingua {
                margin-top: 30px;
                right: 50%;
            }
        }
    </style>
<style>
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
        from { opacity: 0; transform: translate(-50%, -45%); }
        to { opacity: 1; transform: translate(-50%, -50%); }
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
</style>

<div class="language-overlay" id="language-overlay"></div>
<div id="language-popup" class="language-popup">
    <span id="close-popup" class="close-popup">&times;</span>
    <h3 data-translate-en="Seleziona lingua" data-translate-it="Select language">Seleziona lingua</h3>
    
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
    function translatePage(lang) {
        localStorage.setItem('preferredLanguage', lang);

        document.querySelectorAll('[data-translate-it]').forEach(function(el) {
            el.textContent = lang === 'it' ? el.getAttribute('data-translate-it') : el.getAttribute('data-translate-en');
        });

        document.querySelectorAll('[data-placeholder-it]').forEach(function(el) {
            el.setAttribute('placeholder', lang === 'it' ? el.getAttribute('data-placeholder-it') : el.getAttribute('data-placeholder-en'));
        });

        document.getElementById('page-title').textContent = lang === 'it' ? 'Rena - Crea Rena ID' : 'Rena - Create Rena ID';
        const flagImg = document.getElementById('lingua');
        flagImg.src = lang === 'it' 
            ? 'https://renadeveloper.altervista.org/bandierait.png'
            : 'https://renadeveloper.altervista.org/bandieraen.png';
        flagImg.setAttribute('data-lang', lang);
    }

    document.getElementById('lingua').addEventListener('click', function(e) {
        e.stopPropagation();
        document.getElementById('language-overlay').style.display = 'block';
        document.getElementById('language-popup').style.display = 'block';
    });

    function closeLanguagePopup() {
        document.getElementById('language-overlay').style.display = 'none';
        document.getElementById('language-popup').style.display = 'none';
    }

    document.getElementById('close-popup').addEventListener('click', closeLanguagePopup);
    document.getElementById('language-overlay').addEventListener('click', closeLanguagePopup);

    document.getElementById('language-popup').addEventListener('click', function(e) {
        e.stopPropagation();
    });

    function showError(message) {
        const popup = document.getElementById('error-popup');
        popup.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${message}`;
        popup.style.top = '20px';
        setTimeout(() => {
            popup.style.top = '-50px';
        }, 5000);
    }

    function setupPasswordToggle(passwordId, toggleId) {
        const passwordInput = document.getElementById(passwordId);
        const toggleIcon = document.getElementById(toggleId);
        
        if (passwordInput && toggleIcon) {
            toggleIcon.addEventListener('click', function() {
                if (passwordInput.type === 'password') {
                    passwordInput.type = 'text';
                    toggleIcon.classList.remove('fa-eye');
                    toggleIcon.classList.add('fa-eye-slash');
                } else {
                    passwordInput.type = 'password';
                    toggleIcon.classList.remove('fa-eye-slash');
                    toggleIcon.classList.add('fa-eye');
                }
            });
        }
    }

    function checkPasswordMatch() {
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirm_password').value;
        const message = document.getElementById('password-match-message');
        const submitBtn = document.getElementById('submit-btn');

        if (password === '' && confirmPassword === '') {
            message.className = 'password-match';
            message.textContent = '';
            return;
        }

        if (confirmPassword === '') {
            message.className = 'password-match';
            message.textContent = '';
            return;
        }

        if (password === confirmPassword) {
            message.className = 'password-match valid';
            message.textContent = 'Le password coincidono';
            message.setAttribute('data-translate-it', 'Le password coincidono');
            message.setAttribute('data-translate-en', 'Passwords match');
        } else {
            message.className = 'password-match invalid';
            message.textContent = 'Le password non coincidono';
            message.setAttribute('data-translate-it', 'Le password non coincidono');
            message.setAttribute('data-translate-en', 'Passwords do not match');
        }

        const currentLang = localStorage.getItem('preferredLanguage') || 'it';
        if (message.textContent) {
            message.textContent = currentLang === 'it' 
                ? message.getAttribute('data-translate-it')
                : message.getAttribute('data-translate-en');
        }
    }

    function checkPasswordRequirements() {
        const password = document.getElementById('password').value;
        const submitBtn = document.getElementById('submit-btn');
        
        const lengthValid = password.length >= 8;
        updateRequirement('length', lengthValid);
        
        const hasNumber = /[0-9]/.test(password);
        updateRequirement('number', hasNumber);
        
        const hasSpecial = /[\/\-_]/.test(password);
        updateRequirement('special', hasSpecial);
        
        const allValid = lengthValid && hasNumber && hasSpecial;
        submitBtn.disabled = !allValid;
        
        return allValid;
    }
    
    function updateRequirement(type, isValid) {
        const element = document.getElementById(`req-${type}`);
        const icon = element.querySelector('i');
        
        if (isValid) {
            icon.className = 'fas fa-check-circle requirement-met';
        } else {
            icon.className = 'fas fa-times-circle requirement-not-met';
        }
    }

    document.addEventListener('DOMContentLoaded', function() {
        const savedLang = localStorage.getItem('preferredLanguage') || 'it';
        translatePage(savedLang);

        setupPasswordToggle('password', 'toggle-password');
        setupPasswordToggle('confirm_password', 'toggle-confirm-password');

        document.getElementById('password').addEventListener('input', function() {
            checkPasswordRequirements();
            checkPasswordMatch();
        });

        document.getElementById('confirm_password').addEventListener('input', checkPasswordMatch);

        document.querySelectorAll('.language-btn').forEach(btn => {
            if (btn.getAttribute('data-lang') === savedLang) {
                btn.classList.add('active');
            }
            
            btn.addEventListener('click', function() {
                const lang = this.getAttribute('data-lang');
                translatePage(lang);
                closeLanguagePopup();
                
                document.querySelectorAll('.language-btn').forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                
                checkPasswordMatch();
                checkPasswordRequirements();
            });
        });

        <?php if ($error_message): ?>
            showError('<?php echo addslashes($error_message); ?>');
        <?php endif; ?>
    });
</script>
<style>
    #custom-menu {
      display: none;
      position: absolute;
      background: rgba(0, 0, 0, 0.9);
      border-radius: 15px;
      padding: 15px;
      backdrop-filter: blur(20px);
      z-index: 99999999;
      border: 1px solid rgba(255, 255, 255, 0.1);
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
    }

    #custom-menu ul {
      list-style: none;
      padding: 0;
      margin: 0;
    }

    #custom-menu ul li {
      margin-bottom: 10px;
    }

    #custom-menu ul li a {
      display: flex;
      align-items: center;
      color: #fff;
      text-decoration: none;
      padding: 8px 12px;
      border-radius: 8px;
      transition: all 0.3s ease;
    }

    #custom-menu ul li a:hover {
      background: rgba(255, 255, 255, 0.1);
      transform: translateX(5px);
    }

    #custom-menu ul li a img {
      margin-right: 10px;
      border-radius: 5px;
    }

    #custom-menu ul li a span {
      font-size: 16px;
    }

    #custom-menu ul li a.has-svg span {
      margin-left: 10px;
    }

    .custom-menu-svg {
      width: 22px;
      height: 22px;
      max-width: 100%;
      max-height: 100%;
    }
</style>
  <div id="custom-menu">
    <ul>
      <li><a href="https://rena.altervista.org">
          <img src="https://gcsapp.altervista.org/homebanner.png" alt="Home" width="20">
          <span>Home</span>
        </a></li>
      <li><a href="https://rena.altervista.org/privacy-policy.html" class="has-svg">
          <svg class="custom-menu-svg" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path
              d="M12 14.5V16.5M7 10.0288C7.47142 10 8.05259 10 8.8 10H15.2C15.9474 10 16.5286 10 17 10.0288M7 10.0288C6.41168 10.0647 5.99429 10.1455 5.63803 10.327C5.07354 10.6146 4.6146 11.0735 4.32698 11.638C4 12.2798 4 13.1198 4 14.8V16.2C4 17.8802 4 18.7202 4.32698 19.362C4.6146 19.9265 5.07354 20.3854 5.63803 20.673C6.27976 21 7.11984 21 8.8 21H15.2C16.8802 21 17.7202 21 18.362 20.673C18.9265 20.3854 19.3854 19.9265 19.673 19.362C20 18.7202 20 17.8802 20 16.2V14.8C20 13.1198 20 12.2798 19.673 11.638C19.3854 11.0735 18.9265 10.6146 18.362 10.327C18.0057 10.1455 17.5883 10.0647 17 10.0288M7 10.0288V8C7 5.23858 9.23858 3 12 3C14.7614 3 17 5.23858 17 8V10.0288"
              stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
          <span>Privacy Policy</span>
        </a></li>
      <li><a href="https://rena.altervista.org/chi-siamo.html" class="has-svg">
          <svg class="custom-menu-svg" version="1.1" xmlns="http://www.w3.org/2000/svg"
            xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 512 512" fill="#ffffff" stroke="#ffffff">
            <g>
              <path
                d="M256,265.308c73.252,0,132.644-59.391,132.644-132.654C388.644,59.412,329.252,0,256,0 c-73.262,0-132.643,59.412-132.643,132.654C123.357,205.917,182.738,265.308,256,265.308z">
              </path>
              <path
                d="M425.874,393.104c-5.922-35.474-36-84.509-57.552-107.465c-5.829-6.212-15.948-3.628-19.504-1.427 c-27.04,16.672-58.782,26.399-92.819,26.399c-34.036,0-65.778-9.727-92.818-26.399c-3.555-2.201-13.675-4.785-19.505,1.427 c-21.55,22.956-51.628,71.991-57.551,107.465C71.573,480.444,164.877,512,256,512C347.123,512,440.427,480.444,425.874,393.104z">
              </path>
            </g>
          </svg>
          <span data-translate-it="Chi Siamo" data-translate-en="About Us">Chi Siamo</span>
        </a></li>
      <li><a href="https://rena.altervista.org/news.php" class="has-svg">
          <svg class="custom-menu-svg" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"
            stroke="#ffffff">
            <g id="SVGRepo_bgCarrier" stroke-width="0"></g>
            <g id="SVGRepo_tracerCarrier" stroke-linecap="round" stroke-linejoin="round"></g>
            <g id="SVGRepo_iconCarrier">
              <path
                d="M5 21H17C19.2091 21 21 19.2091 21 17V5C21 3.89543 20.1046 3 19 3H9C7.89543 3 7 3.89543 7 5V18C7 19.6569 6.65685 21 5 21C3.61929 21 3 19.8807 3 18.5V10Z"
                stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path>
              <circle cx="12" cy="8" r="1" stroke="#ffffff" stroke-width="2" stroke-linecap="round"></circle>
              <path d="M11 14H17" stroke="#ffffff" stroke-width="2" stroke-linecap="round"></path>
              <path d="M11 17H14" stroke="#ffffff" stroke-width="2" stroke-linecap="round"></path>
            </g>
          </svg>
          <span>News</span>
        </a></li>
    </ul>
  </div>
<script>
document.addEventListener('contextmenu', function (event) {
  event.preventDefault();
  if (window.innerWidth > 768) {
    const customMenu = document.getElementById('custom-menu');
    if (customMenu) {
      customMenu.style.display = 'block';
      customMenu.style.left = event.pageX + 'px';
      customMenu.style.top = event.pageY + 'px';
    }
  }
});

document.addEventListener('click', function (event) {
  const customMenu = document.getElementById('custom-menu');
  if (customMenu && !customMenu.contains(event.target)) {
    customMenu.style.display = 'none';
  }
});
</script>
</body>

</html>

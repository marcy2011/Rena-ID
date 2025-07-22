<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

session_start();

$error_message = '';

$db = new mysqli('localhost', 'username', 'password', 'my_rena');

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $db->real_escape_string($_POST['username']);
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT);

    $check_sql = "SELECT username FROM users WHERE username = '$username'";
    $result = $db->query($check_sql);

    if ($result->num_rows > 0) {
        $error_message = "Username già utilizzato";
    } else {
        $sql = "INSERT INTO users (username, password) VALUES ('$username', '$password')";
        if ($db->query($sql) === TRUE) {
            $user_id = $db->insert_id;
            $_SESSION['user_id'] = $user_id;
            $_SESSION['username'] = $username;
            header("Location: account.php");
            exit();
        } else {
            $error_message = "Errore durante la registrazione: " . $db->error;
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

        <form method="post" action="">
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
                    <input type="password" id="password" name="password" placeholder="La tua password" required required
                        data-placeholder-en="Your password" data-placeholder-it="La tua password">
                    <i class="fas fa-eye password-toggle" id="toggle-password"></i>
                </div>
            </div>

            <button type="submit" class="btn" required>
                <i class="fas fa-sign-in-alt"></i> <span data-translate-en="Sign Up"
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
            popup.textContent = message;
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

    document.getElementById('toggle-password').addEventListener('click', function() {
        const passwordInput = document.getElementById('password');
        const toggleIcon = this;
        
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

    document.addEventListener('DOMContentLoaded', function() {
        const savedLang = localStorage.getItem('preferredLanguage') || 'it';
        translatePage(savedLang);

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
            });
        });

        <?php if ($error_message): ?>
            showError('<?php echo addslashes($error_message); ?>');
        <?php endif; ?>
    });
</script>
</body>

</html>

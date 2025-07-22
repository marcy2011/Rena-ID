<?php
session_start();

$conn = new mysqli("localhost", "username", "password", "my_rena");
if ($conn->connect_error) {
    die("Connessione fallita: " . $conn->connect_error);
}

$code_dir = __DIR__ . '/codes';
if (!is_dir($code_dir)) {
    mkdir($code_dir, 0777, true);
}

function get_code_filename($email)
{
    global $code_dir;
    return $code_dir . '/' . md5($email) . '.txt';
}

$step = $_POST['step'] ?? 'email';

$error = '';
$success = '';

if ($step === 'email' && isset($_POST['email'])) {
    $email = trim($_POST['email']);

    $stmt = $conn->prepare("SELECT id FROM users WHERE email=?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows === 0) {
        $error = "Questa email non è associata a nessun account";
        $step = 'email';
    } else {
        $code = rand(100000, 999999);
        file_put_contents(get_code_filename($email), $code . "|" . time());

        $lang = $_POST['lang'] ?? 'it';

        if ($lang === 'en') {
            $subject = "Rena ID Password Reset Code";
            $message = "<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Password Reset Code</title>
</head>
<body style='margin: 0; padding: 0; font-family: Inter, -apple-system, BlinkMacSystemFont, sans-serif; background-color: #000000; color: #ffffff;'>
    <div style='max-width: 600px; margin: 0 auto; padding: 40px 20px;'>
        <div style='background: rgba(0, 0, 0, 0.8); border-radius: 24px; padding: 40px; border: 1px solid rgba(255, 255, 255, 0.1); text-align: center;'>
            
            <div style='margin-bottom: 30px;'>
                <svg width='60' height='60' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg' style='margin: 0 auto; display: block;'>
                    <path d='M12 14.5V16.5M7 10.0288C7.47142 10 8.05259 10 8.8 10H15.2C15.9474 10 16.5286 10 17 10.0288M7 10.0288C6.41168 10.0647 5.99429 10.1455 5.63803 10.327C5.07354 10.6146 4.6146 11.0735 4.32698 11.638C4 12.2798 4 13.1198 4 14.8V16.2C4 17.8802 4 18.7202 4.32698 19.362C4.6146 19.9265 5.07354 20.3854 5.63803 20.673C6.27976 21 7.11984 21 8.8 21H15.2C16.8802 21 17.7202 21 18.362 20.673C18.9265 20.3854 19.3854 19.9265 19.673 19.362C20 18.7202 20 17.8802 20 16.2V14.8C20 13.1198 20 12.2798 19.673 11.638C19.3854 11.0735 18.9265 10.6146 18.362 10.327C18.0057 10.1455 17.5883 10.0647 17 10.0288M7 10.0288V8C7 5.23858 9.23858 3 12 3C14.7614 3 17 5.23858 17 8V10.0288' stroke='#ffffff' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/>
                </svg>
            </div>
            
            <h1 style='font-size: 24px; font-weight: 600; margin-bottom: 20px; color: #ffffff;'>
                Password Reset
            </h1>
            
            <p style='font-size: 16px; color: #d1d5db; margin-bottom: 30px; line-height: 1.5;'>
                Hi! You requested to reset the password for your Rena ID account.
            </p>
            
            <div style='background: linear-gradient(135deg, #4a4a4a 0%, #2c2c2c 100%); border-radius: 16px; padding: 30px; margin: 30px 0; border: 1px solid rgba(255, 255, 255, 0.1);'>
                <p style='font-size: 14px; color: #d1d5db; margin-bottom: 10px; font-weight: 500;'>
                    Your verification code is:
                </p>
<div style='font-size: 30px; font-weight: 700; color: #ffffff; letter-spacing: 8px; margin: 20px 0; font-family: monospace; white-space: nowrap; overflow-x: auto; text-align: center; right: 50%;'>
    $code
</div>
                <p style='font-size: 12px; color: #d1d5db; margin-top: 15px;'>
                    Valid for 10 minutes
                </p>
            </div>
            
            <div style='background: rgba(16, 185, 129, 0.1); border-radius: 12px; padding: 20px; margin: 20px 0; border: 1px solid rgba(16, 185, 129, 0.2);'>
                <p style='font-size: 14px; color: #10b981; margin: 0; font-weight: 500;'>
                    Enter this code on the password reset page to continue.
                </p>
            </div>
            
            <div style='background: rgba(255, 68, 68, 0.1); border-radius: 12px; padding: 20px; margin: 20px 0; border: 1px solid rgba(255, 68, 68, 0.2);'>
                <p style='font-size: 14px; color: #ff4444; margin: 0; font-weight: 500;'>
                    If you didn't request this password reset, please ignore this email. Your account remains secure.
                </p>
            </div>
            
            <div style='margin-top: 40px; padding-top: 20px; border-top: 1px solid rgba(255, 255, 255, 0.1);'>
                <p style='font-size: 14px; color: #d1d5db; margin-bottom: 10px;'>
                    Thank you for using Rena ID
                </p>
                <p style='font-size: 12px; color: #6b7280; margin: 0;'>
                    The Rena Team
                </p>
            </div>
            
        </div>
    </div>
</body>
</html>";
        } else {
            $subject = "Codice reimpostazione password Rena ID";
            $message = "<!DOCTYPE html>
<html lang='it'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Codice reimpostazione password</title>
</head>
<body style='margin: 0; padding: 0; font-family: Inter, -apple-system, BlinkMacSystemFont, sans-serif; background-color: #000000; color: #ffffff;'>
    <div style='max-width: 600px; margin: 0 auto; padding: 40px 20px;'>
        <div style='background: rgba(0, 0, 0, 0.8); border-radius: 24px; padding: 40px; border: 1px solid rgba(255, 255, 255, 0.1); text-align: center;'>
            
            <div style='margin-bottom: 30px;'>
                <svg width='60' height='60' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg' style='margin: 0 auto; display: block;'>
                    <path d='M12 14.5V16.5M7 10.0288C7.47142 10 8.05259 10 8.8 10H15.2C15.9474 10 16.5286 10 17 10.0288M7 10.0288C6.41168 10.0647 5.99429 10.1455 5.63803 10.327C5.07354 10.6146 4.6146 11.0735 4.32698 11.638C4 12.2798 4 13.1198 4 14.8V16.2C4 17.8802 4 18.7202 4.32698 19.362C4.6146 19.9265 5.07354 20.3854 5.63803 20.673C6.27976 21 7.11984 21 8.8 21H15.2C16.8802 21 17.7202 21 18.362 20.673C18.9265 20.3854 19.3854 19.9265 19.673 19.362C20 18.7202 20 17.8802 20 16.2V14.8C20 13.1198 20 12.2798 19.673 11.638C19.3854 11.0735 18.9265 10.6146 18.362 10.327C18.0057 10.1455 17.5883 10.0647 17 10.0288M7 10.0288V8C7 5.23858 9.23858 3 12 3C14.7614 3 17 5.23858 17 8V10.0288' stroke='#ffffff' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/>
                </svg>
            </div>
            
            <h1 style='font-size: 24px; font-weight: 600; margin-bottom: 20px; color: #ffffff;'>
                Reimpostazione Password
            </h1>
            
            <p style='font-size: 16px; color: #d1d5db; margin-bottom: 30px; line-height: 1.5;'>
                Ciao! Hai richiesto di reimpostare la password per il tuo account Rena ID.
            </p>
            
            <div style='background: linear-gradient(135deg, #4a4a4a 0%, #2c2c2c 100%); border-radius: 16px; padding: 30px; margin: 30px 0; border: 1px solid rgba(255, 255, 255, 0.1);'>
                <p style='font-size: 14px; color: #d1d5db; margin-bottom: 10px; font-weight: 500;'>
                    Il tuo codice di verifica è:
                </p>
                <div style='font-size: 30px; font-weight: 700; color: #ffffff; letter-spacing: 8px; margin: 20px 0; font-family: monospace; white-space: nowrap; overflow-x: auto; text-align: center;'>
                    $code
                </div>
                <p style='font-size: 12px; color: #d1d5db; margin-top: 15px;'>
                    Valido per 10 minuti
                </p>
            </div>
            
            <div style='background: rgba(16, 185, 129, 0.1); border-radius: 12px; padding: 20px; margin: 20px 0; border: 1px solid rgba(16, 185, 129, 0.2);'>
                <p style='font-size: 14px; color: #10b981; margin: 0; font-weight: 500;'>
                    Inserisci questo codice nella pagina di reimpostazione password per continuare.
                </p>
            </div>
            
            <div style='background: rgba(255, 68, 68, 0.1); border-radius: 12px; padding: 20px; margin: 20px 0; border: 1px solid rgba(255, 68, 68, 0.2);'>
                <p style='font-size: 14px; color: #ff4444; margin: 0; font-weight: 500;'>
                    Se non hai richiesto questa reimpostazione password, ignora questa email. Il tuo account rimane sicuro.
                </p>
            </div>
            
            <div style='margin-top: 40px; padding-top: 20px; border-top: 1px solid rgba(255, 255, 255, 0.1);'>
                <p style='font-size: 14px; color: #d1d5db; margin-bottom: 10px;'>
                    Grazie per aver usato Rena ID
                </p>
                <p style='font-size: 12px; color: #6b7280; margin: 0;'>
                    Il Team Rena
                </p>
            </div>
            
        </div>
    </div>
</body>
</html>";
        }
        $headers = "From: Rena ID <rena@altervista.org>\r\n";
        $headers .= "MIME-Version: 1.0\r\n";
        $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
        mail($email, $subject, $message, $headers);

        $_SESSION['email'] = $email;
        $step = 'code';
    }

    $stmt->close();
} elseif ($step === 'code' && isset($_POST['code'])) {
    $email = $_SESSION['email'] ?? '';
    $input_code = trim($_POST['code']);
    $filename = get_code_filename($email);

    if (file_exists($filename)) {
        list($saved_code, $timestamp) = explode("|", file_get_contents($filename));
        $saved_code = trim($saved_code);

        if (time() - $timestamp > 600) {
            $error = "Codice scaduto. Riprova.";
            $step = 'email';
        } elseif ($input_code === $saved_code) {
            $step = 'reset';
        } else {
            $error = "Codice errato. Riprova.";
        }
    } else {
        $error = "Nessun codice trovato. Invia prima l'email.";
        $step = 'email';
    }
} elseif ($step === 'reset' && isset($_POST['new_password'])) {
    $email = $_SESSION['email'] ?? '';
    $new_password = password_hash($_POST['new_password'], PASSWORD_DEFAULT);

    $stmt = $conn->prepare("UPDATE users SET password = ? WHERE email = ?");
    $stmt->bind_param("ss", $new_password, $email);

    if ($stmt->execute()) {
        $success = "Password cambiata con successo!";
        unlink(get_code_filename($email));
        session_destroy();
        $step = 'done';
    } else {
        $error = "Errore nel cambiare la password: " . $stmt->error;
        $step = 'reset';
    }

    $stmt->close();
}

?>

<!DOCTYPE html>
<html lang="it">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/x-icon" href="logo.png">
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <title id="page-title">Rena - Reimposta Password</title>
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
            cursor: url('cursore.png'), pointer;
        }

        .reset-container {
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
            margin-bottom: 10px;
            color: white;
        }

        .subtitle {
            font-size: 14px;
            color: #d1d5db;
            margin-bottom: 30px;
            line-height: 1.5;
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

        .form-group input[type="email"],
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

        .back-link {
            display: block;
            margin-top: 20px;
            color: #d1d5db;
            text-decoration: none;
            font-size: 14px;
            transition: color 0.3s ease;
        }

        .back-link:hover {
            color: white;
            text-decoration: underline;
        }

        .back-link i {
            margin-right: 8px;
        }

        .success-message {
            color: #10b981;
            font-weight: 500;
            margin-bottom: 20px;
            padding: 12px 16px;
            background: rgba(16, 185, 129, 0.1);
            border-radius: 8px;
            border: 1px solid rgba(16, 185, 129, 0.2);
        }

        .success-container {
            text-align: center;
        }

        .success-icon {
            font-size: 48px;
            color: #10b981;
            margin-bottom: 20px;
        }

        .success-title {
            font-size: 20px;
            font-weight: 600;
            color: white;
            margin-bottom: 10px;
        }

        .success-subtitle {
            font-size: 14px;
            color: #d1d5db;
            margin-bottom: 30px;
        }

        .login-btn {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: white;
            padding: 14px 32px;
            border: none;
            border-radius: 12px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 500;
            transition: all 0.3s ease;
            width: 100%;
            text-decoration: none;
            display: inline-block;
            text-align: center;
        }

        .login-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(16, 185, 129, 0.3);
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
            .reset-container {
                width: 90%;
                padding: 30px 20px;
            }

            body {
                padding: 20px 0;
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

        .step-indicator {
            display: flex;
            justify-content: center;
            align-items: center;
            margin-bottom: 30px;
            gap: 10px;
        }

        .step-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #2a2a2a;
            transition: all 0.3s ease;
        }

        .step-dot.active {
            background: white;
            transform: scale(1.2);
        }

        .step-dot.completed {
            background: #10b981;
        }
    </style>
</head>

<body>
    <div id="error-popup"></div>

    <div class="reset-container">
        <?php if ($step === 'email'): ?>
            <div class="logo-container">
                <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" stroke="#ffffff">
                    <g id="SVGRepo_bgCarrier" stroke-width="0"></g>
                    <g id="SVGRepo_tracerCarrier" stroke-linecap="round" stroke-linejoin="round"></g>
                    <g id="SVGRepo_iconCarrier">
                        <path
                            d="M12 14.5V16.5M7 10.0288C7.47142 10 8.05259 10 8.8 10H15.2C15.9474 10 16.5286 10 17 10.0288M7 10.0288C6.41168 10.0647 5.99429 10.1455 5.63803 10.327C5.07354 10.6146 4.6146 11.0735 4.32698 11.638C4 12.2798 4 13.1198 4 14.8V16.2C4 17.8802 4 18.7202 4.32698 19.362C4.6146 19.9265 5.07354 20.3854 5.63803 20.673C6.27976 21 7.11984 21 8.8 21H15.2C16.8802 21 17.7202 21 18.362 20.673C18.9265 20.3854 19.3854 19.9265 19.673 19.362C20 18.7202 20 17.8802 20 16.2V14.8C20 13.1198 20 12.2798 19.673 11.638C19.3854 11.0735 18.9265 10.6146 18.362 10.327C18.0057 10.1455 17.5883 10.0647 17 10.0288M7 10.0288V8C7 5.23858 9.23858 3 12 3C14.7614 3 17 5.23858 17 8V10.0288"
                            stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path>
                    </g>
                </svg>
            </div>
        <?php elseif ($step === 'code' || $step === 'reset'): ?>
            <div class="logo-container">
                <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" stroke="#ffffff">
                    <g id="SVGRepo_bgCarrier" stroke-width="0"></g>
                    <g id="SVGRepo_tracerCarrier" stroke-linecap="round" stroke-linejoin="round"></g>
                    <g id="SVGRepo_iconCarrier">
                        <path
                            d="M12 14.5V16.5M7 10.0288C7.47142 10 8.05259 10 8.8 10H15.2C15.9474 10 16.5286 10 17 10.0288M7 10.0288C6.41168 10.0647 5.99429 10.1455 5.63803 10.327C5.07354 10.6146 4.6146 11.0735 4.32698 11.638C4 12.2798 4 13.1198 4 14.8V16.2C4 17.8802 4 18.7202 4.32698 19.362C4.6146 19.9265 5.07354 20.3854 5.63803 20.673C6.27976 21 7.11984 21 8.8 21H15.2C16.8802 21 17.7202 21 18.362 20.673C18.9265 20.3854 19.3854 19.9265 19.673 19.362C20 18.7202 20 17.8802 20 16.2V14.8C20 13.1198 20 12.2798 19.673 11.638C19.3854 11.0735 18.9265 10.6146 18.362 10.327C18.0057 10.1455 17.5883 10.0647 17 10.0288M7 10.0288V8C7 5.23858 9.23858 3 12 3C14.7614 3 17 5.23858 17 8V10.0288"
                            stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path>
                    </g>
                </svg>
            </div>
        <?php endif; ?>

        <?php if ($step === 'email'): ?>
            <h1 data-translate-en="Reset Password" data-translate-it="Reimposta Password">Reimposta Password</h1>
            <p class="subtitle" data-translate-en="Enter your email address and we'll send you a verification code"
                data-translate-it="Inserisci la tua email e ti invieremo un codice di verifica">
                Inserisci la tua email e ti invieremo un codice di verifica
            </p>

            <div class="step-indicator">
                <div class="step-dot active"></div>
                <div class="step-dot"></div>
                <div class="step-dot"></div>
            </div>

            <form method="POST">
                <input type="hidden" name="step" value="email" />
                <input type="hidden" name="lang" id="form-lang" value="it" />
                <div class="form-group">
                    <label for="email" data-translate-en="Email Address" data-translate-it="Indirizzo Email">Indirizzo
                        Email</label>
                    <div class="input-container">
                        <input type="email" id="email" name="email" placeholder="Inserisci la tua email" required
                            data-placeholder-en="Enter your email" data-placeholder-it="Inserisci la tua email">
                    </div>
                </div>
                <button type="submit" class="btn">
                    <i class="fas fa-paper-plane"></i> <span data-translate-en="Send Code"
                        data-translate-it="Invia Codice">Invia Codice</span>
                </button>
            </form>

        <?php elseif ($step === 'code'): ?>
            <h1 data-translate-en="Verify Code" data-translate-it="Verifica Codice">Verifica Codice</h1>
            <p class="subtitle" data-translate-en="Enter the 6-digit code we sent to your email"
                data-translate-it="Inserisci il codice a 6 cifre che ti abbiamo inviato">
                Inserisci il codice a 6 cifre che ti abbiamo inviato
            </p>

            <div class="step-indicator">
                <div class="step-dot completed"></div>
                <div class="step-dot active"></div>
                <div class="step-dot"></div>
            </div>

            <form method="POST">
                <input type="hidden" name="step" value="code" />
                <input type="hidden" name="lang" id="form-lang" value="it" />
                <div class="form-group">
                    <label for="code" data-translate-en="Verification Code" data-translate-it="Codice di Verifica">Codice di
                        Verifica</label>
                    <div class="input-container">
                        <input type="text" id="code" name="code" placeholder="123456" required maxlength="6"
                            data-placeholder-en="123456" data-placeholder-it="123456">
                    </div>
                </div>
                <button type="submit" class="btn">
                    <i class="fas fa-check"></i> <span data-translate-en="Verify Code"
                        data-translate-it="Verifica Codice">Verifica Codice</span>
                </button>
            </form>

        <?php elseif ($step === 'reset'): ?>
            <h1 data-translate-en="New Password" data-translate-it="Nuova Password">Nuova Password</h1>
            <p class="subtitle" data-translate-en="Enter your new password"
                data-translate-it="Inserisci la tua nuova password">
                Inserisci la tua nuova password
            </p>

            <div class="step-indicator">
                <div class="step-dot completed"></div>
                <div class="step-dot completed"></div>
                <div class="step-dot active"></div>
            </div>

            <form method="POST">
                <input type="hidden" name="step" value="reset" />
                <input type="hidden" name="lang" id="form-lang" value="it" />
                <div class="form-group">
                    <label for="new_password" data-translate-en="New Password" data-translate-it="Nuova Password">Nuova
                        Password</label>
                    <div class="input-container">
                        <input type="password" id="new_password" name="new_password"
                            placeholder="Inserisci la nuova password" required data-placeholder-en="Enter new password"
                            data-placeholder-it="Inserisci la nuova password">
                        <i class="fas fa-eye password-toggle" id="toggle-password"></i>
                    </div>
                </div>
                <button type="submit" class="btn">
                    <i class="fas fa-save"></i> <span data-translate-en="Update Password"
                        data-translate-it="Aggiorna Password">Aggiorna Password</span>
                </button>
            </form>

        <?php elseif ($step === 'done'): ?>
            <div class="success-container">
                <div class="success-icon">
                    <i class="fas fa-check-circle"></i>
                </div>
                <h1 class="success-title" data-translate-en="Password Updated!" data-translate-it="Password Aggiornata!">
                    Password Aggiornata!</h1>
                <p class="success-subtitle"
                    data-translate-en="Your password has been successfully updated. You can now log in with your new password."
                    data-translate-it="La tua password è stata aggiornata con successo. Ora puoi accedere con la nuova password.">
                    La tua password è stata aggiornata con successo. Ora puoi accedere con la nuova password.
                </p>
                <a href="login.php" class="login-btn">
                    <i class="fas fa-sign-in-alt"></i> <span data-translate-en="Go to Login"
                        data-translate-it="Vai al Login">Vai al Login</span>
                </a>
            </div>
        <?php endif; ?>

        <?php if ($step !== 'done'): ?>
            <a href="login.php" class="back-link" data-translate-en="Back to Login" data-translate-it="Torna al Login">
                <i class="fas fa-arrow-left"></i> Torna al Login
            </a>
        <?php endif; ?>
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
        function translatePage(lang) {
            localStorage.setItem('preferredLanguage', lang);

            document.querySelectorAll('[data-translate-it]').forEach(function (el) {
                el.textContent = lang === 'it' ? el.getAttribute('data-translate-it') : el.getAttribute('data-translate-en');
            });

            document.querySelectorAll('[data-placeholder-it]').forEach(function (el) {
                el.setAttribute('placeholder', lang === 'it' ? el.getAttribute('data-placeholder-it') : el.getAttribute('data-placeholder-en'));
            });

            document.getElementById('page-title').textContent = lang === 'it' ? 'Rena - Reimposta Password' : 'Rena - Reset Password';

            const flagImg = document.getElementById('lingua');
            flagImg.src = lang === 'it'
                ? 'https://renadeveloper.altervista.org/bandierait.png'
                : 'https://renadeveloper.altervista.org/bandieraen.png';
            flagImg.setAttribute('data-lang', lang);
        }

        document.getElementById('lingua').addEventListener('click', function (e) {
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

        document.getElementById('language-popup').addEventListener('click', function (e) {
            e.stopPropagation();
        });

        document.addEventListener('DOMContentLoaded', function () {
            const savedLang = localStorage.getItem('preferredLanguage') || 'it';
            translatePage(savedLang);

            document.querySelectorAll('.language-btn').forEach(btn => {
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

            <?php if ($error): ?>
                showError('<?php echo addslashes($error); ?>');
            <?php endif; ?>
        });

        const togglePassword = document.getElementById('toggle-password');
        if (togglePassword) {
            togglePassword.addEventListener('click', function () {
                const passwordInput = document.getElementById('new_password');
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
        }

        const codeInput = document.getElementById('code');
        if (codeInput) {
            codeInput.addEventListener('input', function (e) {
                this.value = this.value.replace(/\D/g, '');

                if (this.value.length > 6) {
                    this.value = this.value.slice(0, 6);
                }
            });
        }
    </script>
</body>

</html>

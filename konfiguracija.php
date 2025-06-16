
<?php
session_start();

// Database credentials
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root');
define('DB_PASSWORD', '');
define('DB_NAME', 'slaptazodziai');

// Attempt to connect to MySQL database
try {
    $mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
    if ($mysqli->connect_error) {
        throw new Exception("ERROR: Could not connect. " . $mysqli->connect_error);
    }
} catch (Exception $e) {
    die($e->getMessage());
}

// CSRF token generation
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Autoload classes
/*spl_autoload_register(function ($class_name) {
    include $class_name . '.php';
});*/
?>
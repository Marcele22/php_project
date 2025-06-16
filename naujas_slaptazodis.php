<?php
require_once "konfiguracija.php";
require_once "users.php";

if (!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
    header("Location: login.php");
    exit;
}

$errors = [];

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $user = new User($mysqli);
    $old_password = trim($_POST['old_password']);
    $new_password = trim($_POST['new_password']);
    $confirm_password = trim($_POST['confirm_password']);

    $result = $user->resetPassword($new_password, $confirm_password, $_SESSION['id'], $old_password);
    if ($result === true) {
        header("Location: login.php");
        exit;
    } else {
        $errors = $result;
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Keisti slaptažodį</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .wrapper { max-width: 400px; margin: 40px auto; padding: 20px; }
    </style>
</head>
<body>
    <div class="wrapper">
        <h2>Keisti slaptažodį</h2>
        <?php if (!empty($errors['general'])): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($errors['general']); ?></div>
        <?php endif; ?>
        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <div class="form-group">
                <label>Dabartinis slaptažodis</label>
                <input type="password" name="old_password" class="form-control <?php echo !empty($errors['old_password']) ? 'is-invalid' : ''; ?>">
                <div class="invalid-feedback"><?php echo htmlspecialchars($errors['old_password'] ?? ''); ?></div>
            </div>
            <div class="form-group">
                <label>Naujas slaptažodis</label>
                <input type="password" name="new_password" class="form-control <?php echo !empty($errors['new_password']) ? 'is-invalid' : ''; ?>">
                <div class="invalid-feedback"><?php echo htmlspecialchars($errors['new_password'] ?? ''); ?></div>
            </div>
            <div class="form-group">
                <label>Patvirtinkite slaptažodį</label>
                <input type="password" name="confirm_password" class="form-control <?php echo !empty($errors['confirm_password']) ? 'is-invalid' : ''; ?>">
                <div class="invalid-feedback"><?php echo htmlspecialchars($errors['confirm_password'] ?? ''); ?></div>
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Pateikti">
                <a href="welcome.php" class="btn btn-secondary ml-2">Atšaukti</a>
            </div>
        </form>
    </div>
</body>
</html>
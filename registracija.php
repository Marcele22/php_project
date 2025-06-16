<?php
require_once "konfiguracija.php";
require_once "users.php";
$email = "";
$errors = [];

if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST['csrf_token']) && $_POST['csrf_token'] === $_SESSION['csrf_token']) {
    $user = new User($mysqli);
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);
    $confirm_password = trim($_POST['confirm_password']);

    $result = $user->register($email, $password, $confirm_password);
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
    <title>Vartotojo registracija</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .container { max-width: 400px; margin: 50px auto; }
        .form-group { margin-bottom: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Registracija</h2>
        <?php if (!empty($errors['general'])): ?>
            <div class="alert alert-error"><?php echo htmlspecialchars($errors['general']); ?></div>
        <?php endif; ?>
        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <div class="form-group">
                <label>El. paštas</label>
                <input type="email" name="email" class="form-control <?php echo !empty($errors['email']) ? 'is-invalid' : ''; ?>" value="<?php echo htmlspecialchars($email); ?>">
                <div class="invalid-feedback"><?php echo htmlspecialchars($errors['email'] ?? ''); ?></div>
            </div>
            <div class="form-group">
                <label>Slaptažodis</label>
                <input type="password" name="password" class="form-control <?php echo !empty($errors['password']) ? 'is-invalid' : ''; ?>">
                <div class="invalid-feedback"><?php echo htmlspecialchars($errors['password'] ?? '') ?></div>
            </div>
            <div class="form-group">
                <label>Patvirtinkite slaptažodį</label>
                <input type="password" name="confirm_password" class="form-control <?php echo !empty($errors['confirm_password']) ? 'is-invalid' : ''; ?>">
                <div class="invalid-feedback"><?php echo htmlspecialchars($errors['confirm_password'] ?? '') ?></div>
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Registruotis">
            </div>
            <p>Jau turite paskyrą? <a href="login.php">Prisijungti</a>.</p>
        </form>
    </div>
</body>
</html>
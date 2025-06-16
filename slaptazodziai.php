<?php
require_once "konfiguracija.php";
require_once "slaptazodzio_generavimas.php";
require_once "slaptazodziu_valdymas.php";

if (!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
    header("Location: login.php");
    exit;
}

$length = $uppercase_count = $lowercase_count = $number_count = $special_count = 0;
$website_name = $password = $user_password = "";
$generated_password = "";
$errors = [];
$success_message = "";

// Handle password generation
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST['action']) && $_POST['action'] === 'generate' && isset($_POST['csrf_token']) && $_POST['csrf_token'] === $_SESSION['csrf_token']) {
    $generator = new SlaptazodzioGeneravimas();
    $length = (int)$_POST['length'];
    $uppercase_count = (int)$_POST['uppercase_count'];
    $lowercase_count = (int)$_POST['lowercase_count'];
    $number_count = (int)$_POST['number_count'];
    $special_count = (int)$_POST['special_count'];

    $result = $generator->generate($length, $uppercase_count, $lowercase_count, $number_count, $special_count);
    if (isset($result['password'])) {
        $generated_password = $result['password'];
        $password = $generated_password; // Pre-fill save form
    } else {
        $errors = $result['errors'];
    }
}

// Handle password saving
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST['action']) && $_POST['action'] === 'save' && isset($_POST['csrf_token']) && $_POST['csrf_token'] === $_SESSION['csrf_token']) {
    $password_manager = new slaptazodziu_valdymas($mysqli, $_SESSION['id']);
    $website_name = trim($_POST['website_name']);
    $password = trim($_POST['password']);
    $user_password = trim($_COOKIE['pass']);
    $sql_query = "SELECT * FROM passwords WHERE site_name = ? AND user_id = ?";
    $stmt = $mysqli->prepare($sql_query);
    $stmt->bind_param("si", $website_name, $_SESSION['id']);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows > 0) {
        // If the password already exists, update it
        $flag = true;
    } else {
        // If the password does not exist, insert it
        $flag = false;
    }
    $result = $password_manager->savePassword($website_name, $password, $user_password, $flag);
    if ($result === true) {
        $success_message = "Slaptažodis sėkmingai išsaugotas!";
    } else {
        $errors = $result;
    }
}

// Get saved passwords
$password_manager = new slaptazodziu_valdymas($mysqli, $_SESSION['id']);
$passwords = $password_manager->getPasswords($_COOKIE['pass']);

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Slaptažodžių tvarkymas</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .container { max-width: 800px; margin: 40px auto; }
        .form-group { margin-bottom: 20px; }
        .form-section { margin-bottom: 40px; }
        table { margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Slaptažodžių tvarkymas</h2>
        <?php if (!empty($success_message)): ?>
            <div class="alert alert-success"><?php echo htmlspecialchars($success_message); ?></div>
        <?php endif; ?>
        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger">
                <?php foreach ($errors as $error): ?>
                    <p><?php echo htmlspecialchars($error); ?></p>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

        <!-- Password Generation Form -->
        <div class="form-section">
            <h3>Generuoti slaptažodį</h3>
            <?php if (!empty($generated_password)): ?>
                <div class="alert alert-success">
                    <p>Sugeneruotas slaptažodis: <strong><?php echo htmlspecialchars($generated_password); ?></strong></p>
                </div>
            <?php endif; ?>
            <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <input type="hidden" name="action" value="generate">
                <div class="form-group">
                    <label>Slaptažodžio ilgis</label>
                    <input type="number" name="length" min="6" class="form-control" value="<?php echo $length; ?>">
                </div>
                <div class="form-group">
                    <label>Didžiosios raidės (kiekis)</label>
                    <input type="number" name="uppercase_count" min="0" class="form-control" value="<?php echo $uppercase_count; ?>">
                </div>
                <div class="form-group">
                    <label>Mažosios raidės (kiekis)</label>
                    <input type="number" name="lowercase_count" min="0" class="form-control" value="<?php echo $lowercase_count; ?>">
                </div>
                <div class="form-group">
                    <label>Skaičiai (kiekis)</label>
                    <input type="number" name="number_count" min="0" class="form-control" value="<?php echo $number_count; ?>">
                </div>
                <div class="form-group">
                    <label>Specialūs simboliai (kiekis)</label>
                    <input type="number" name="special_count" min="0" class="form-control" value="<?php echo $special_count; ?>">
                </div>
                <div class="form-group">
                    <input type="submit" class="btn btn-primary" value="Generuoti">
                </div>
            </form>
        </div>

        <!-- Password Saving Form -->
        <div class="form-section">
            <h3>Išsaugoti slaptažodį</h3>
            <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <input type="hidden" name="action" value="save">
                <div class="form-group">
                    <label>Svetainės pavadinimas</label>
                    <input type="text" name="website_name" class="form-control" value="<?php echo htmlspecialchars($website_name); ?>">
                </div>
                <div class="form-group">
                    <label>Slaptažodis</label>
                    <input type="text" name="password" class="form-control" value="<?php echo htmlspecialchars($password); ?>">
                </div>
                <div class="form-group">
                    <input type="submit" class="btn btn-primary" value="Išsaugoti">
                </div>
            </form>
        </div>

        <!-- Saved Passwords -->
        <h3>Jūsų slaptažodžiai</h3>

        <?php if (!empty($passwords) && !isset($passwords['error'])): ?>
            <table class="table table-bordered">
                <thead>
                    <tr>
                        <th>Svetainė</th>
                        <th>Slaptažodis</th>
                        <th>Sukūrimo data</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($passwords as $password): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($password['site_name']); ?></td>
                            <td><?php echo htmlspecialchars($password['encypted_password']); ?></td>
                            <td><?php echo htmlspecialchars($password['created_at']); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php elseif (isset($passwords['error'])): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($passwords['error']); ?></div>
        <?php endif; ?>
        <a href="welcome.php" class="btn btn-secondary">Grįžti</a>
    </div>
</body>
</html>
<?php
// Initialize the session
session_start();
 
// Check if the user is logged in, if not then redirect him to login page
if(!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true){
    header("location: login.php");
    exit;
}
?>
 
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sveiki</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body{ font: 14px sans-serif; text-align: center; }
    </style>
</head>
<body>
    <h1 class="my-5"> Labas! Tu mano svetainėje</h1>
    <p>
        <a href="logout.php" class="btn btn-danger ml-3">Atsijungti</a>
        <a href="slaptazodziai.php" class="btn btn-info ml-3">Tvarkyti slaptažodžius</a>
        <a href="naujas_slaptazodis.php" class="btn btn-success ml-3">Pakeisti slatažodį</a>
    </p>
</body>
</html>
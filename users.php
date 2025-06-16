<?php
class User {
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }

    public function register($email, $password, $confirm_password) {
        $errors = [];

        // Validate email
        if (empty(trim($email))) {
            $errors['email'] = "Please enter an email.";
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors['email'] = "Invalid email format.";
        } else {
            $sql = "SELECT id FROM users WHERE email = ?";
            if ($stmt = $this->mysqli->prepare($sql)) {
                $stmt->bind_param("s", $email);
                $stmt->execute();
                if ($stmt->get_result()->num_rows > 0) {
                    $errors['email'] = "This email is already taken.";
                }
                $stmt->close();
            }
        }

        // Validate password
        if (empty(trim($password))) {
            $errors['password'] = "Please enter a password.";
        } elseif (strlen(trim($password)) < 6) {
            $errors['password'] = "Password must have at least 6 characters.";
        }

        // Validate confirm password
        if (empty(trim($confirm_password))) {
            $errors['confirm_password'] = "Please confirm password.";
        } elseif ($password !== $confirm_password) {
            $errors['confirm_password'] = "Passwords do not match.";
        }

        if (empty($errors)) {
            // Generate encryption key
            $raw_key = random_bytes(32); // 256-bit key
            $iv = random_bytes(16);
            $hashed_password = hash('sha256', $password, true);
            $encrypted_key = openssl_encrypt($raw_key, 'AES-256-CBC', $hashed_password, 0, $iv);
            $encrypted_key = base64_encode($iv . $encrypted_key);

            // Insert user
            $sql = "INSERT INTO users (email, password_hash, encrypted_key) VALUES (?, ?, ?)";
            if ($stmt = $this->mysqli->prepare($sql)) {
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                $stmt->bind_param("sss", $email, $hashed_password, $encrypted_key);
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                if ($stmt->execute()) {
                    return true;
                } else {
                    $errors['general'] = "Something went wrong. Please try again later.";
                }
                $stmt->close();
            }
        }

        return $errors;
    }

    public function login($email, $password) {
        $errors = [];

        if (empty(trim($email))) {
            $errors['email'] = "Please enter email.";
        }
        if (empty(trim($password))) {
            $errors['password'] = "Please enter password.";
        }

        if (empty($errors)) {
            $sql = "SELECT id, email, password_hash FROM users WHERE email = ?";
            if ($stmt = $this->mysqli->prepare($sql)) {
                $stmt->bind_param("s", $email);
                $stmt->execute();
                $result = $stmt->get_result();
                if ($result->num_rows === 1) {
                    $user = $result->fetch_assoc();
                    if (password_verify($password, $user['password_hash'])) {
                        setcookie("pass", $password, time() + (86400 * 30), "/"); 
                        $_SESSION['loggedin'] = true;
                        $_SESSION['id'] = $user['id'];
                        $_SESSION['email'] = $user['email'];
                        echo "User logged in successfully.";
                        session_regenerate_id();
                        return true;
                    } else {
                        $errors['general'] = "Invalid email or password.";
                    }
                } else {
                    $errors['general'] = "Invalid email or password.";
                }
                $stmt->close();
            }
        }

        return $errors;
    }

    public function resetPassword($new_password, $confirm_password, $user_id, $old_password) {
        $errors = [];

        // Validate new password
        if (empty(trim($new_password))) {
            $errors['new_password'] = "Please enter the new password.";
        } elseif (strlen(trim($new_password)) < 6) {
            $errors['new_password'] = "Password must have at least 6 characters.";
        }

        // Validate confirm password
        if (empty(trim($confirm_password))) {
            $errors['confirm_password'] = "Please confirm the password.";
        } elseif ($new_password !== $confirm_password) {
            $errors['confirm_password'] = "Passwords do not match.";
        }

        if (empty($errors)) {
            // Get current encrypted key
            $sql = "SELECT encrypted_key, password_hash FROM users WHERE id = ?";
            if ($stmt = $this->mysqli->prepare($sql)) {
                $stmt->bind_param("i", $user_id);
                $stmt->execute();
                $result = $stmt->get_result()->fetch_assoc();
                $encrypted_key = $result['encrypted_key'];
                $current_password = $result['password_hash'];
                $stmt->close();

                if (!password_verify($old_password, $current_password)) {
                    $errors['old_password'] = "Current password is incorrect.";
                } else {
                    // Decrypt and re-encrypt key
                    $data = base64_decode($encrypted_key);
                    $iv = substr($data, 0, 16);
                    $encrypted = substr($data, 16);
                    $hashed_old_password = hash('sha256', $old_password, true);
                    $raw_key = openssl_decrypt($encrypted, 'AES-256-CBC', $hashed_old_password, 0, $iv);

                    if ($raw_key !== false) {
                        $new_iv = random_bytes(16);
                        $hashed_new_password = hash('sha256', $new_password, true);
                        $new_encrypted_key = openssl_encrypt($raw_key, 'AES-256-CBC', $hashed_new_password, 0, $new_iv);
                        $new_encrypted_key = base64_encode($new_iv . $new_encrypted_key);

                        // Update password and key
                        $sql = "UPDATE users SET password_hash = ?, encrypted_key = ? WHERE id = ?";
                        if ($stmt = $this->mysqli->prepare($sql)) {
                            $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
                            $stmt->bind_param("ssi", $hashed_password, $new_encrypted_key, $user_id);
                            if ($stmt->execute()) {
                                session_destroy();
                                return true;
                            } else {
                                $errors['general'] = "Something went wrong. Please try again later.";
                            }
                            $stmt->close();
                        }
                    } else {
                        $errors['general'] = "Failed to decrypt key. Please try again.";
                    }
                }
            }
        }

        return $errors;
    }
}
?>
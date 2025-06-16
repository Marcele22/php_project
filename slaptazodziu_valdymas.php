<?php
class slaptazodziu_valdymas {
    private $mysqli;
    private $user_id;
    private $cipher = 'AES-256-CBC';

    public function __construct($mysqli, $user_id) {
        $this->mysqli = $mysqli;
        $this->user_id = $user_id;
    }

    private function decryptKey($encrypted_key, $password) {
        $data = base64_decode($encrypted_key);
        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);
        $hashed_password = hash('sha256', $password, true);
        return openssl_decrypt($encrypted, $this->cipher, $hashed_password, 0, $iv);
    }

    public function savePassword($website_name, $password, $user_password, $flag = false) {
        $errors = [];

        if (empty(trim($website_name))) {
            $errors['website_name'] = "Irasykite svetainės pavadinimą.";
        }
        if (empty(trim($password))) {
            $errors['password'] = "Įrašykite slaptažodį.";
        }

        if (empty($errors)) {
            $sql = "SELECT encrypted_key FROM users WHERE id = ?";
            if ($stmt = $this->mysqli->prepare($sql)) {
                $stmt->bind_param("i", $this->user_id);
                $stmt->execute();
                $encrypted_key = $stmt->get_result()->fetch_assoc()['encrypted_key'];
                $stmt->close();

                $raw_key = $this->decryptKey($encrypted_key, $user_password);

                if ($raw_key !== false) {
                    // Encrypt password with key
                    $iv = random_bytes(16);
                    $encrypted_password = openssl_encrypt($password, $this->cipher, $raw_key, 0, $iv);
                    $encrypted_password = base64_encode($iv . $encrypted_password);

                    // Save to database
                    if( $flag ) {
                        $sql = "UPDATE passwords SET site_name = ?, encrypted_password = ? WHERE user_id = ? AND site_name = ?";
                        $stmt = $this->mysqli->prepare($sql);
                        $stmt->bind_param("ssis", $website_name, $encrypted_password, $this->user_id, $website_name);
                        if ($stmt->execute()) {
                            return true;
                        } else {
                            $errors['general'] = "Nepavyko atnaujinti slaptažodžio.";
                        }
                    }else{
                        $sql = "INSERT INTO passwords (user_id, site_name, encrypted_password) VALUES (?, ?, ?)";
                        if ($stmt = $this->mysqli->prepare($sql)) {
                        $stmt->bind_param("iss", $this->user_id, $website_name, $encrypted_password);
                        if ($stmt->execute()) {
                            return true;
                        } else {
                            $errors['general'] = "Nepavyko išsaugoti slaptažodžio.";
                        }
                        $stmt->close();
                     }

                    }
                    
                } else {
                    $errors['user_password'] = "Neteisingas vartotojo slaptažodis.";
                }
            }
        }

        return $errors;
    }

    public function getPasswords($user_password) {
        $passwords = [];
        $sql = "SELECT id, site_name, encrypted_password, created_at FROM passwords WHERE user_id = ?";
        if ($stmt = $this->mysqli->prepare($sql)) {
            $stmt->bind_param("i", $this->user_id);
            $stmt->execute();
            $result = $stmt->get_result();

            $sql_key = "SELECT encrypted_key FROM users WHERE id = ?";
            if ($stmt_key = $this->mysqli->prepare($sql_key)) {
                $stmt_key->bind_param("i", $this->user_id);
                $stmt_key->execute();
                $encrypted_key = $stmt_key->get_result()->fetch_assoc()['encrypted_key'];
                $stmt_key->close();

                $raw_key = $this->decryptKey($encrypted_key, $user_password);

                if ($raw_key !== false) {
                    while ($row = $result->fetch_assoc()) {
                        // Decrypt password
                        $encrypted_password = base64_decode($row['encrypted_password']);
                        $iv = substr($encrypted_password, 0, 16);
                        $encrypted = substr($encrypted_password, 16);
                        $decrypted_password = openssl_decrypt($encrypted, $this->cipher, $raw_key, 0, $iv);
                        $passwords[] = [
                            'id' => $row['id'],
                            'site_name' => $row['site_name'],
                            'encypted_password' => $decrypted_password ?: 'Decryption failed',
                            'created_at' => $row['created_at']
                        ];
                    }
                }else {
                    return ['error' => 'Neteisingas vartotojo slaptažodis.'];
                }
            }
            $stmt->close();
        }
        return $passwords;
    }
}
?>
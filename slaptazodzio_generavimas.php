<?php
class SlaptazodzioGeneravimas {
    private $lowercase = 'abcdefghijklmnopqrstuvwxyz';
    private $uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    private $numbers = '0123456789';
    private $special = '!@#$%^&*()_+-=[]{}|;:,.<>?';

    public function generate($length, $uppercase_count, $lowercase_count, $number_count, $special_count) {
        $errors = [];

        // Validate total length
        $total = $uppercase_count + $lowercase_count + $number_count + $special_count;
        if ($total > $length) {
            $errors['length'] = "Ženklų skaičius viršija nurodytą ilgį.";
        } elseif ($total < $length) {
            $errors['length'] = "Ženklų skaičius yra mažesnis nei nurodytas ilgis.";
        }

        if ($uppercase_count < 0 || $lowercase_count < 0 || $number_count < 0 || $special_count < 0) {
            $errors['counts'] = "Simbolių skaičius negali būti neigiamas.";
        }

        if (empty($errors)) {
            $password = '';
            // Add required characters
            for ($i = 0; $i < $uppercase_count; $i++) {
                $password .= $this->uppercase[random_int(0, strlen($this->uppercase) - 1)];
            }
            for ($i = 0; $i < $lowercase_count; $i++) {
                $password .= $this->lowercase[random_int(0, strlen($this->lowercase) - 1)];
            }
            for ($i = 0; $i < $number_count; $i++) {
                $password .= $this->numbers[random_int(0, strlen($this->numbers) - 1)];
            }
            for ($i = 0; $i < $special_count; $i++) {
                $password .= $this->special[random_int(0, strlen($this->special) - 1)];
            }

            // Shuffle password
            $password = str_shuffle($password);
            return ['password' => $password];
        }

        return ['errors' => $errors];
    }
}
?>
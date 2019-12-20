package dev.juniorstreichan.course;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class BcryptTests {

    @Test
    void generatePassword() {
        // GERA SENHA
        var passwordEncoder = new BCryptPasswordEncoder();
        System.out.println(passwordEncoder.encode("java"));
    }
}

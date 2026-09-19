package com.arthur.security.attacks.bruteforce;

import com.arthur.security.attacks.report.SecurityReport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Sensitive data exposure (OWASP A02:2021): why passwords must be hashed with a slow, salted algorithm
 * and never stored or compared as plaintext.
 */
class PasswordStorageTest {

    private final PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    @Test
    @DisplayName("VULNERABLE: plaintext storage leaks the password and reveals reuse")
    void plaintextStorageIsReadable() {
        // Simulates storing the raw password and comparing with String.equals.
        String storedForAlice = "hunter2";
        String storedForBob = "hunter2";

        assertEquals("hunter2", storedForAlice);           // one DB leak burns every credential
        assertEquals(storedForAlice, storedForBob);        // identical => password reuse is visible

        SecurityReport.vulnerable("Armazenamento de Senha", "senha em texto puro no banco", "vazamento expoe a senha e revela reuso entre contas");
    }

    @Test
    @DisplayName("DEFENSE: BCrypt hashes are prefixed, non-reversible, verifiable and uniquely salted")
    void bcryptStorageIsSafe() {
        String hash = encoder.encode("hunter2");

        assertTrue(hash.startsWith("{bcrypt}$2"));          // DelegatingPasswordEncoder marks the scheme
        assertNotEquals("hunter2", hash);                   // not the plaintext
        assertTrue(encoder.matches("hunter2", hash));       // still verifiable
        assertFalse(encoder.matches("wrong", hash));

        // Same password, two encodings => different hashes (per-hash salt), so reuse is not detectable.
        assertNotEquals(encoder.encode("hunter2"), encoder.encode("hunter2"));

        SecurityReport.defended("Armazenamento de Senha", "{bcrypt} via DelegatingPasswordEncoder", "hash com salt unico, irreversivel e ainda verificavel");
    }
}

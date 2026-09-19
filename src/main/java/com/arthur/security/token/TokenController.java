package com.arthur.security.token;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.SecureRandom;
import java.util.HexFormat;

/**
 * Hardened counterpart to {@code /vulnerable/token} (OWASP A02:2021, CWE-330 - use of insufficiently
 * random values).
 *
 * <p>Security tokens (password-reset links, session ids, API keys) must be unpredictable. The
 * vulnerable version uses {@link java.util.Random}, which is a deterministic pseudo-random generator:
 * anyone who learns or guesses the seed can reproduce every value it will ever emit. This endpoint uses
 * {@link SecureRandom} - a cryptographically strong generator - and 256 bits of entropy, so the token
 * cannot be predicted or brute-forced. The {@code seed} parameter is accepted but deliberately ignored,
 * to make the contrast visible: a real generator does not take a caller-supplied seed.
 */
@RestController
public class TokenController {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @GetMapping("/api/token")
    public String token(@RequestParam(required = false) Long seed) {
        byte[] bytes = new byte[32]; // 256 bits
        SECURE_RANDOM.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }
}

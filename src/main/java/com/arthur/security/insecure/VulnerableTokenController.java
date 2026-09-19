package com.arthur.security.insecure;

import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Random;

/**
 * Deliberately INSECURE: derives a "security token" from {@link java.util.Random} seeded by a
 * caller-influenced value (CWE-330 - insufficiently random values). Hardened counterpart:
 * {@code /api/token}.
 *
 * <p>{@code java.util.Random} is a deterministic PRNG: the same seed always yields the same sequence.
 * Calling this twice with {@code seed=42} returns the identical token, so anyone who guesses the seed
 * (often derived from the current time) can predict password-reset tokens or session ids.
 */
@RestController
@Profile("insecure")
public class VulnerableTokenController {

    @GetMapping("/vulnerable/token")
    public String token(@RequestParam(defaultValue = "42") long seed) {
        // BUG: predictable generator + caller-known seed.
        long value = new Random(seed).nextLong();
        return Long.toHexString(value);
    }
}

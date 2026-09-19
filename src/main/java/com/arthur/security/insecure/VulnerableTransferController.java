package com.arthur.security.insecure;

import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Deliberately INSECURE: a money-moving POST with CSRF protection off (CWE-352). Hardened contrast:
 * the real form-login POST requires a CSRF token. On this lab chain CSRF is disabled, so a tokenless
 * cross-site POST is accepted.
 */
@RestController
@Profile("insecure")
public class VulnerableTransferController {

    @PostMapping("/vulnerable/transfer")
    public String transfer(@RequestParam String to, @RequestParam String amount) {
        // BUG: no CSRF token required for a state change.
        return "transferido " + amount + " para " + to;
    }
}

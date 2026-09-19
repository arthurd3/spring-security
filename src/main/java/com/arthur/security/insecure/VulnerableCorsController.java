package com.arthur.security.insecure;

import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Deliberately INSECURE: reflects any Origin and allows credentials (CWE-942, CORS misconfiguration).
 * Hardened contrast: {@code /api/**} allows exactly one configured origin.
 */
@RestController
@Profile("insecure")
public class VulnerableCorsController {

    @CrossOrigin(originPatterns = "*", allowCredentials = "true")
    @GetMapping("/vulnerable/cors/balance")
    public String balance() {
        return "{\"balance\":1500.00}";
    }
}

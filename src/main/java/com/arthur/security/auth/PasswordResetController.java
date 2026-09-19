package com.arthur.security.auth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Builds a password-reset link from a TRUSTED, configured base URL - the fix for host header injection
 * (CWE-644 / web cache & password-reset poisoning).
 *
 * <p>The vulnerable version builds the link from the incoming {@code Host} header, which the client
 * fully controls. An attacker requests a reset for the victim with {@code Host: evil.example}; the
 * victim receives a real-looking email whose link points at the attacker's server, handing over the
 * reset token when clicked. The fix is never to trust the {@code Host} header for anything security
 * relevant - use a value the server was configured with.
 */
@RestController
public class PasswordResetController {

    private final String baseUrl;

    public PasswordResetController(@Value("${app.base-url:https://myapp.example}") String baseUrl) {
        this.baseUrl = baseUrl;
    }

    @GetMapping("/api/reset-link")
    public String resetLink(@RequestParam String user) {
        String token = "demo-token-for-" + user;
        // Built from the configured base URL, so the Host header cannot redirect the link.
        return baseUrl + "/reset?token=" + token;
    }
}

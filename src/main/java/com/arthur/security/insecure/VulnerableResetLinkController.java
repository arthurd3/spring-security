package com.arthur.security.insecure;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Deliberately INSECURE: builds a password-reset link from the client-controlled {@code Host} header
 * (CWE-644 - host header injection / password-reset poisoning). Hardened counterpart:
 * {@code /api/reset-link}.
 *
 * <p>Send {@code Host: evil.example} and the victim's reset email points at the attacker's server,
 * leaking the reset token when clicked.
 */
@RestController
@Profile("insecure")
public class VulnerableResetLinkController {

    @GetMapping("/vulnerable/reset-link")
    public String resetLink(@RequestParam String user, HttpServletRequest request) {
        String token = "demo-token-for-" + user;
        // BUG: the Host header is attacker-controlled.
        String host = request.getHeader("Host");
        return "http://" + host + "/reset?token=" + token;
    }
}

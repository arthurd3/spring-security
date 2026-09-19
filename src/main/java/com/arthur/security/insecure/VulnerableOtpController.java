package com.arthur.security.insecure;

import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Deliberately INSECURE: OTP verification with NO rate limiting (CWE-770). Hardened counterpart:
 * {@code /api/otp-verify}. A 4-digit code has 10,000 possibilities - trivially brute-forced when every
 * attempt is accepted.
 */
@RestController
@Profile("insecure")
public class VulnerableOtpController {

    @GetMapping("/vulnerable/otp-verify")
    public ResponseEntity<String> verify(@RequestParam String code) {
        boolean ok = "1234".equals(code);
        return ResponseEntity.status(ok ? HttpStatus.OK : HttpStatus.UNAUTHORIZED)
                .body(ok ? "verified" : "invalid code");
    }
}

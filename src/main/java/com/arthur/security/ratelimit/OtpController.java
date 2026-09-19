package com.arthur.security.ratelimit;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

/**
 * Hardened OTP verification: throttled per client so it cannot be brute-forced. The vulnerable
 * counterpart {@code /vulnerable/otp-verify} accepts unlimited attempts.
 */
@RestController
public class OtpController {

    private static final int MAX_ATTEMPTS = 5;
    private static final Duration WINDOW = Duration.ofMinutes(1);

    private final RateLimiter rateLimiter;

    public OtpController(RateLimiter rateLimiter) {
        this.rateLimiter = rateLimiter;
    }

    @GetMapping("/api/otp-verify")
    public ResponseEntity<String> verify(@RequestParam String code, HttpServletRequest request) {
        String key = request.getRemoteAddr();
        if (!rateLimiter.tryAcquire(key, MAX_ATTEMPTS, WINDOW)) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body("Too many attempts - try again later");
        }
        boolean ok = "1234".equals(code);
        return ResponseEntity.status(ok ? HttpStatus.OK : HttpStatus.UNAUTHORIZED)
                .body(ok ? "verified" : "invalid code");
    }
}

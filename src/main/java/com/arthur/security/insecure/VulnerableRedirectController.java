package com.arthur.security.insecure;

import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Deliberately INSECURE: echoes any URL into the Location header (CWE-601, open redirect).
 * Hardened counterpart: {@code /api/redirect} (allowlist).
 */
@RestController
@Profile("insecure")
public class VulnerableRedirectController {

    @GetMapping("/vulnerable/redirect")
    public ResponseEntity<Void> redirect(@RequestParam("url") String url) {
        return ResponseEntity.status(HttpStatus.FOUND).header("Location", url).build();
    }
}

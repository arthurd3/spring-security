package com.arthur.security.insecure;

import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Deliberately INSECURE: writes user input to the "log" verbatim (CWE-117 - log injection). Hardened
 * counterpart: {@code /api/log}.
 *
 * <p>A newline in the input forges a second log line - e.g. a fake "user admin logged in" entry. The
 * endpoint returns the exact text it would log, so the injected newline (two lines) is visible.
 */
@RestController
@Profile("insecure")
public class VulnerableLogController {

    @GetMapping("/vulnerable/log")
    public String record(@RequestParam String user) {
        // BUG: raw input becomes part of the log line, newlines included.
        return "login attempt for user=" + user;
    }
}

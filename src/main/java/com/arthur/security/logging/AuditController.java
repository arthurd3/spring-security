package com.arthur.security.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Writes an audit line with user input SANITISED first - the fix for log injection / log forging
 * (OWASP A09:2021, CWE-117).
 *
 * <p>If raw input is logged, a value containing a newline injects an entire fake log line: an attacker
 * can forge "user admin logged in" entries, hide their tracks, or break log parsers and dashboards. The
 * fix is to strip or encode CR/LF (and other control characters) before the value reaches the log.
 *
 * <p>The endpoint returns the exact string it logged, so the demo can show it is a single line.
 */
@RestController
public class AuditController {

    private static final Logger log = LoggerFactory.getLogger(AuditController.class);

    @GetMapping("/api/log")
    public String record(@RequestParam String user) {
        String safe = sanitise(user);
        String line = "login attempt for user=" + safe;
        log.info(line);
        return line;
    }

    /** Collapse anything that could start a new log line (CR, LF, tab and other control chars). */
    static String sanitise(String value) {
        return value.replaceAll("[\\r\\n\\t\\p{Cntrl}]", "_");
    }
}

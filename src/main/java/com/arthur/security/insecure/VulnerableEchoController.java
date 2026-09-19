package com.arthur.security.insecure;

import org.springframework.context.annotation.Profile;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Deliberately INSECURE: reflects raw input into an HTML response (CWE-79, reflected XSS).
 * Hardened counterpart: {@code /api/v1/echo} (HTML-escaped).
 */
@RestController
@Profile("insecure")
public class VulnerableEchoController {

    @GetMapping(value = "/vulnerable/echo", produces = MediaType.TEXT_HTML_VALUE)
    public String echo(@RequestParam(defaultValue = "") String message) {
        // BUG: user input placed into HTML with no encoding.
        return "<html><body>You said: " + message + "</body></html>";
    }
}

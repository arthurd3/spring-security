package com.arthur.security.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Locale;

/**
 * A "return to where you came from" redirect that cannot be pointed at an attacker's site.
 *
 * <p>Open redirect (CWE-601) turns your domain into a credible launch pad for phishing: the victim
 * sees a link to the site they trust, and lands on the attacker's login page. It is also the classic
 * way to smuggle OAuth codes and tokens out of an application.
 *
 * <p>Two rules, applied in order:
 * <ol>
 *   <li>A <b>relative path</b> is accepted, but only if it starts with a single {@code /}. Rejecting
 *       {@code //evil.example} matters because browsers read a protocol-relative URL as an absolute
 *       one; {@code \\} is rejected for the same reason, since browsers normalise it to {@code /}.</li>
 *   <li>An <b>absolute URL</b> is accepted only if its host is on the allowlist. Matching the host of
 *       a parsed {@link URI} - never {@code startsWith} on the raw string - is what stops tricks like
 *       {@code https://trusted.example.evil.test} and {@code https://evil.test/?x=trusted.example}.</li>
 * </ol>
 */
@RestController
public class SafeRedirectController {

    private final List<String> allowedHosts;

    public SafeRedirectController(
            @Value("${app.redirect.allowed-hosts:localhost}") List<String> allowedHosts) {
        this.allowedHosts = allowedHosts.stream().map(host -> host.toLowerCase(Locale.ROOT)).toList();
    }

    @GetMapping("/api/redirect")
    public ResponseEntity<Void> redirect(@RequestParam("to") String to) {
        if (!isAllowed(to)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Redirect target not allowed");
        }
        return ResponseEntity.status(HttpStatus.FOUND).header("Location", to).build();
    }

    boolean isAllowed(String target) {
        if (target == null || target.isBlank()) {
            return false;
        }
        // Control characters (CR/LF/NUL) would allow header injection on top of the redirect.
        for (int i = 0; i < target.length(); i++) {
            if (Character.isISOControl(target.charAt(i))) {
                return false;
            }
        }

        String normalised = target.replace('\\', '/');
        if (normalised.startsWith("/")) {
            return !normalised.startsWith("//");
        }

        try {
            URI uri = new URI(target);
            String host = uri.getHost();
            if (host == null || !uri.isAbsolute()) {
                return false;
            }
            String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
            if (!scheme.equals("http") && !scheme.equals("https")) {
                return false;
            }
            return allowedHosts.contains(host.toLowerCase(Locale.ROOT));
        } catch (URISyntaxException e) {
            return false;
        }
    }
}

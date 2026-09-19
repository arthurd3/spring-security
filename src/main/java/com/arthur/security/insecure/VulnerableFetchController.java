package com.arthur.security.insecure;

import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;

/**
 * Deliberately INSECURE: fetches any URL the caller supplies, any scheme (CWE-918, SSRF).
 * Hardened counterpart: {@code /api/fetch} (scheme+host allowlist, resolved-address check).
 */
@RestController
@Profile("insecure")
public class VulnerableFetchController {

    @GetMapping("/vulnerable/fetch")
    public String fetch(@RequestParam String url) throws Exception {
        // BUG: no scheme check, no host allowlist. file:// reads local files; http:// reaches internal hosts.
        try (InputStream in = URI.create(url).toURL().openStream()) {
            byte[] bytes = in.readAllBytes();
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }
}

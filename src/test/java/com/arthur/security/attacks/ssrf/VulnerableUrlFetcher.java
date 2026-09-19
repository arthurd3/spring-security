package com.arthur.security.attacks.ssrf;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;

/**
 * A deliberately INSECURE "fetch this URL for me" helper (OWASP A10:2021, server-side request forgery).
 *
 * <p>The feature is innocuous on its face - import from a URL, render a link preview, proxy a webhook.
 * The problem is who is making the request: the server sits inside the network, so the attacker
 * borrows its position to reach things they cannot route to themselves. Cloud metadata endpoints at
 * {@code 169.254.169.254}, admin panels bound to loopback, databases on the private subnet.
 *
 * <p>This is a plain class with no stereotype annotation, so component scanning ignores it outright.
 * The safe counterpart is {@code UrlFetchService}, which allowlists the host, re-checks the resolved
 * address, and refuses to follow redirects.
 */
class VulnerableUrlFetcher {

    String fetch(String url) throws IOException {
        // BUG: no scheme check, no host allowlist, no check on where the name resolves to.
        try (InputStream in = URI.create(url).toURL().openStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}

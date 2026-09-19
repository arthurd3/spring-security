package com.arthur.security.net;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Locale;

/**
 * Fetches a URL on the server's behalf, with the guards that make SSRF (OWASP A10:2021) impractical.
 *
 * <p>SSRF turns the application into a proxy for the attacker: because the request originates inside
 * the network, it reaches things the attacker cannot reach directly - cloud metadata endpoints
 * ({@code http://169.254.169.254/}), admin panels bound to loopback, databases on the private subnet.
 *
 * <p>Four guards, all of which must pass:
 * <ol>
 *   <li><b>Scheme allowlist</b> - only {@code http}/{@code https}. Blocks {@code file://},
 *       {@code gopher://}, {@code jar://} and friends.</li>
 *   <li><b>Host allowlist</b> - a positive list, not a blocklist. Blocklists lose to decimal-encoded
 *       IPs, IPv6-mapped addresses, and DNS names that simply resolve to an internal address.</li>
 *   <li><b>Address check after DNS resolution</b> - the allowlisted name is resolved and the resulting
 *       address must be routable. This is what stops DNS rebinding, where an attacker-controlled name
 *       on the allowlist resolves to {@code 127.0.0.1}.</li>
 *   <li><b>Redirects disabled</b> - otherwise an allowlisted host answers with
 *       {@code 302 Location: http://169.254.169.254/} and the client follows it straight past guards
 *       1-3.</li>
 * </ol>
 */
@Service
public class UrlFetchService {

    private static final Duration TIMEOUT = Duration.ofSeconds(3);

    private final List<String> allowedHosts;
    private final HttpClient client;

    public UrlFetchService(@Value("${app.fetch.allowed-hosts:}") List<String> allowedHosts) {
        this.allowedHosts = allowedHosts.stream()
                .filter(host -> !host.isBlank())
                .map(host -> host.trim().toLowerCase(Locale.ROOT))
                .toList();
        this.client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(TIMEOUT)
                .build();
    }

    /** Validates the URL against every guard, throwing 400 on the first failure. */
    public URI validate(String url) {
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            throw reject("Malformed URL");
        }

        if (!uri.isAbsolute() || uri.getScheme() == null) {
            throw reject("URL must be absolute");
        }
        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            throw reject("Only http and https are allowed");
        }

        String host = uri.getHost();
        if (host == null) {
            throw reject("URL has no host");
        }
        if (!allowedHosts.contains(host.toLowerCase(Locale.ROOT))) {
            throw reject("Host is not on the allowlist");
        }

        for (InetAddress address : resolve(host)) {
            if (isInternal(address)) {
                throw reject("Host resolves to an internal address");
            }
        }
        return uri;
    }

    /** Validates, then performs the request. */
    public String fetch(String url) {
        URI uri = validate(url);
        HttpRequest request = HttpRequest.newBuilder(uri).timeout(TIMEOUT).GET().build();
        try {
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            return response.body();
        } catch (IOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Upstream request failed");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Upstream request interrupted");
        }
    }

    /** True for anything that is not a routable public address. */
    static boolean isInternal(InetAddress address) {
        return address.isLoopbackAddress()
                || address.isAnyLocalAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isMulticastAddress();
    }

    private InetAddress[] resolve(String host) {
        try {
            return InetAddress.getAllByName(host);
        } catch (UnknownHostException e) {
            throw reject("Host could not be resolved");
        }
    }

    private static ResponseStatusException reject(String reason) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, reason);
    }
}

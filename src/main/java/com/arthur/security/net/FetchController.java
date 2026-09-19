package com.arthur.security.net;

import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Server-side URL fetch, restricted to admins on top of the allowlist in {@link UrlFetchService}.
 * An endpoint that makes outbound requests is high value to an attacker, so it gets both controls.
 */
@RestController
public class FetchController {

    private final UrlFetchService urlFetchService;

    public FetchController(UrlFetchService urlFetchService) {
        this.urlFetchService = urlFetchService;
    }

    @GetMapping(value = "/api/fetch", produces = MediaType.TEXT_PLAIN_VALUE)
    @PreAuthorize("hasRole('ADMIN')")
    public String fetch(@RequestParam String url) {
        return urlFetchService.fetch(url);
    }
}

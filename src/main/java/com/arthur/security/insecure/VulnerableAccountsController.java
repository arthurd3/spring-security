package com.arthur.security.insecure;

import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Deliberately INSECURE: returns any account by id with no ownership check (CWE-639, IDOR).
 * Hardened counterpart: {@code /api/accounts/{id}} ({@code @PostAuthorize} ownership).
 */
@RestController
@Profile("insecure")
public class VulnerableAccountsController {

    private static final Map<Long, String> OWNERS = Map.of(1L, "alice", 2L, "bob", 3L, "carol");

    @GetMapping("/vulnerable/accounts/{id}")
    public String account(@PathVariable Long id) {
        // BUG: no check that the caller owns account {id}.
        return "conta " + id + " pertence a " + OWNERS.getOrDefault(id, "?") + " (saldo secreto: 9999)";
    }
}

package com.arthur.security.attacks.dataexposure;

import com.arthur.security.VulnerableExample;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.time.Instant;

/**
 * A deliberately INSECURE profile endpoint that serialises the persistence entity straight to JSON
 * (OWASP A02:2021 / CWE-200, sensitive data exposure).
 *
 * <p>Nobody decided to publish the password hash - Jackson simply serialises every getter it finds.
 * The bug is structural: the response contract is "whatever columns the entity happens to have today",
 * so each new column is a potential leak, and reviewers never see a line of code to object to.
 *
 * <p>A leaked BCrypt hash is not harmless. It is offline-crackable at attacker leisure, and it
 * confirms which accounts exist. The internal id and lock timestamps help an attacker too.
 */
@VulnerableExample
@Controller
public class VulnerableProfileController {

    @GetMapping("/vulnerable/profile")
    @ResponseBody
    public UserEntity profile() {
        // BUG: the entity is the response. Every field goes out, including the credential.
        return new UserEntity(
                7L,
                "arthur",
                "{bcrypt}$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
                "USER",
                Instant.parse("2026-01-01T00:00:00Z"));
    }

    /** Stands in for the JPA entity, with the columns a real user table carries. */
    @Getter
    @AllArgsConstructor
    public static class UserEntity {
        private Long id;
        private String username;
        private String password;
        private String roles;
        private Instant lockedUntil;
    }
}

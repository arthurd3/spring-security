package com.arthur.security.insecure;

import com.arthur.security.user.AppUser;
import com.arthur.security.user.AppUserRepository;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Deliberately INSECURE: serialises the full user record, password hash included (CWE-200).
 * Hardened counterpart: {@code /api/users/me} (DTO with no credential).
 */
@RestController
@Profile("insecure")
public class VulnerableProfileController {

    private final AppUserRepository users;

    public VulnerableProfileController(AppUserRepository users) {
        this.users = users;
    }

    @GetMapping("/vulnerable/profile")
    public Map<String, Object> profile() {
        AppUser u = users.findByUsername("arthur").orElseThrow();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", u.getId());
        out.put("username", u.getUsername());
        out.put("password", u.getPassword()); // BUG: leaks the stored BCrypt hash
        out.put("roles", u.getRoles());
        out.put("lockedUntil", u.getLockedUntil());
        return out;
    }
}

package com.arthur.security.user;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Exposes the authenticated user's own profile - and nothing else.
 *
 * <p>The lookup is keyed off {@link Authentication#getName()} rather than a client-supplied id, so
 * there is no object reference for an attacker to tamper with, and the response is a
 * {@link UserProfile} DTO so the stored password hash never reaches the wire.
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

    private final AppUserRepository users;

    public UserController(AppUserRepository users) {
        this.users = users;
    }

    @GetMapping("/me")
    public UserProfile me(Authentication authentication) {
        return users.findByUsername(authentication.getName())
                .map(UserProfile::from)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    }
}

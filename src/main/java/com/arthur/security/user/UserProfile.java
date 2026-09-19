package com.arthur.security.user;

import java.util.List;

/**
 * The safe projection of an {@link AppUser} for API responses.
 *
 * <p>Returning a purpose-built DTO is the primary defense against sensitive-data exposure
 * (OWASP A02:2021, CWE-200): the response can only ever contain the fields listed here, so a column
 * added to the entity later - a password hash, a reset token, a TOTP secret - cannot silently start
 * leaking through an endpoint that was written before it existed.
 */
public record UserProfile(String username, List<String> roles) {

    public static UserProfile from(AppUser user) {
        return new UserProfile(user.getUsername(), List.of(user.roleArray()));
    }
}

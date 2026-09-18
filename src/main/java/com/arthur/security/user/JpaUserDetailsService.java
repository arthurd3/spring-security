package com.arthur.security.user;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;

/**
 * Loads users from the database for authentication.
 *
 * <p>Any {@link UserDetailsService} bean is picked up automatically by Spring Boot and wired into a
 * {@code DaoAuthenticationProvider}, which compares the submitted password against the stored
 * {@code {bcrypt}} hash using the configured {@code PasswordEncoder}. The provider also honours
 * {@link UserDetails#isAccountNonLocked()} — that is how the brute-force lockout takes effect: a
 * locked account is rejected before the password is even checked.
 *
 * <p>A {@link Clock} is injected so the "is the lock still active?" decision is deterministic in tests.
 */
@Service
public class JpaUserDetailsService implements UserDetailsService {

    private final AppUserRepository users;
    private final Clock clock;

    public JpaUserDetailsService(AppUserRepository users, Clock clock) {
        this.users = users;
        this.clock = clock;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser user = users.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        Instant lockedUntil = user.getLockedUntil();
        boolean locked = lockedUntil != null && Instant.now(clock).isBefore(lockedUntil);

        return User.withUsername(user.getUsername())
                .password(user.getPassword())
                .roles(user.roleArray())
                .accountLocked(locked)
                .build();
    }
}

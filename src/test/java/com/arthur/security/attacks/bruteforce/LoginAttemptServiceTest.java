package com.arthur.security.attacks.bruteforce;

import com.arthur.security.login.LoginAttemptService;
import com.arthur.security.user.AppUser;
import com.arthur.security.user.AppUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit test for the lockout logic: it locks after the threshold and unlocks once the window elapses.
 */
class LoginAttemptServiceTest {

    private static final int MAX_ATTEMPTS = 3;
    private static final long LOCK_MINUTES = 15;

    private MutableClock clock;
    private AppUser user;
    private LoginAttemptService service;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        user = new AppUser("arthur", "{bcrypt}$2a$10$abc", "USER");

        AppUserRepository users = mock(AppUserRepository.class);
        when(users.findByUsername("arthur")).thenReturn(Optional.of(user));
        when(users.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));

        service = new LoginAttemptService(users, clock, MAX_ATTEMPTS, LOCK_MINUTES);
    }

    @Test
    @DisplayName("account locks after the configured number of failed attempts")
    void locksAfterThreshold() {
        assertFalse(service.isLocked("arthur"));

        for (int i = 0; i < MAX_ATTEMPTS; i++) {
            service.loginFailed("arthur");
        }

        assertTrue(service.isLocked("arthur"));
    }

    @Test
    @DisplayName("lock expires once the lockout window has elapsed")
    void unlocksAfterWindow() {
        for (int i = 0; i < MAX_ATTEMPTS; i++) {
            service.loginFailed("arthur");
        }
        assertTrue(service.isLocked("arthur"));

        clock.advance(Duration.ofMinutes(LOCK_MINUTES + 1));

        assertFalse(service.isLocked("arthur"));
    }

    @Test
    @DisplayName("a successful login clears the failure counter and any lock")
    void successResetsState() {
        service.loginFailed("arthur");
        service.loginFailed("arthur");

        service.loginSucceeded("arthur");

        assertFalse(service.isLocked("arthur"));
    }
}

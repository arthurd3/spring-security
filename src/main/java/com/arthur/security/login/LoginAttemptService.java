package com.arthur.security.login;

import com.arthur.security.user.AppUser;
import com.arthur.security.user.AppUserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tracks failed logins per username and locks an account after too many failures.
 *
 * <p>Spring Security ships no built-in lockout, so this is built on its authentication events (see
 * {@link AuthenticationEventListener}). When the failure count reaches the threshold the user's
 * {@code lockedUntil} is set to {@code now + lockDuration}; {@code JpaUserDetailsService} then reports
 * the account as locked and {@code DaoAuthenticationProvider} rejects it before checking the password.
 *
 * <p>A {@link Clock} is injected so lockout expiry can be tested deterministically instead of with
 * {@code Thread.sleep}.
 */
@Service
public class LoginAttemptService {

    private final AppUserRepository users;
    private final Clock clock;
    private final int maxAttempts;
    private final Duration lockDuration;
    private final Map<String, Integer> attempts = new ConcurrentHashMap<>();

    public LoginAttemptService(AppUserRepository users,
                               Clock clock,
                               @Value("${security.lockout.max-attempts:3}") int maxAttempts,
                               @Value("${security.lockout.duration-minutes:15}") long lockDurationMinutes) {
        this.users = users;
        this.clock = clock;
        this.maxAttempts = maxAttempts;
        this.lockDuration = Duration.ofMinutes(lockDurationMinutes);
    }

    public void loginFailed(String username) {
        int count = attempts.merge(username, 1, Integer::sum);
        if (count >= maxAttempts) {
            users.findByUsername(username).ifPresent(user -> {
                user.setLockedUntil(Instant.now(clock).plus(lockDuration));
                users.save(user);
            });
        }
    }

    public void loginSucceeded(String username) {
        attempts.remove(username);
        users.findByUsername(username).ifPresent(user -> {
            if (user.getLockedUntil() != null) {
                user.setLockedUntil(null);
                users.save(user);
            }
        });
    }

    public boolean isLocked(String username) {
        return users.findByUsername(username)
                .map(AppUser::getLockedUntil)
                .map(until -> Instant.now(clock).isBefore(until))
                .orElse(false);
    }

    public int failedAttempts(String username) {
        return attempts.getOrDefault(username, 0);
    }
}

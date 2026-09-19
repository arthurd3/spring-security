package com.arthur.security.ratelimit;

import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A minimal fixed-window rate limiter (OWASP A04:2021, CWE-770 - allocation without limits / throttling).
 *
 * <p>Without a limit, an endpoint like OTP verification or login can be tried millions of times, which
 * is what makes brute force and credential stuffing practical. This limiter allows {@code maxRequests}
 * per key (e.g. per client IP) inside a rolling {@code window}, and rejects the rest.
 *
 * <p>A {@link Clock} is injected so the window logic can be tested without sleeping.
 */
@Component
public class RateLimiter {

    private record Window(Instant start, int count) {}

    private final Map<String, Window> windows = new ConcurrentHashMap<>();
    private final Clock clock;

    public RateLimiter(Clock clock) {
        this.clock = clock;
    }

    /** @return true if the request is allowed, false if it exceeds the limit */
    public boolean tryAcquire(String key, int maxRequests, Duration window) {
        Instant now = Instant.now(clock);
        Window updated = windows.compute(key, (k, current) -> {
            if (current == null || now.isAfter(current.start().plus(window))) {
                return new Window(now, 1);
            }
            return new Window(current.start(), current.count() + 1);
        });
        return updated.count() <= maxRequests;
    }
}

package com.arthur.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Clock;

/**
 * Cross-cutting beans.
 *
 * <p>The {@link PasswordEncoder} is a {@code DelegatingPasswordEncoder}: it encodes new passwords with
 * BCrypt (writing the {@code {bcrypt}} prefix) and can still verify other {@code {id}}-prefixed hashes,
 * which makes password migrations painless. Storing a plaintext password with no prefix would make this
 * encoder throw {@code IllegalArgumentException: There is no PasswordEncoder mapped for the id "null"} —
 * the classic Spring Security 6 beginner error.
 */
@Configuration
public class AppConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /** Injected wherever time-based decisions must be deterministic under test (e.g. lockout expiry). */
    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}

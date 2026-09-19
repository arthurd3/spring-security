package com.arthur.security.insecure;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Security chain for the live attack lab - active ONLY under the {@code insecure} profile.
 *
 * <p>It claims {@code /vulnerable/**} (ordered before the session-based web chain) and deliberately
 * takes every protection off that surface: authentication is not required, CSRF is disabled, and the
 * default security headers are removed. That is the point - each {@code /vulnerable/**} endpoint is
 * meant to be trivially reachable so a script can demonstrate the raw flaw, then contrast it with the
 * hardened {@code /api/**} endpoint that blocks the identical request.
 *
 * <p>The hardened {@code /api/**} chain ({@code ApiSecurityConfig}) and the real web chain still apply
 * to their own paths; this chain only governs the demo surface.
 */
@Configuration
@EnableWebSecurity
@Profile("insecure")
public class InsecureLabSecurityConfig {

    @Bean
    @Order(50)
    public SecurityFilterChain vulnerableLabFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/vulnerable/**")
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .csrf(csrf -> csrf.disable())
                .headers(headers -> headers.disable());
        return http.build();
    }
}

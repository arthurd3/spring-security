package com.arthur.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * Security for everything that is not {@code /api/**}: the session-based, browser-facing surface.
 *
 * <p>This chain deliberately keeps the secure-by-default protections that a stateful app needs and that
 * old tutorials often switch off:
 * <ul>
 *   <li><b>CSRF enabled</b> (the default) — required for cookie/session auth.</li>
 *   <li><b>Session-fixation protection</b> — the default {@code changeSessionId} rotates the session id
 *       at login, defeating fixation. Concurrency is capped at one active session per user.</li>
 *   <li><b>Security headers</b> — HSTS + a strict-ish CSP. {@code frameOptions().sameOrigin()} is set
 *       (instead of the old {@code .disable()}) so the H2 console can render in a dev iframe.</li>
 * </ul>
 * The H2 console is a development convenience for inspecting the {@code {bcrypt}} hashes in the user
 * table; it is not something you would expose in production.
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    @Bean
    @Order(100)
    public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/login", "/error").permitAll()
                        .requestMatchers("/h2-console/**").permitAll()
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults())
                // H2 console posts without a CSRF token; ignore only that dev-only path.
                .csrf(csrf -> csrf.ignoringRequestMatchers(new AntPathRequestMatcher("/h2-console/**")))
                .sessionManagement(session -> session
                        .sessionFixation(fixation -> fixation.changeSessionId())
                        .maximumSessions(1))
                .headers(headers -> headers
                        .frameOptions(frame -> frame.sameOrigin())
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(31_536_000))
                        .contentSecurityPolicy(csp -> csp
                                .policyDirectives("default-src 'self'; script-src 'self'; object-src 'none'")));
        return http.build();
    }

    /** Exposed so the JWT login endpoint can authenticate credentials via the standard provider chain. */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    /** Required for {@code maximumSessions} to observe session lifecycle events. */
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }
}

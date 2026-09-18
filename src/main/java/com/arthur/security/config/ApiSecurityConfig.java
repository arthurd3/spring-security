package com.arthur.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Security for the stateless REST API ({@code /api/**}).
 *
 * <p>Ordered first so its {@code securityMatcher} claims the API paths before the session-based
 * {@link WebSecurityConfig} default chain. Highlights of the hardened configuration:
 * <ul>
 *   <li><b>Stateless</b> — no HTTP session is created; every request must carry its own credential.</li>
 *   <li><b>Bearer JWT + HTTP Basic</b> — the resource server validates JWTs (signature + expiry);
 *       Basic is enabled too so the endpoints are easy to try with {@code curl -u}.</li>
 *   <li><b>CSRF disabled</b> — correct <i>only</i> because auth travels in the {@code Authorization}
 *       header, which browsers never attach automatically. Never disable CSRF for cookie/session apps.</li>
 *   <li><b>Explicit CORS</b> and <b>security headers</b> (HSTS, CSP, nosniff, frame DENY).</li>
 * </ul>
 */
@Configuration
@EnableWebSecurity
public class ApiSecurityConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http,
                                                      JwtAuthenticationConverter jwtAuthConverter) throws Exception {
        http
                .securityMatcher("/api/**")
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/api/auth/login").permitAll()
                        .requestMatchers("/api/v1/welcome").permitAll()
                        .requestMatchers("/api/v1/user").hasRole("USER")
                        .requestMatchers("/api/v1/admin", "/api/admin/**").hasRole("ADMIN")
                        .requestMatchers("/api/accounts/**").authenticated()
                        .anyRequest().authenticated())
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthConverter)))
                .headers(headers -> headers
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(31_536_000))
                        .contentSecurityPolicy(csp -> csp
                                .policyDirectives("default-src 'none'; frame-ancestors 'none'")));
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("http://localhost:3000"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);
        return source;
    }
}

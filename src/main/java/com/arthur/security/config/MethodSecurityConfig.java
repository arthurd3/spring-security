package com.arthur.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/**
 * Enables method-level authorization annotations ({@code @PreAuthorize}, {@code @PostAuthorize}, ...).
 *
 * <p>{@code @EnableMethodSecurity} turns on the pre/post annotations by default (unlike the deprecated
 * {@code @EnableGlobalMethodSecurity}, which required {@code prePostEnabled = true}). This is what makes
 * the object-level ownership check in {@code AccountService} — the real fix for IDOR — take effect.
 */
@Configuration
@EnableMethodSecurity
public class MethodSecurityConfig {
}

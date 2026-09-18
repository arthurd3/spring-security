package com.arthur.security.attacks;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Base class for defense tests that exercise the real, hardened application.
 *
 * <p>{@code @SpringBootTest} boots the full context (both filter chains, JPA, seeded users/accounts) and
 * {@code @AutoConfigureMockMvc} applies Spring Security's filter chain to {@link MockMvc} automatically.
 * All subclasses share the same context, so it is built once and cached.
 */
@SpringBootTest
@AutoConfigureMockMvc
public abstract class AbstractSecurityIntegrationTest {

    @Autowired
    protected MockMvc mvc;
}

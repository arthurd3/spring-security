package com.arthur.security.attacks.csrf;

import com.arthur.security.attacks.AbstractSecurityIntegrationTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The session-based chain requires a valid CSRF token on unsafe methods, while the stateless bearer-token
 * API is correctly exempt (a browser never auto-attaches the {@code Authorization} header).
 */
class CsrfDefenseTest extends AbstractSecurityIntegrationTest {

    @Test
    @DisplayName("DEFENSE: session-based POST without a CSRF token is rejected")
    void loginWithoutTokenIsForbidden() throws Exception {
        mvc.perform(post("/login")
                        .param("username", "arthur")
                        .param("password", "password"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("DEFENSE: session-based POST with a valid CSRF token is processed")
    void loginWithValidTokenIsAccepted() throws Exception {
        mvc.perform(post("/login")
                        .param("username", "arthur")
                        .param("password", "password")
                        .with(csrf()))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    @DisplayName("DEFENSE: a tampered CSRF token is rejected")
    void loginWithInvalidTokenIsForbidden() throws Exception {
        mvc.perform(post("/login")
                        .param("username", "arthur")
                        .param("password", "password")
                        .with(csrf().useInvalidToken()))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("DEFENSE: the stateless API is correctly exempt from CSRF (bearer tokens, not cookies)")
    void statelessApiDoesNotRequireCsrfToken() throws Exception {
        mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"arthur\",\"password\":\"password\"}"))
                .andExpect(status().isOk());
    }
}

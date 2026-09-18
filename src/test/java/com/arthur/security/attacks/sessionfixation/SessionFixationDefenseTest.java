package com.arthur.security.attacks.sessionfixation;

import com.arthur.security.attacks.AbstractSecurityIntegrationTest;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * End-to-end proof that the real app rotates the session id on successful login, defeating fixation.
 */
class SessionFixationDefenseTest extends AbstractSecurityIntegrationTest {

    @Test
    @DisplayName("DEFENSE: the pre-login session id is replaced after authentication")
    void sessionIdChangesAfterLogin() throws Exception {
        MockHttpSession preLogin = new MockHttpSession();
        String before = preLogin.getId();

        MvcResult result = mvc.perform(post("/login")
                        .param("username", "arthur")
                        .param("password", "password")
                        .session(preLogin)
                        .with(csrf()))
                .andExpect(authenticated())
                .andReturn();

        HttpSession after = result.getRequest().getSession(false);
        assertNotNull(after);
        assertNotEquals(before, after.getId());
    }
}

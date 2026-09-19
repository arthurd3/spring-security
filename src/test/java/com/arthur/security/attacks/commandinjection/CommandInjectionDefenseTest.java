package com.arthur.security.attacks.commandinjection;

import com.arthur.security.attacks.AbstractSecurityIntegrationTest;
import com.arthur.security.attacks.report.SecurityReport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The hardened {@code /api/system/ping} validates the host against a strict allowlist, so a
 * metacharacter-bearing value is refused before any command could be built.
 */
class CommandInjectionDefenseTest extends AbstractSecurityIntegrationTest {

    private static final String CATEGORY = "Command Injection";

    @Test
    @DisplayName("DEFENSE: a host containing shell metacharacters is rejected")
    void metacharactersAreRejected() throws Exception {
        mvc.perform(get("/api/system/ping").param("host", "localhost; echo PWNED")
                        .with(httpBasic("arthur", "password")))
                .andExpect(status().isBadRequest());

        SecurityReport.defended(CATEGORY, "GET /api/system/ping?host=localhost; echo PWNED",
                "400 - allowlist recusa o ';' antes de montar qualquer comando");
    }

    @Test
    @DisplayName("DEFENSE: a plain host name is accepted")
    void plainHostIsAccepted() throws Exception {
        mvc.perform(get("/api/system/ping").param("host", "example.com")
                        .with(httpBasic("arthur", "password")))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("example.com")));

        SecurityReport.defended(CATEGORY, "GET /api/system/ping?host=example.com (uso legitimo)",
                "200 - host valido continua funcionando");
    }

    @Test
    @DisplayName("DEFENSE: /api/system/ping requires authentication")
    void endpointRequiresAuthentication() throws Exception {
        mvc.perform(get("/api/system/ping").param("host", "example.com"))
                .andExpect(status().isUnauthorized());

        SecurityReport.defended(CATEGORY, "GET /api/system/ping sem credenciais",
                "401 - endpoint exige autenticacao");
    }
}

package com.arthur.security.attacks.xpath;

import com.arthur.security.attacks.AbstractSecurityIntegrationTest;
import com.arthur.security.attacks.report.SecurityReport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Bound XPath variables make the payload inert while real credentials still authenticate. */
class XpathInjectionDefenseTest extends AbstractSecurityIntegrationTest {

    private static final String CATEGORY = "XPath Injection";

    @Test
    @DisplayName("DEFENSE: the tautology payload is denied")
    void tautologyIsDenied() throws Exception {
        mvc.perform(get("/api/xlogin").param("user", "arthur").param("pass", "' or '1'='1"))
                .andExpect(status().isOk())
                .andExpect(content().string("denied"));

        SecurityReport.defended(CATEGORY, "GET /api/xlogin?pass=' or '1'='1",
                "denied - variavel vinculada, aspas tratadas como dado");
    }

    @Test
    @DisplayName("DEFENSE: correct credentials still authenticate")
    void realCredentialsWork() throws Exception {
        mvc.perform(get("/api/xlogin").param("user", "arthur").param("pass", "password"))
                .andExpect(status().isOk())
                .andExpect(content().string("authenticated"));

        SecurityReport.defended(CATEGORY, "GET /api/xlogin (credenciais corretas)",
                "authenticated - login legitimo continua funcionando");
    }
}

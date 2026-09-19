package com.arthur.security.attacks.spel;

import com.arthur.security.attacks.AbstractSecurityIntegrationTest;
import com.arthur.security.attacks.report.SecurityReport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** The hardened endpoint treats the name as text: {@code 7*7} comes back literally, never evaluated. */
class SpelInjectionDefenseTest extends AbstractSecurityIntegrationTest {

    private static final String CATEGORY = "SpEL / SSTI";

    @Test
    @DisplayName("DEFENSE: the name is echoed as text, not evaluated")
    void inputIsNotEvaluated() throws Exception {
        mvc.perform(get("/api/greet").param("name", "7*7"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("7*7")))
                .andExpect(content().string(not(containsString("49"))));

        SecurityReport.defended(CATEGORY, "GET /api/greet?name=7*7",
                "resposta contem 7*7 literal - nada e avaliado");
    }

    @Test
    @DisplayName("DEFENSE: a type-access payload is not evaluated either")
    void typeAccessIsNotEvaluated() throws Exception {
        mvc.perform(get("/api/greet").param("name", "T(java.lang.System)"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("T(java.lang.System)")));

        SecurityReport.defended(CATEGORY, "GET /api/greet?name=T(java.lang.System)...",
                "devolvido como texto - sem acesso a tipos/Runtime");
    }
}

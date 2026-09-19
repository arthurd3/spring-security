package com.arthur.security.attacks.redos;

import com.arthur.security.attacks.AbstractSecurityIntegrationTest;
import com.arthur.security.attacks.report.SecurityReport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** The hardened validator is linear and length-capped, so the same input returns instantly. */
class ReDoSDefenseTest extends AbstractSecurityIntegrationTest {

    private static final String CATEGORY = "ReDoS";

    @Test
    @DisplayName("DEFENSE: the crafted input returns immediately with a linear check")
    void linearCheckReturnsFast() throws Exception {
        String input = "a".repeat(40) + "!";

        long start = System.nanoTime();
        mvc.perform(get("/api/validate").param("input", input))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("match=false")));
        long ms = (System.nanoTime() - start) / 1_000_000;

        SecurityReport.defended(CATEGORY, "GET /api/validate?input=aaaa...a! (verificacao linear)",
                "match=false em ~" + ms + "ms - sem backtracking");
    }

    @Test
    @DisplayName("DEFENSE: over-long input is rejected outright")
    void overLongInputRejected() throws Exception {
        mvc.perform(get("/api/validate").param("input", "a".repeat(5000)))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("rejeitado")));

        SecurityReport.defended(CATEGORY, "GET /api/validate com 5000 caracteres",
                "rejeitado pelo limite de tamanho antes de qualquer regex");
    }
}

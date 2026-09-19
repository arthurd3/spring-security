package com.arthur.security.attacks.loginjection;

import com.arthur.security.attacks.AbstractSecurityIntegrationTest;
import com.arthur.security.attacks.report.SecurityReport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/** The hardened endpoint strips CR/LF, so the value stays on one line. */
class LogInjectionDefenseTest extends AbstractSecurityIntegrationTest {

    private static final String CATEGORY = "Log Injection (CRLF)";

    @Test
    @DisplayName("DEFENSE: newlines in the input are neutralised before logging")
    void newlinesAreStripped() throws Exception {
        String payload = "mallory\nINFO login attempt for user=admin SUCCESS";

        MvcResult result = mvc.perform(get("/api/log").param("user", payload)
                        .with(httpBasic("arthur", "password"))).andReturn();
        String logged = result.getResponse().getContentAsString();

        assertThat(logged).doesNotContain("\n").doesNotContain("\r");

        SecurityReport.defended(CATEGORY, "user=mallory\\nINFO ...",
                "CR/LF substituidos por _ - continua uma unica linha de log");
    }
}

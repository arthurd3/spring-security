package com.arthur.security.attacks.hostheader;

import com.arthur.security.attacks.AbstractSecurityIntegrationTest;
import com.arthur.security.attacks.report.SecurityReport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** The hardened endpoint uses a configured base URL and ignores the Host header. */
class HostHeaderInjectionDefenseTest extends AbstractSecurityIntegrationTest {

    private static final String CATEGORY = "Host Header Injection";

    @Test
    @DisplayName("DEFENSE: a forged Host header does not change the link")
    void hostHeaderIsIgnored() throws Exception {
        mvc.perform(get("/api/reset-link").param("user", "alice")
                        .header(HttpHeaders.HOST, "evil.example"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("myapp.example")))
                .andExpect(content().string(not(containsString("evil.example"))));

        SecurityReport.defended(CATEGORY, "Host: evil.example",
                "link usa a base URL configurada (myapp.example), Host ignorado");
    }
}

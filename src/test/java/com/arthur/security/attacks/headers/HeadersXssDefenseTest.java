package com.arthur.security.attacks.headers;

import com.arthur.security.attacks.AbstractSecurityIntegrationTest;
import com.arthur.security.attacks.report.SecurityReport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The hardened app sets protective headers on every response and HTML-escapes reflected input.
 */
class HeadersXssDefenseTest extends AbstractSecurityIntegrationTest {

    @Test
    @DisplayName("DEFENSE: security headers are present")
    void securityHeadersPresent() throws Exception {
        mvc.perform(get("/api/v1/welcome"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Content-Security-Policy", containsString("default-src 'none'")));

        SecurityReport.defended("Headers / XSS", "headers de resposta da API", "nosniff + X-Frame-Options DENY + CSP presentes");
    }

    @Test
    @DisplayName("DEFENSE: reflected input is HTML-escaped, neutralising the XSS payload")
    void reflectedInputIsEscaped() throws Exception {
        mvc.perform(get("/api/v1/echo")
                        .param("message", "<script>alert(1)</script>")
                        .with(httpBasic("arthur", "password")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("&lt;script&gt;")))
                .andExpect(content().string(not(containsString("<script>"))));

        SecurityReport.defended("Headers / XSS", "GET /api/v1/echo?message=<script>alert(1)</script>", "refletido como &lt;script&gt; - markup vira texto inerte");
    }
}

package com.arthur.security.attacks.cors;

import com.arthur.security.attacks.AbstractSecurityIntegrationTest;
import com.arthur.security.attacks.report.SecurityReport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The real API allows exactly one origin ({@code http://localhost:3000}, configured in
 * {@code ApiSecurityConfig}). Anything else gets no {@code Access-Control-Allow-Origin} header at all,
 * so the browser refuses to expose the response to the calling page.
 */
class CorsDefenseTest extends AbstractSecurityIntegrationTest {

    private static final String CATEGORY = "CORS";
    private static final String EVIL = "https://evil.example";
    private static final String TRUSTED = "http://localhost:3000";

    @Test
    @DisplayName("DEFENSE: the configured origin is allowed")
    void trustedOriginIsAllowed() throws Exception {
        mvc.perform(get("/api/v1/welcome").header(HttpHeaders.ORIGIN, TRUSTED))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", TRUSTED));

        SecurityReport.defended(CATEGORY, "Origin: " + TRUSTED + " (origem legitima)",
                "200 com ACAO: " + TRUSTED + " - front-end oficial continua funcionando");
    }

    @Test
    @DisplayName("DEFENSE: an unknown origin gets no CORS header on a simple request")
    void unknownOriginGetsNoCorsHeader() throws Exception {
        MvcResult result = mvc.perform(get("/api/v1/welcome").header(HttpHeaders.ORIGIN, EVIL))
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"))
                .andReturn();

        SecurityReport.defended(CATEGORY, "Origin: " + EVIL,
                result.getResponse().getStatus() + " sem ACAO - navegador bloqueia a leitura");
    }

    @Test
    @DisplayName("DEFENSE: the preflight for an unknown origin is refused")
    void preflightFromUnknownOriginIsRefused() throws Exception {
        MvcResult result = mvc.perform(options("/api/v1/welcome")
                        .header(HttpHeaders.ORIGIN, EVIL)
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET"))
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"))
                .andReturn();

        assertThat(result.getResponse().getStatus()).isNotEqualTo(200);

        SecurityReport.defended(CATEGORY, "OPTIONS preflight de " + EVIL,
                result.getResponse().getStatus() + " - preflight recusado antes da requisicao real");
    }
}

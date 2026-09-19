package com.arthur.security.attacks.ssrf;

import com.arthur.security.attacks.AbstractSecurityIntegrationTest;
import com.arthur.security.attacks.report.SecurityReport;
import com.arthur.security.net.UrlFetchService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Each guard in {@link UrlFetchService} is exercised on its own, including the one that matters most
 * and is most often missing: re-checking the <i>resolved address</i> even for an allowlisted host.
 */
class SsrfDefenseTest extends AbstractSecurityIntegrationTest {

    private static final String CATEGORY = "SSRF";

    @Test
    @DisplayName("DEFENSE: a host that is not on the allowlist is refused")
    void hostNotOnAllowlistIsRefused() throws IOException {
        UrlFetchService service = new UrlFetchService(List.of("api.partner.example"));

        try (InternalService internal = InternalService.start()) {
            assertThatThrownBy(() -> service.validate(internal.url()))
                    .isInstanceOf(ResponseStatusException.class)
                    .hasMessageContaining("allowlist");

            SecurityReport.defended(CATEGORY, "GET " + internal.url(),
                    "400 - host fora da allowlist, servico interno intocado");
        }
    }

    @Test
    @DisplayName("DEFENSE: an allowlisted host that resolves to loopback is still refused")
    void allowlistedHostResolvingInternallyIsRefused() throws IOException {
        // The DNS-rebinding case: the name passes the allowlist, the address check catches it anyway.
        UrlFetchService service = new UrlFetchService(List.of("127.0.0.1"));

        try (InternalService internal = InternalService.start()) {
            assertThatThrownBy(() -> service.validate(internal.url()))
                    .isInstanceOf(ResponseStatusException.class)
                    .hasMessageContaining("internal address");

            SecurityReport.defended(CATEGORY, "host na allowlist resolvendo para 127.0.0.1",
                    "400 - checagem do endereco resolvido barra DNS rebinding");
        }
    }

    @Test
    @DisplayName("DEFENSE: non-HTTP schemes are refused")
    void nonHttpSchemesAreRefused() {
        UrlFetchService service = new UrlFetchService(List.of("example.com"));

        assertThatThrownBy(() -> service.validate("file:///etc/passwd"))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("http");

        SecurityReport.defended(CATEGORY, "file:///etc/passwd",
                "400 - apenas http/https aceitos");
    }

    @Test
    @DisplayName("DEFENSE: /api/fetch is admin-only")
    void endpointIsAdminOnly() throws Exception {
        mvc.perform(get("/api/fetch").param("url", "http://example.com")
                        .with(httpBasic("arthur", "password")))
                .andExpect(status().isForbidden());

        SecurityReport.defended(CATEGORY, "usuario USER chamando /api/fetch",
                "403 - @PreAuthorize(hasRole('ADMIN')) sobre a allowlist");
    }
}

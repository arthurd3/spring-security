package com.arthur.security.attacks.openredirect;

import com.arthur.security.attacks.AbstractSecurityIntegrationTest;
import com.arthur.security.attacks.report.SecurityReport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Exercises the real {@code /api/redirect}, which is deliberately public - an open-redirect demo only
 * makes sense on a path an unauthenticated victim can be lured to.
 */
class OpenRedirectDefenseTest extends AbstractSecurityIntegrationTest {

    private static final String CATEGORY = "Open Redirect";

    @Test
    @DisplayName("DEFENSE: a relative path is still allowed")
    void relativePathIsAllowed() throws Exception {
        mvc.perform(get("/api/redirect").param("to", "/dashboard"))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", "/dashboard"));

        SecurityReport.defended(CATEGORY, "GET /api/redirect?to=/dashboard (uso legitimo)",
                "302 Location: /dashboard - caminho interno continua funcionando");
    }

    @Test
    @DisplayName("DEFENSE: an off-site absolute URL is rejected")
    void offSiteUrlIsRejected() throws Exception {
        mvc.perform(get("/api/redirect").param("to", "https://evil.example/login"))
                .andExpect(status().isBadRequest())
                .andExpect(header().doesNotExist("Location"));

        SecurityReport.defended(CATEGORY, "GET /api/redirect?to=https://evil.example/login",
                "400 - host fora da allowlist, sem header Location");
    }

    @Test
    @DisplayName("DEFENSE: the bypass variants are rejected as well")
    void bypassVariantsAreRejected() throws Exception {
        // Each of these defeats a different naive check: "starts with /", "contains the trusted host",
        // and backslash normalisation in the browser.
        for (String payload : new String[]{
                "//evil.example/login",
                "https://localhost.evil.example/login",
                "/\\evil.example/login",
                "javascript:alert(1)"}) {
            mvc.perform(get("/api/redirect").param("to", payload))
                    .andExpect(status().isBadRequest());
        }

        SecurityReport.defended(CATEGORY, "// | localhost.evil.example | /\\ | javascript:",
                "400 nas 4 variantes de bypass");
    }
}

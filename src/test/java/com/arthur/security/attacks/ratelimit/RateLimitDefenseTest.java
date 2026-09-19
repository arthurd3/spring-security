package com.arthur.security.attacks.ratelimit;

import com.arthur.security.attacks.AbstractSecurityIntegrationTest;
import com.arthur.security.attacks.report.SecurityReport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/** The hardened endpoint throttles after 5 attempts per client, returning 429. */
class RateLimitDefenseTest extends AbstractSecurityIntegrationTest {

    private static final String CATEGORY = "Rate Limiting Ausente";

    @Test
    @DisplayName("DEFENSE: after 5 attempts the 6th is throttled with 429")
    void throttlesAfterLimit() throws Exception {
        int firstThrottledAt = -1;
        for (int i = 1; i <= 6; i++) {
            int status = mvc.perform(get("/api/otp-verify").param("code", "0000"))
                    .andReturn().getResponse().getStatus();
            if (status == 429 && firstThrottledAt < 0) {
                firstThrottledAt = i;
            }
        }

        assertThat(firstThrottledAt).isEqualTo(6);

        SecurityReport.defended(CATEGORY, "6 tentativas de OTP no mesmo cliente",
                "6a retornou 429 - throttling por IP corta a forca bruta");
    }
}

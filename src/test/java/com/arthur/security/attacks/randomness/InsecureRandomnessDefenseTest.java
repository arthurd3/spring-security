package com.arthur.security.attacks.randomness;

import com.arthur.security.attacks.AbstractSecurityIntegrationTest;
import com.arthur.security.attacks.report.SecurityReport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/** SecureRandom ignores the seed and never repeats: 256-bit unpredictable tokens. */
class InsecureRandomnessDefenseTest extends AbstractSecurityIntegrationTest {

    private static final String CATEGORY = "Aleatoriedade Insegura";

    private String token() throws Exception {
        return mvc.perform(get("/api/token").param("seed", "42"))
                .andReturn().getResponse().getContentAsString();
    }

    @Test
    @DisplayName("DEFENSE: even with the same seed, tokens differ and are 256-bit")
    void tokenIsUnpredictable() throws Exception {
        String a = token();
        String b = token();

        assertThat(a).isNotEqualTo(b);
        assertThat(a).hasSize(64); // 32 bytes as hex

        SecurityReport.defended(CATEGORY, "GET /api/token?seed=42 (duas vezes)",
                "tokens diferentes de 256 bits - SecureRandom ignora a semente");
    }
}

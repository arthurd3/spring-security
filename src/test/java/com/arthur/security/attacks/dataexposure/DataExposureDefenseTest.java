package com.arthur.security.attacks.dataexposure;

import com.arthur.security.attacks.AbstractSecurityIntegrationTest;
import com.arthur.security.attacks.report.SecurityReport;
import com.arthur.security.user.AppUser;
import com.arthur.security.user.AppUserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Both layers of the defense are checked: the DTO returned by {@code /api/users/me} (the primary fix)
 * and the {@code @JsonIgnore} on the entity's password (defense in depth, for the day someone returns
 * the entity by mistake).
 */
class DataExposureDefenseTest extends AbstractSecurityIntegrationTest {

    private static final String CATEGORY = "Exposicao de Dados";

    @Autowired
    private AppUserRepository users;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("DEFENSE: /api/users/me returns a DTO with no credential in it")
    void profileEndpointReturnsOnlySafeFields() throws Exception {
        MvcResult result = mvc.perform(get("/api/users/me").with(httpBasic("arthur", "password")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("arthur"))
                .andExpect(jsonPath("$.roles[0]").value("USER"))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.id").doesNotExist())
                .andExpect(jsonPath("$.lockedUntil").doesNotExist())
                .andReturn();

        String body = result.getResponse().getContentAsString();
        assertThat(body).doesNotContain("$2a$").doesNotContain("bcrypt");

        SecurityReport.defended(CATEGORY, "GET /api/users/me (DTO UserProfile)",
                "200 " + body + " - sem hash, sem id interno");
    }

    @Test
    @DisplayName("DEFENSE: even serialising the entity directly omits the password")
    void entitySerialisationOmitsPassword() throws Exception {
        AppUser entity = users.findByUsername("arthur").orElseThrow();
        assertThat(entity.getPassword()).startsWith("{bcrypt}");

        String json = objectMapper.writeValueAsString(entity);

        // @JsonIgnore is the safety net if the entity ever leaks into a response by accident.
        assertThat(json).doesNotContain("$2a$").doesNotContain("password");

        SecurityReport.defended(CATEGORY, "ObjectMapper.writeValueAsString(AppUser)",
                "@JsonIgnore remove o hash mesmo serializando a entidade");
    }

    @Test
    @DisplayName("DEFENSE: an error response carries no stack trace or internal message")
    void errorResponsesDoNotLeakInternals() throws Exception {
        MvcResult result = mvc.perform(get("/api/accounts/999999").with(httpBasic("arthur", "password")))
                .andReturn();

        String body = result.getResponse().getContentAsString();
        assertThat(body).doesNotContain("Exception").doesNotContain("com.arthur.security");

        SecurityReport.defended(CATEGORY, "GET /api/accounts/999999 (id inexistente)",
                result.getResponse().getStatus() + " sem stack trace (include-stacktrace=never)");
    }
}

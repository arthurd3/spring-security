package com.arthur.security.attacks.massassignment;

import com.arthur.security.attacks.AbstractSecurityIntegrationTest;
import com.arthur.security.attacks.report.SecurityReport;
import com.arthur.security.user.AppUser;
import com.arthur.security.user.AppUserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The real {@code /api/auth/register} binds to a record with only {@code username} and {@code password},
 * so the injected {@code roles} field has nowhere to land and the server assigns the role itself.
 */
class MassAssignmentDefenseTest extends AbstractSecurityIntegrationTest {

    private static final String CATEGORY = "Mass Assignment";

    @Autowired
    private AppUserRepository users;

    @AfterEach
    void removeTestUser() {
        users.findByUsername("mallory").ifPresent(users::delete);
    }

    @Test
    @DisplayName("DEFENSE: the injected roles field is ignored and USER is assigned by the server")
    void injectedRoleIsIgnored() throws Exception {
        String payload = """
                {"username":"mallory","password":"hunter2-long","roles":"ADMIN"}""";

        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value("mallory"))
                .andExpect(jsonPath("$.roles[0]").value("USER"))
                .andExpect(jsonPath("$.password").doesNotExist());

        // The stored row is the real proof - the response could have been filtered on its own.
        AppUser stored = users.findByUsername("mallory").orElseThrow();
        assertThat(stored.getRoles()).isEqualTo("USER");
        assertThat(stored.getPassword()).startsWith("{bcrypt}");

        SecurityReport.defended(CATEGORY, "POST body com \"roles\":\"ADMIN\"",
                "gravado roles=" + stored.getRoles() + " - campo extra descartado no bind");
    }

    @Test
    @DisplayName("DEFENSE: the new account cannot reach admin-only endpoints")
    void registeredUserCannotReachAdminEndpoints() throws Exception {
        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"mallory","password":"hunter2-long","roles":"ADMIN"}"""))
                .andExpect(status().isCreated());

        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .get("/api/v1/admin")
                        .with(org.springframework.security.test.web.servlet.request
                                .SecurityMockMvcRequestPostProcessors.httpBasic("mallory", "hunter2-long")))
                .andExpect(status().isForbidden());

        SecurityReport.defended(CATEGORY, "conta auto-registrada acessando /api/v1/admin",
                "403 - o papel veio do servidor, nao do corpo da requisicao");
    }
}

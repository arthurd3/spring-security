package com.arthur.security.attacks.sqli;

import com.arthur.security.attacks.AbstractSecurityIntegrationTest;
import com.arthur.security.attacks.report.SecurityReport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MvcResult;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Two levels of proof that the same payloads are inert against the hardened code: directly against a
 * {@link SafeAccountDao} using bind parameters, and end-to-end against the real
 * {@code GET /api/accounts/search} endpoint, which is backed by a Spring Data derived query.
 */
class SqlInjectionDefenseTest extends AbstractSecurityIntegrationTest {

    private static final String CATEGORY = "SQL Injection";

    private Connection connection;
    private SafeAccountDao dao;

    @BeforeEach
    void setUp() throws SQLException {
        connection = DemoAccountsDb.open("sqli_defense");
        dao = new SafeAccountDao(connection);
    }

    @AfterEach
    void tearDown() throws SQLException {
        connection.close();
    }

    @Test
    @DisplayName("DEFENSE: bind parameters make the tautology payload match nothing")
    void preparedStatementNeutralisesTautology() throws SQLException {
        String payload = "alice' OR '1'='1";

        List<String> found = dao.findByOwner(payload);

        // The payload is compared as a literal username, which simply does not exist.
        assertThat(found).isEmpty();
        assertThat(dao.findByOwner("alice")).containsExactly("alice");

        SecurityReport.defended(CATEGORY, payload,
                "0 resultados - valor tratado como dado, nao como SQL");
    }

    @Test
    @DisplayName("DEFENSE: bind parameters keep the password check intact")
    void preparedStatementKeepsAuthenticationIntact() throws SQLException {
        String payload = "alice' --";

        assertThat(dao.authenticate(payload, "wrong-password")).isFalse();
        assertThat(dao.authenticate("alice", "alice-secret")).isTrue();

        SecurityReport.defended(CATEGORY, payload + "  (senha: wrong-password)",
                "login recusado; credencial correta continua funcionando");
    }

    @Test
    @DisplayName("DEFENSE: /api/accounts/search is immune to the same payload")
    void searchEndpointIsParameterised() throws Exception {
        String payload = "arthur' OR '1'='1";

        MvcResult result = mvc.perform(get("/api/accounts/search")
                        .param("owner", payload)
                        .with(httpBasic("admin", "password")))
                .andExpect(status().isOk())
                .andExpect(content().json("[]"))
                .andReturn();

        // Sanity check that the endpoint does return data for a genuine owner.
        mvc.perform(get("/api/accounts/search").param("owner", "arthur")
                        .with(httpBasic("admin", "password")))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("arthur")));

        SecurityReport.defended(CATEGORY, "GET /api/accounts/search?owner=" + payload,
                "200 " + result.getResponse().getContentAsString() + " - nenhuma conta vazada");
    }

    @Test
    @DisplayName("DEFENSE: the search endpoint is admin-only")
    void searchEndpointRequiresAdmin() throws Exception {
        mvc.perform(get("/api/accounts/search").param("owner", "arthur")
                        .with(httpBasic("arthur", "password")))
                .andExpect(status().isForbidden());

        SecurityReport.defended(CATEGORY, "usuario USER chamando /api/accounts/search",
                "403 - @PreAuthorize(hasRole('ADMIN'))");
    }
}

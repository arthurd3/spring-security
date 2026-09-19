package com.arthur.security.attacks.accesscontrol;

import com.arthur.security.attacks.report.SecurityReport;
import com.arthur.security.account.Account;
import com.arthur.security.account.AccountRepository;
import com.arthur.security.attacks.AbstractSecurityIntegrationTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Proves the hardened app blocks both flavours of broken access control:
 * object-level (IDOR, via {@code @PostAuthorize} ownership) and function-level (role-gated URLs).
 */
class AccessControlDefenseTest extends AbstractSecurityIntegrationTest {

    @Autowired
    private AccountRepository accounts;

    private Long accountIdOf(String owner) {
        return accounts.findAll().stream()
                .filter(a -> a.getOwner().equals(owner))
                .map(Account::getId)
                .findFirst()
                .orElseThrow();
    }

    @Test
    @DisplayName("DEFENSE: owner can read their own account")
    void ownerCanReadOwnAccount() throws Exception {
        mvc.perform(get("/api/accounts/" + accountIdOf("arthur")).with(httpBasic("arthur", "password")))
                .andExpect(status().isOk());

        SecurityReport.defended("Access Control", "arthur lendo a propria conta (uso legitimo)", "200 - dono continua com acesso");
    }

    @Test
    @DisplayName("DEFENSE: IDOR blocked — a user cannot read another user's account")
    void otherUsersAccountIsForbidden() throws Exception {
        mvc.perform(get("/api/accounts/" + accountIdOf("admin")).with(httpBasic("arthur", "password")))
                .andExpect(status().isForbidden());

        SecurityReport.defended("Access Control", "arthur lendo a conta de admin (IDOR)", "403 - @PostAuthorize confere o dono");
    }

    @Test
    @DisplayName("DEFENSE: admin may read any account")
    void adminCanReadAnyAccount() throws Exception {
        mvc.perform(get("/api/accounts/" + accountIdOf("arthur")).with(httpBasic("admin", "password")))
                .andExpect(status().isOk());

        SecurityReport.defended("Access Control", "admin lendo a conta de arthur", "200 - hasRole('ADMIN') no @PostAuthorize");
    }

    @Test
    @DisplayName("DEFENSE: vertical escalation blocked on admin endpoint")
    void verticalEscalationIsBlocked() throws Exception {
        mvc.perform(get("/api/v1/admin"))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/admin").with(httpBasic("arthur", "password")))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/v1/admin").with(httpBasic("admin", "password")))
                .andExpect(status().isOk());

        SecurityReport.defended("Access Control", "USER e anonimo em /api/v1/admin", "401 anonimo / 403 USER / 200 ADMIN");
    }
}

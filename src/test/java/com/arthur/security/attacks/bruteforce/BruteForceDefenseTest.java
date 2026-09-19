package com.arthur.security.attacks.bruteforce;

import com.arthur.security.attacks.AbstractSecurityIntegrationTest;
import com.arthur.security.attacks.report.SecurityReport;
import com.arthur.security.login.LoginAttemptService;
import com.arthur.security.user.AppUserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;

/**
 * Proves the lockout blocks a brute-force run end-to-end: after the threshold of failures, even the
 * correct password is rejected. Each test unlocks {@code arthur} afterward so the shared context stays
 * clean for other tests.
 */
class BruteForceDefenseTest extends AbstractSecurityIntegrationTest {

    @Autowired
    private AppUserRepository users;

    @Autowired
    private LoginAttemptService loginAttemptService;

    @AfterEach
    void unlockArthur() {
        users.findByUsername("arthur").ifPresent(user -> {
            user.setLockedUntil(null);
            users.save(user);
        });
        loginAttemptService.loginSucceeded("arthur");
    }

    @Test
    @DisplayName("DEFENSE: account locks after repeated failures — the correct password then fails too")
    void accountLocksAfterRepeatedFailures() throws Exception {
        for (int i = 0; i < 3; i++) {
            mvc.perform(formLogin().user("arthur").password("wrong"))
                    .andExpect(unauthenticated());
        }

        mvc.perform(formLogin().user("arthur").password("password"))
                .andExpect(unauthenticated());

        SecurityReport.defended("Brute Force", "3 senhas erradas e depois a correta", "conta travada - nem a senha certa autentica");
    }
}

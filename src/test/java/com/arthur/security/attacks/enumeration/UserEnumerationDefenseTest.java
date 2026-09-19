package com.arthur.security.attacks.enumeration;

import com.arthur.security.attacks.AbstractSecurityIntegrationTest;
import com.arthur.security.attacks.report.SecurityReport;
import com.arthur.security.login.LoginAttemptService;
import com.arthur.security.user.AppUserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * The real {@code /api/auth/login} answers identically whether the account exists or not.
 *
 * <p>Spring Security does most of the work: {@code DaoAuthenticationProvider} defaults to
 * {@code hideUserNotFoundExceptions = true}, converting {@code UsernameNotFoundException} into the
 * same {@code BadCredentialsException} a wrong password produces. It also runs the password encoder
 * against a dummy hash for unknown users, so the two paths take comparable time and the discrepancy
 * does not simply move from the status code to the clock.
 *
 * <p>{@code server.error.include-message=never} keeps the body free of any distinguishing detail.
 */
class UserEnumerationDefenseTest extends AbstractSecurityIntegrationTest {

    private static final String CATEGORY = "Enumeracao de Usuarios";

    @Autowired
    private AppUserRepository users;

    @Autowired
    private LoginAttemptService loginAttemptService;

    /** The failed attempts below count toward the lockout; reset so other tests see a clean account. */
    @AfterEach
    void unlockArthur() {
        users.findByUsername("arthur").ifPresent(user -> {
            user.setLockedUntil(null);
            users.save(user);
        });
        loginAttemptService.loginSucceeded("arthur");
    }

    private MvcResult login(String username) throws Exception {
        return mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"definitely-wrong\"}"))
                .andReturn();
    }

    @Test
    @DisplayName("DEFENSE: unknown user and wrong password give byte-identical responses")
    void bothFailuresLookIdentical() throws Exception {
        MvcResult existing = login("arthur");
        MvcResult unknown = login("nobody-with-this-name");

        int existingStatus = existing.getResponse().getStatus();
        int unknownStatus = unknown.getResponse().getStatus();
        String existingBody = existing.getResponse().getContentAsString();
        String unknownBody = unknown.getResponse().getContentAsString();

        assertThat(existingStatus)
                .as("an existing account must not be distinguishable by status code")
                .isEqualTo(unknownStatus);
        assertThat(existingBody)
                .as("an existing account must not be distinguishable by response body")
                .isEqualTo(unknownBody);
        assertThat(existingBody).doesNotContain("not found").doesNotContain("nobody-with-this-name");

        SecurityReport.defended(CATEGORY, "senha errada vs. usuario inexistente",
                "ambos " + existingStatus + " com corpo identico - nenhuma conta confirmada");
    }

    @Test
    @DisplayName("DEFENSE: correct credentials still authenticate")
    void validCredentialsStillWork() throws Exception {
        MvcResult result = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"arthur\",\"password\":\"password\"}"))
                .andReturn();

        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        assertThat(result.getResponse().getContentAsString()).contains("token");

        SecurityReport.defended(CATEGORY, "credenciais corretas",
                "200 com token - resposta uniforme nao quebra o login legitimo");
    }
}

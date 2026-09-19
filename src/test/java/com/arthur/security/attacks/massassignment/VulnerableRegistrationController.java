package com.arthur.security.attacks.massassignment;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import com.arthur.security.VulnerableExample;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * A deliberately INSECURE registration endpoint that binds the request body straight onto the
 * persistence model (OWASP A08:2021, CWE-915 - "mass assignment" / "over-posting").
 *
 * <p>The developer's mental model is "the form has a username and a password". Jackson's model is
 * "set every property you find a matching setter for". The attacker simply adds a field the form never
 * showed - {@code roles} - and the binder obligingly writes it, so the account is created as an admin.
 *
 * <p>Lives under {@code src/test} and is never component-scanned into the running application. The
 * safe counterpart is {@code RegistrationController}, which binds to a two-component record.
 */
@VulnerableExample
@Controller
public class VulnerableRegistrationController {

    @PostMapping("/vulnerable/register")
    @ResponseBody
    public NewUser register(@RequestBody NewUser submitted) {
        // BUG: whatever the client sent is what gets persisted - roles included.
        return submitted;
    }

    /** Stands in for the JPA entity a careless codebase would bind and save directly. */
    @Getter
    @Setter
    @NoArgsConstructor
    public static class NewUser {
        private String username;
        private String password;
        private String roles = "USER";
    }
}

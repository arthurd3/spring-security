package com.arthur.security.attacks.enumeration;

import com.arthur.security.VulnerableExample;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Map;

/**
 * A deliberately INSECURE login that reports <i>why</i> authentication failed (CWE-204, observable
 * response discrepancy - "username enumeration").
 *
 * <p>The messages look helpful and are exactly what a UX review asks for. They also turn the login
 * form into a free membership oracle: an attacker replays a breached email list and keeps the ones
 * that come back "user not found" versus "wrong password". The resulting list of confirmed accounts
 * is what makes credential stuffing and targeted phishing efficient.
 *
 * <p>The status code leaks the same thing even if the body is generic, which is why the real endpoint
 * has to return one identical response for both cases.
 */
@VulnerableExample
@Controller
public class VulnerableLoginController {

    private static final Map<String, String> USERS = Map.of("arthur", "password");

    @PostMapping("/vulnerable/login")
    @ResponseBody
    public ResponseEntity<String> login(@RequestParam String username, @RequestParam String password) {
        // BUG: the two failure modes are distinguishable, by both status and message.
        if (!USERS.containsKey(username)) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("No account with that username");
        }
        if (!USERS.get(username).equals(password)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Wrong password");
        }
        return ResponseEntity.ok("Welcome");
    }
}

package com.arthur.security.insecure;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Deliberately INSECURE auth endpoints, one per flaw. Hardened counterparts live under {@code /api/**}.
 * <ul>
 *   <li>{@code /vulnerable/login-enum} - distinguishable failures (CWE-204, user enumeration)</li>
 *   <li>{@code /vulnerable/login-nolimit} - unlimited attempts, no lockout (CWE-307, brute force)</li>
 *   <li>{@code /vulnerable/register-role} - binds a client-supplied role (CWE-915, mass assignment)</li>
 *   <li>{@code /vulnerable/register} + {@code /vulnerable/users} - plaintext passwords (CWE-256)</li>
 *   <li>{@code /vulnerable/jwt/whoami} - trusts a JWT without verifying its signature (CWE-347)</li>
 * </ul>
 */
@RestController
@Profile("insecure")
public class VulnerableAuthController {

    private static final Map<String, String> USERS = Map.of("arthur", "password");
    private final Map<String, String> plaintextStore = new ConcurrentHashMap<>();
    private final ObjectMapper mapper = new ObjectMapper();

    @GetMapping("/vulnerable/login-enum")
    public ResponseEntity<String> loginEnum(@RequestParam String user, @RequestParam String pass) {
        if (!USERS.containsKey(user)) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("No account with that username");
        }
        if (!USERS.get(user).equals(pass)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Wrong password");
        }
        return ResponseEntity.ok("Welcome");
    }

    @GetMapping("/vulnerable/login-nolimit")
    public ResponseEntity<String> loginNoLimit(@RequestParam String user, @RequestParam String pass) {
        // BUG: no attempt counter, no lockout - guess forever.
        boolean ok = USERS.getOrDefault(user, "\0").equals(pass);
        return ResponseEntity.status(ok ? HttpStatus.OK : HttpStatus.UNAUTHORIZED)
                .body(ok ? "Welcome" : "invalid credentials");
    }

    @PostMapping("/vulnerable/register-role")
    public Map<String, String> registerWithRole(@RequestParam String username,
                                                 @RequestParam(defaultValue = "USER") String roles) {
        // BUG: the client decides its own role.
        Map<String, String> out = new LinkedHashMap<>();
        out.put("username", username);
        out.put("roles", roles);
        return out;
    }

    @PostMapping("/vulnerable/register")
    public String register(@RequestParam String username, @RequestParam String password) {
        // BUG: password stored in clear text.
        plaintextStore.put(username, password);
        return "registered " + username;
    }

    @GetMapping("/vulnerable/users")
    public Map<String, String> users() {
        // BUG: dumps stored plaintext passwords.
        return plaintextStore;
    }

    @GetMapping("/vulnerable/jwt/whoami")
    public String whoami(@RequestParam String token) throws Exception {
        // BUG: decodes the payload and trusts it WITHOUT verifying the signature.
        String[] parts = token.split("\\.");
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
        Map<?, ?> claims = mapper.readValue(payloadJson, Map.class);
        return "sub=" + claims.get("sub") + " roles=" + claims.get("roles") + " (assinatura NAO verificada)";
    }
}

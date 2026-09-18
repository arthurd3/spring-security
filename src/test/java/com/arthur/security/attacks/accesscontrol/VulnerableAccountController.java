package com.arthur.security.attacks.accesscontrol;

import java.security.Principal;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * A deliberately INSECURE controller used only in tests to demonstrate IDOR.
 *
 * <p>It fetches the object purely by the client-supplied id and never checks that the caller owns it —
 * the essence of Insecure Direct Object Reference (OWASP A01:2021, CWE-639). It is a plain class (no
 * {@code @RestController}) so component scanning never wires it into the real application; tests drive
 * it with {@code MockMvcBuilders.standaloneSetup(...)}.
 *
 * <p>It is annotated {@code @Controller} (with {@code @ResponseBody} on the method) so standalone
 * MockMvc recognises it. Living under {@code src/test}, it never reaches the production classpath, so
 * {@code spring-boot:run} can never expose it.
 */
@Controller
public class VulnerableAccountController {

    private final Map<Long, String> owners = new ConcurrentHashMap<>();

    public VulnerableAccountController() {
        owners.put(1L, "alice");
        owners.put(2L, "bob");
    }

    @GetMapping("/vulnerable/accounts/{id}")
    @ResponseBody
    public String getAccount(@PathVariable Long id, Principal principal) {
        // BUG: returns the record regardless of who is asking.
        return "account " + id + " owned by " + owners.get(id);
    }
}

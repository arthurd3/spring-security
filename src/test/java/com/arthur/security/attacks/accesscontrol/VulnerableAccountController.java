package com.arthur.security.attacks.accesscontrol;

import java.security.Principal;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.arthur.security.VulnerableExample;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * A deliberately INSECURE controller used only in tests to demonstrate IDOR.
 *
 * <p>It fetches the object purely by the client-supplied id and never checks that the caller owns it —
 * the essence of Insecure Direct Object Reference (OWASP A01:2021, CWE-639). Tests drive it with
 * {@code MockMvcBuilders.standaloneSetup(...)}. *
 * <p>Isolation: the class is annotated {@code @Controller} because
 * {@code MockMvcBuilders.standaloneSetup(...)} only registers handler methods on a class it recognises
 * as a controller. That also makes it a component-scan candidate - it sits under the scanned
 * {@code com.arthur.security} package, and {@code src/test} is on the classpath while tests run - so
 * {@code @VulnerableExample} is what actually keeps it out of the application context (see the exclude
 * filter in {@code SecurityApplication}, enforced by {@code VulnerableCodeIsolationTest}). It never
 * ships either way: {@code src/test} is absent from the packaged jar.
 */
@VulnerableExample
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

package com.arthur.security.attacks.csrf;

import com.arthur.security.VulnerableExample;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * A state-changing endpoint used only in tests. Driven via standalone MockMvc (no CSRF filter), it
 * models the "{@code csrf().disable()} on a cookie/session app" misconfiguration: a forged cross-site
 * POST — one that carries no CSRF token — is accepted.
 *
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
public class VulnerableTransferController {

    @PostMapping("/vulnerable/transfer")
    @ResponseBody
    public String transfer(@RequestParam String to, @RequestParam String amount) {
        return "transferred " + amount + " to " + to;
    }
}

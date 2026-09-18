package com.arthur.security.attacks.csrf;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * A state-changing endpoint used only in tests. Driven via standalone MockMvc (no CSRF filter), it
 * models the "{@code csrf().disable()} on a cookie/session app" misconfiguration: a forged cross-site
 * POST — one that carries no CSRF token — is accepted.
 */
@Controller
public class VulnerableTransferController {

    @PostMapping("/vulnerable/transfer")
    @ResponseBody
    public String transfer(@RequestParam String to, @RequestParam String amount) {
        return "transferred " + amount + " to " + to;
    }
}

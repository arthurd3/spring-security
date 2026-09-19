package com.arthur.security.attacks.cors;

import com.arthur.security.VulnerableExample;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * A deliberately INSECURE CORS policy: reflect whatever {@code Origin} asks, and allow credentials
 * (OWASP A05:2021, security misconfiguration).
 *
 * <p>The same-origin policy normally stops {@code https://evil.example} from <i>reading</i> a response
 * from your site. {@code originPatterns = "*"} makes the server echo the attacker's origin back in
 * {@code Access-Control-Allow-Origin}, and {@code allowCredentials = "true"} tells the browser to send
 * the victim's session cookie along. Together they hand the attacker's page full authenticated read
 * access to this endpoint.
 *
 * <p>Note the wildcard has to be spelled {@code originPatterns} rather than {@code origins}: Spring
 * rejects the literal {@code "*"} combined with credentials outright, which is a guard-rail a
 * developer "fixes" by reaching for patterns - arriving at something strictly worse.
 */
@VulnerableExample
@Controller
public class VulnerableCorsController {

    // BUG: any origin, plus credentials. The browser will let evil.example read this response.
    @CrossOrigin(originPatterns = "*", allowCredentials = "true")
    @GetMapping("/vulnerable/cors/balance")
    @ResponseBody
    public String balance() {
        return "{\"balance\":1500.00}";
    }
}

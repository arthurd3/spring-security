package com.arthur.security.attacks.openredirect;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import com.arthur.security.VulnerableExample;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * A deliberately INSECURE "return to where you came from" redirect (CWE-601, open redirect).
 *
 * <p>The {@code url} parameter is echoed straight into the {@code Location} header. The victim sees a
 * link on a domain they trust, clicks it, and lands on the attacker's page - which is why open
 * redirects are prized for phishing and for smuggling OAuth codes out of an application.
 *
 * <p>Lives under {@code src/test} and is never component-scanned into the running application. The
 * safe counterpart is {@code SafeRedirectController}, which allowlists the destination.
 */
@VulnerableExample
@Controller
public class VulnerableRedirectController {

    @GetMapping("/vulnerable/redirect")
    @ResponseBody
    public ResponseEntity<Void> redirect(@RequestParam("url") String url) {
        // BUG: any absolute URL the caller supplies becomes the Location header.
        return ResponseEntity.status(HttpStatus.FOUND).header("Location", url).build();
    }
}

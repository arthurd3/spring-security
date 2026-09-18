package com.arthur.security.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

/**
 * Role-gated demo endpoints plus a safe "echo" showing output encoding.
 *
 * <p>Access to these paths is enforced by URL rules in {@code ApiSecurityConfig}. The {@code /echo}
 * endpoint reflects user input but escapes it with {@link HtmlUtils#htmlEscape(String)} — the primary
 * XSS defense (output encoding) — so a {@code <script>} payload comes back inert.
 */
@RestController
@RequestMapping("/api/v1")
public class MainController {

    @GetMapping("/welcome")
    public String welcome() {
        return "Welcome! This endpoint is public.";
    }

    @GetMapping("/user")
    public String user() {
        return "Hello USER — you are authenticated with the USER role.";
    }

    @GetMapping("/admin")
    public String admin() {
        return "Hello ADMIN — you are authenticated with the ADMIN role.";
    }

    /** Reflects the query but HTML-escapes it first, so injected markup is rendered as text. */
    @GetMapping("/echo")
    public String echo(@RequestParam(defaultValue = "") String message) {
        return "You said: " + HtmlUtils.htmlEscape(message);
    }
}

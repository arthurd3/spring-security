package com.arthur.security.attacks.headers;

import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * INSECURE (test-only): reflects raw user input into an HTML response with no output encoding — a
 * reflected-XSS sink (OWASP A03:2021, CWE-79). Driven by standalone MockMvc, which also has no Spring
 * Security filter, so the response carries none of the protective headers either.
 */
@Controller
public class VulnerableEchoController {

    @GetMapping(value = "/vulnerable/echo", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String echo(@RequestParam String message) {
        return "<div>" + message + "</div>";
    }
}

package com.arthur.security.attacks.headers;

import org.springframework.http.MediaType;
import com.arthur.security.VulnerableExample;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * INSECURE (test-only): reflects raw user input into an HTML response with no output encoding — a
 * reflected-XSS sink (OWASP A03:2021, CWE-79). Driven by standalone MockMvc, which also has no Spring
 * Security filter, so the response carries none of the protective headers either.
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
public class VulnerableEchoController {

    @GetMapping(value = "/vulnerable/echo", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String echo(@RequestParam String message) {
        return "<div>" + message + "</div>";
    }
}

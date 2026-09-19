package com.arthur.security.spel;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

/**
 * Hardened counterpart to {@code /vulnerable/greet} (OWASP A03:2021, CWE-917 - expression-language
 * injection / server-side template injection).
 *
 * <p>The fix is simply to <b>treat the name as data, never as an expression</b>. The vulnerable version
 * feeds user input to {@code SpelExpressionParser.parseExpression(name).getValue()}, so a payload like
 * {@code T(java.lang.Runtime).getRuntime().exec(...)} runs code. Here the name is concatenated as text
 * (and HTML-escaped, so it is also XSS-safe). Nothing is ever evaluated.
 */
@RestController
public class GreetingController {

    @GetMapping("/api/greet")
    public String greet(@RequestParam(defaultValue = "world") String name) {
        return "Hello, " + HtmlUtils.htmlEscape(name) + "!";
    }
}

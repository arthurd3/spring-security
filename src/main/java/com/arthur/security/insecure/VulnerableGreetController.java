package com.arthur.security.insecure;

import org.springframework.context.annotation.Profile;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Deliberately INSECURE: evaluates the {@code name} parameter as a SpEL expression (CWE-917 - EL
 * injection / server-side template injection). Hardened counterpart: {@code /api/greet}.
 *
 * <p>Because user input is parsed and evaluated, {@code name=7*7} returns {@code 49} and
 * {@code name=T(java.lang.System).getProperty('user.name')} leaks the server's OS user - the same
 * primitive reaches {@code T(java.lang.Runtime).getRuntime().exec(...)} for full RCE.
 */
@RestController
@Profile("insecure")
public class VulnerableGreetController {

    private final SpelExpressionParser parser = new SpelExpressionParser();

    @GetMapping("/vulnerable/greet")
    public String greet(@RequestParam String name) {
        // BUG: the user's string is compiled and evaluated as code.
        Object value = parser.parseExpression(name).getValue();
        return "Hello, " + value + "!";
    }
}

package com.arthur.security.validation;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Hardened counterpart to {@code /vulnerable/validate} (OWASP - regular expression denial of service,
 * CWE-1333).
 *
 * <p>The vulnerable version matches input against {@code ^(a+)+$}, an "evil regex": nested quantifiers
 * make the engine try exponentially many ways to match a near-miss input, so a few dozen characters
 * can pin a CPU core for seconds or minutes.
 *
 * <p>Two defenses, both applied here:
 * <ul>
 *   <li>A <b>length cap</b> - untrusted input fed to a regex should always be bounded.</li>
 *   <li>A <b>linear check</b> instead of a backtracking pattern. {@code chars().allMatch(...)} is O(n)
 *       and cannot backtrack. (An equivalent regex fix is a possessive quantifier: {@code ^a++$}.)</li>
 * </ul>
 */
@RestController
public class ValidationController {

    private static final int MAX_LENGTH = 200;

    @GetMapping("/api/validate")
    public String validate(@RequestParam String input) {
        if (input.length() > MAX_LENGTH) {
            return "rejeitado: entrada acima de " + MAX_LENGTH + " caracteres";
        }
        boolean allA = !input.isEmpty() && input.chars().allMatch(c -> c == 'a');
        return "match=" + allA + " (verificacao linear, sem backtracking)";
    }
}

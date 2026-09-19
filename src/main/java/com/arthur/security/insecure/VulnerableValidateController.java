package com.arthur.security.insecure;

import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.regex.Pattern;

/**
 * Deliberately INSECURE: matches input against an "evil regex" with nested quantifiers (CWE-1333 -
 * ReDoS). Hardened counterpart: {@code /api/validate}.
 *
 * <p>{@code (.*a){20}} forces the engine into super-linear backtracking on a near-miss like
 * {@code "aaaa...aX"}, pinning a CPU core (~18s for ~30 chars). To keep the demo safe the match runs
 * in a background thread with a 3-second cap; if it has not finished, that itself proves the blow-up.
 */
@RestController
@Profile("insecure")
public class VulnerableValidateController {

    private static final Pattern EVIL = Pattern.compile("(.*a){20}");

    @GetMapping("/vulnerable/validate")
    public String validate(@RequestParam String input) throws InterruptedException {
        final boolean[] result = new boolean[1];
        Thread worker = new Thread(() -> result[0] = EVIL.matcher(input).matches());
        worker.setDaemon(true);
        long start = System.nanoTime();
        worker.start();
        worker.join(3000);
        long ms = (System.nanoTime() - start) / 1_000_000;
        if (worker.isAlive()) {
            return "ReDoS: ainda processando apos " + ms + "ms (backtracking catastrofico)";
        }
        return "match=" + result[0] + " em " + ms + "ms";
    }
}

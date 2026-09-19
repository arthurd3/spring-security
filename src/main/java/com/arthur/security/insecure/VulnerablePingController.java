package com.arthur.security.insecure;

import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

/**
 * Deliberately INSECURE: builds a shell command by pasting the {@code host} parameter into a string and
 * running it through {@code sh -c} (OWASP A03:2021, CWE-78 - OS command injection).
 *
 * <p>The shell parses {@code ;}, {@code |}, {@code &&}, backticks and {@code $(...)}, so a value like
 * {@code x; id} runs a second, attacker-chosen command with the server's privileges. This is the live
 * endpoint the {@code scripts/} demo attacks; the hardened counterpart is {@code /api/system/ping}.
 *
 * <p>Only active under the {@code insecure} profile (see the package docs). The unit test drives this
 * same class directly via standalone MockMvc.
 */
@RestController
@Profile("insecure")
public class VulnerablePingController {

    @GetMapping("/vulnerable/ping")
    public String ping(@RequestParam String host) throws Exception {
        // BUG: user input is concatenated into a shell command line.
        Process process = new ProcessBuilder("sh", "-c", "echo pinging " + host).start();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            return reader.lines().collect(Collectors.joining("\n"));
        }
    }
}

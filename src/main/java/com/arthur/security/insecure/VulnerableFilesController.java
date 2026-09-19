package com.arthur.security.insecure;

import jakarta.annotation.PostConstruct;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Deliberately INSECURE: resolves a client-supplied name against a base dir with no containment check
 * (CWE-22, path traversal). Hardened counterpart: {@code /api/files}.
 */
@RestController
@Profile("insecure")
public class VulnerableFilesController {

    private final Path base = Paths.get(System.getProperty("java.io.tmpdir"),
            "spring-security-lab", "vuln-public");

    @PostConstruct
    void seed() {
        try {
            Files.createDirectories(base);
            Files.writeString(base.resolve("readme.txt"), "arquivo publico - ok servir\n");
            // A secret one level ABOVE the public dir, reachable via ../
            Files.writeString(base.getParent().resolve("secrets.properties"),
                    "db.password=super-secret\n");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @GetMapping("/vulnerable/files")
    public String read(@RequestParam String name) throws IOException {
        // BUG: no normalize()/containment check - ../ escapes the base directory.
        return Files.readString(base.resolve(name));
    }
}

package com.arthur.security.insecure;

import org.springframework.context.annotation.Profile;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Deliberately INSECURE: stores an upload under the client's own filename and serves it back with a
 * content type guessed from the extension (CWE-434 - unrestricted file upload). Hardened counterpart:
 * {@code /api/upload}.
 *
 * <p>Upload {@code evil.html} containing {@code <script>...</script>} and request it back: the server
 * stores it verbatim and serves it as {@code text/html}, so the script runs in a victim's browser under
 * this site's origin (stored XSS). A {@code .jsp}/{@code .php} in a servable directory would be RCE.
 */
@RestController
@Profile("insecure")
public class VulnerableUploadController {

    private final Path dir = Paths.get(System.getProperty("java.io.tmpdir"),
            "spring-security-lab", "vulnerable-uploads");

    @PostMapping("/vulnerable/upload")
    public String upload(@RequestParam("file") MultipartFile file) throws IOException {
        Files.createDirectories(dir);
        // BUG: trusts the client's filename - no extension check, no rename.
        String name = file.getOriginalFilename();
        Files.write(dir.resolve(name), file.getBytes());
        return "/vulnerable/uploads/" + name;
    }

    @GetMapping("/vulnerable/uploads/{name}")
    public ResponseEntity<byte[]> serve(@PathVariable String name) throws IOException {
        byte[] content = Files.readAllBytes(dir.resolve(name));
        // BUG: content type from extension, so uploaded HTML executes in the browser.
        MediaType type = name.endsWith(".html") ? MediaType.TEXT_HTML
                : MediaType.APPLICATION_OCTET_STREAM;
        return ResponseEntity.ok().contentType(type).body(content);
    }
}

package com.arthur.security.upload;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Locale;
import java.util.Set;

/**
 * Stores uploaded files safely (OWASP A04/A05, CWE-434 - unrestricted upload of dangerous file types).
 *
 * <p>An unrestricted uploader lets an attacker put an executable page (a {@code .jsp}, {@code .php} or
 * an HTML file with script) into a served directory and then request it, turning "upload an avatar"
 * into remote code execution or stored XSS. The defenses here, in order of importance:
 * <ul>
 *   <li><b>Extension allowlist</b> - only known-inert types are accepted.</li>
 *   <li><b>Server-generated name</b> - the client's filename is never used, so it cannot control the
 *       path or the extension.</li>
 *   <li><b>Size limit</b> and storage in a directory that is not executed as code.</li>
 * </ul>
 */
@Service
public class UploadService {

    private static final Set<String> ALLOWED_EXTENSIONS = Set.of("png", "jpg", "jpeg", "gif", "txt", "pdf");
    private static final long MAX_BYTES = 1_000_000; // 1 MB
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Path storageDir;

    @Autowired
    public UploadService(@Value("${app.upload.dir:}") String configured) {
        this(StringUtils.hasText(configured)
                ? Paths.get(configured)
                : Paths.get(System.getProperty("java.io.tmpdir"), "spring-security-lab", "uploads"));
    }

    public UploadService(Path storageDir) {
        this.storageDir = storageDir.toAbsolutePath().normalize();
    }

    @PostConstruct
    void createDir() {
        try {
            Files.createDirectories(storageDir);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not create upload directory", e);
        }
    }

    /** @return the safe, server-generated file name that was stored */
    public String store(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Empty file");
        }
        if (file.getSize() > MAX_BYTES) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "File too large");
        }

        String ext = extensionOf(file.getOriginalFilename());
        if (!ALLOWED_EXTENSIONS.contains(ext)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "File type not allowed");
        }

        // The client's filename is discarded; the server picks a random, safe name.
        String safeName = randomHex() + "." + ext;
        try {
            Path target = storageDir.resolve(safeName).normalize();
            if (!target.startsWith(storageDir)) { // belt and braces
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid name");
            }
            file.transferTo(target);
        } catch (IOException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Could not store file");
        }
        return safeName;
    }

    private static String extensionOf(String filename) {
        if (filename == null) {
            return "";
        }
        int dot = filename.lastIndexOf('.');
        return dot < 0 ? "" : filename.substring(dot + 1).toLowerCase(Locale.ROOT);
    }

    private static String randomHex() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}

package com.arthur.security.files;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Reads files from a fixed directory, and refuses to read anything outside it.
 *
 * <p>Path traversal (CWE-22) happens when a client-supplied name is appended to a base directory and
 * the result is used without being resolved first: {@code base + "/" + "../../etc/passwd"} escapes the
 * directory entirely. The fix is to <b>canonicalise, then verify containment</b> - never to blacklist
 * {@code ".."}, which attackers bypass with encodings such as {@code %2e%2e%2f} or {@code ....//}.
 *
 * <p>{@link Path#normalize()} collapses the {@code ..} segments and {@link Path#startsWith(Path)} then
 * proves the result is still under the base. Both operate on the resolved real path of the base, so a
 * symlinked base directory cannot be used to sidestep the check either.
 */
@Service
public class FileStorageService {

    private final Path baseDir;

    @Autowired
    public FileStorageService(@Value("${app.files.base-dir:}") String configured) {
        this(StringUtils.hasText(configured)
                ? Paths.get(configured)
                : Paths.get(System.getProperty("java.io.tmpdir"), "spring-security-lab", "public"));
    }

    /** Test-friendly constructor: point it straight at a {@code @TempDir}. */
    public FileStorageService(Path baseDir) {
        this.baseDir = baseDir.toAbsolutePath().normalize();
    }

    /** Creates the directory and a sample file so {@code /api/files?name=readme.txt} works out of the box. */
    @PostConstruct
    void seedSampleFile() {
        try {
            Files.createDirectories(baseDir);
            Path sample = baseDir.resolve("readme.txt");
            if (Files.notExists(sample)) {
                Files.writeString(sample, "This file is inside the public directory - safe to serve.\n");
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Could not prepare the public file directory", e);
        }
    }

    public Path baseDir() {
        return baseDir;
    }

    /**
     * Reads {@code name} from the base directory.
     *
     * @throws ResponseStatusException 400 if the name escapes the base directory, 404 if no such file
     */
    public String read(String name) {
        Path base = realBase();
        Path target = base.resolve(name).normalize();

        if (!target.startsWith(base)) {
            // The only branch that matters: the resolved path left the directory we are willing to serve.
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid file name");
        }
        if (!Files.isRegularFile(target)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "File not found");
        }

        try {
            return Files.readString(target);
        } catch (IOException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Could not read file");
        }
    }

    /** Resolves symlinks so containment is checked against the directory's true location. */
    private Path realBase() {
        try {
            return Files.exists(baseDir) ? baseDir.toRealPath() : baseDir;
        } catch (IOException e) {
            return baseDir;
        }
    }
}

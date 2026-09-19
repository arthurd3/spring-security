package com.arthur.security.attacks.pathtraversal;

import com.arthur.security.VulnerableExample;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * A deliberately INSECURE file endpoint: it joins the client-supplied name onto a base directory and
 * reads whatever that resolves to (CWE-22, path traversal / directory traversal).
 *
 * <p>The author assumed {@code name} would be a plain file name. {@code ..} segments make the join
 * walk back out of the directory, so the endpoint becomes an arbitrary-file-read primitive - typically
 * used against {@code /etc/passwd}, {@code application.properties}, or a cloud credentials file.
 *
 * <p>Lives under {@code src/test} and is never component-scanned into the running application. The
 * safe counterpart is {@code FileStorageService#read}, which normalises and then verifies containment.
 */
@VulnerableExample
@Controller
public class VulnerableFileController {

    private final Path baseDir;

    public VulnerableFileController(Path baseDir) {
        this.baseDir = baseDir;
    }

    @GetMapping("/vulnerable/files")
    @ResponseBody
    public String read(@RequestParam String name) {
        try {
            // BUG: resolve() without normalize()/containment check happily walks out of baseDir.
            return Files.readString(baseDir.resolve(name));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}

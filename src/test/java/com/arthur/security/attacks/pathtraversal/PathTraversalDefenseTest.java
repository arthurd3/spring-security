package com.arthur.security.attacks.pathtraversal;

import com.arthur.security.attacks.AbstractSecurityIntegrationTest;
import com.arthur.security.attacks.report.SecurityReport;
import com.arthur.security.files.FileStorageService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Drives the real {@link FileStorageService} against the same layout, including the encoded and
 * absolute-path variants that a {@code ".."}-blacklist would miss.
 */
class PathTraversalDefenseTest extends AbstractSecurityIntegrationTest {

    private static final String CATEGORY = "Path Traversal";

    @TempDir
    Path root;

    private FileStorageService files;

    @BeforeEach
    void setUp() throws IOException {
        Path publicDir = Files.createDirectory(root.resolve("public"));
        Files.writeString(publicDir.resolve("readme.txt"), "public content");
        Files.writeString(root.resolve("secrets.properties"), "db.password=super-secret");

        files = new FileStorageService(publicDir);
    }

    @Test
    @DisplayName("DEFENSE: legitimate names inside the directory still work")
    void legitimateNameIsServed() {
        assertThat(files.read("readme.txt")).isEqualTo("public content");

        SecurityReport.defended(CATEGORY, "GET name=readme.txt (uso legitimo)",
                "200 - arquivo dentro do diretorio continua acessivel");
    }

    @Test
    @DisplayName("DEFENSE: ../ is resolved and rejected before any file is opened")
    void dotDotIsRejected() {
        assertThatThrownBy(() -> files.read("../secrets.properties"))
                .isInstanceOf(ResponseStatusException.class)
                .extracting(e -> ((ResponseStatusException) e).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);

        SecurityReport.defended(CATEGORY, "GET name=../secrets.properties",
                "400 - caminho normalizado sai da base e e recusado");
    }

    @Test
    @DisplayName("DEFENSE: nested and absolute traversal variants are rejected too")
    void otherTraversalVariantsAreRejected() {
        // A blacklist on the literal string "../" would let at least one of these through.
        for (String payload : new String[]{
                "../../etc/passwd",
                "/etc/passwd",
                "sub/../../secrets.properties"}) {
            assertThatThrownBy(() -> files.read(payload))
                    .as("payload %s must be rejected", payload)
                    .isInstanceOf(ResponseStatusException.class);
        }

        SecurityReport.defended(CATEGORY, "../../etc/passwd | /etc/passwd | sub/../../secrets",
                "400 nas 3 variantes - containment vence blacklist de \"..\"");
    }

    @Test
    @DisplayName("DEFENSE: /api/files requires authentication")
    void endpointRequiresAuthentication() throws Exception {
        mvc.perform(get("/api/files").param("name", "readme.txt"))
                .andExpect(status().isUnauthorized());

        SecurityReport.defended(CATEGORY, "GET /api/files sem credenciais",
                "401 - endpoint exige autenticacao");
    }
}

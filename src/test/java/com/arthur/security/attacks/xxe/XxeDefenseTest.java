package com.arthur.security.attacks.xxe;

import com.arthur.security.attacks.AbstractSecurityIntegrationTest;
import com.arthur.security.attacks.report.SecurityReport;
import com.arthur.security.xml.SafeXmlParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code disallow-doctype-decl} makes the parser reject the document outright, so the entity is never
 * declared, let alone resolved. Benign XML keeps working, which is what makes the switch safe to turn
 * on by default.
 */
class XxeDefenseTest extends AbstractSecurityIntegrationTest {

    private static final String CATEGORY = "XXE";

    @TempDir
    Path tempDir;

    @Autowired
    private SafeXmlParser parser;

    private Path secretFile;

    @BeforeEach
    void setUp() throws IOException {
        secretFile = tempDir.resolve("secrets.properties");
        Files.writeString(secretFile, "db.password=super-secret");
    }

    private String payload() {
        return """
                <?xml version="1.0"?>
                <!DOCTYPE note [ <!ENTITY xxe SYSTEM "%s"> ]>
                <note>&xxe;</note>
                """.formatted(secretFile.toUri());
    }

    @Test
    @DisplayName("DEFENSE: the DOCTYPE is refused, so no entity can be declared")
    void doctypeIsRejected() {
        assertThatThrownBy(() -> parser.rootText(payload()))
                .isInstanceOf(SAXException.class)
                .hasMessageContaining("DOCTYPE");

        SecurityReport.defended(CATEGORY, "<!ENTITY xxe SYSTEM \"file:///...secrets.properties\">",
                "SAXException - DOCTYPE proibido, entidade nunca declarada");
    }

    @Test
    @DisplayName("DEFENSE: ordinary XML still parses")
    void benignXmlStillParses() throws Exception {
        assertThat(parser.rootText("<note>hello</note>")).isEqualTo("hello");

        SecurityReport.defended(CATEGORY, "<note>hello</note> (entrada normal)",
                "parse normal - a protecao nao quebra o uso legitimo");
    }

    @Test
    @DisplayName("DEFENSE: /api/xml/parse rejects the payload with 400 and leaks nothing")
    void endpointRejectsPayload() throws Exception {
        mvc.perform(post("/api/xml/parse")
                        .contentType(MediaType.APPLICATION_XML)
                        .content(payload())
                        .with(httpBasic("arthur", "password")))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("super-secret"))));

        mvc.perform(post("/api/xml/parse")
                        .contentType(MediaType.APPLICATION_XML)
                        .content("<note>hello</note>")
                        .with(httpBasic("arthur", "password")))
                .andExpect(status().isOk())
                .andExpect(content().string("hello"));

        SecurityReport.defended(CATEGORY, "POST /api/xml/parse com DOCTYPE malicioso",
                "400 sem vazar o arquivo; XML normal continua 200");
    }
}

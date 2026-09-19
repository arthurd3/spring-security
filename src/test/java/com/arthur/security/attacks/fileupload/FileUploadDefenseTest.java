package com.arthur.security.attacks.fileupload;

import com.arthur.security.attacks.AbstractSecurityIntegrationTest;
import com.arthur.security.attacks.report.SecurityReport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** The hardened endpoint rejects dangerous types and renames what it keeps. */
class FileUploadDefenseTest extends AbstractSecurityIntegrationTest {

    private static final String CATEGORY = "Upload sem Restricao";

    @Test
    @DisplayName("DEFENSE: an HTML upload is rejected")
    void htmlUploadRejected() throws Exception {
        MockMultipartFile evil = new MockMultipartFile(
                "file", "evil.html", "text/html", "<script>alert(1)</script>".getBytes());

        mvc.perform(multipart("/api/upload").file(evil).with(httpBasic("arthur", "password")))
                .andExpect(status().isBadRequest());

        SecurityReport.defended(CATEGORY, "upload de evil.html",
                "400 - extensao fora da allowlist");
    }

    @Test
    @DisplayName("DEFENSE: an allowed type is accepted and given a random server-side name")
    void allowedTypeIsRenamed() throws Exception {
        MockMultipartFile img = new MockMultipartFile(
                "file", "avatar.png", "image/png", new byte[]{1, 2, 3, 4});

        mvc.perform(multipart("/api/upload").file(img).with(httpBasic("arthur", "password")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(".png")))
                .andExpect(content().string(not(containsString("avatar.png"))));

        SecurityReport.defended(CATEGORY, "upload de avatar.png",
                "200 - aceito com nome aleatorio no servidor, nome do cliente descartado");
    }
}

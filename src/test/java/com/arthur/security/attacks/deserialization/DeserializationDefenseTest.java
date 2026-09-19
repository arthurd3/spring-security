package com.arthur.security.attacks.deserialization;

import com.arthur.security.attacks.AbstractSecurityIntegrationTest;
import com.arthur.security.attacks.report.SecurityReport;
import com.arthur.security.insecure.LabGadget;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** The hardened import parses JSON into a fixed type - no native stream, no gadget execution. */
class DeserializationDefenseTest extends AbstractSecurityIntegrationTest {

    private static final String CATEGORY = "Desserializacao Insegura";

    @Test
    @DisplayName("DEFENSE: valid JSON imports into a fixed type")
    void jsonImportsSafely() throws Exception {
        mvc.perform(post("/api/import").with(httpBasic("arthur", "password"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"salary\",\"amount\":100}"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("amount=100")));

        SecurityReport.defended(CATEGORY, "POST /api/import (JSON em tipo fixo)",
                "200 - Jackson so popula os campos do DTO, sem instanciar tipos arbitrarios");
    }

    @Test
    @DisplayName("DEFENSE: a native serialized blob is rejected and runs nothing")
    void nativeBlobIsRejected() throws Exception {
        LabGadget.lastSideEffect = null;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(new LabGadget("echo pwned"));
        }
        String blob = Base64.getEncoder().encodeToString(bos.toByteArray());

        mvc.perform(post("/api/import").with(httpBasic("arthur", "password"))
                        .contentType(MediaType.APPLICATION_JSON).content(blob))
                .andExpect(status().isBadRequest());

        assertThat(LabGadget.lastSideEffect).isNull();

        SecurityReport.defended(CATEGORY, "POST /api/import com stream Java serializado",
                "400 e nenhum codigo executado - o endpoint nunca chama readObject");
    }
}

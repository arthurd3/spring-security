package com.arthur.security.insecure;

import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;

/**
 * Deliberately INSECURE: deserializes a native Java object stream supplied by the client (CWE-502).
 * Hardened counterpart: {@code /api/import} (JSON into a fixed type).
 *
 * <p>{@code ObjectInputStream.readObject()} rebuilds whatever object graph the bytes describe and runs
 * each class's {@code readObject} in the process - so attacker bytes become attacker code. The
 * {@code /sample} endpoint hands out a ready-made payload so the demo needs no Java tooling.
 */
@RestController
@Profile("insecure")
public class VulnerableImportController {

    /** Returns a base64 native-serialized {@link LabGadget}, so a shell script can just replay it. */
    @GetMapping("/vulnerable/deserialize/sample")
    public String sample() throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(new LabGadget("echo pwned-by-deserialization"));
        }
        return Base64.getEncoder().encodeToString(bos.toByteArray());
    }

    @PostMapping("/vulnerable/deserialize")
    public String deserialize(@RequestBody String base64) throws Exception {
        LabGadget.lastSideEffect = null;
        byte[] bytes = Base64.getDecoder().decode(base64.trim());
        // BUG: reconstructs an arbitrary object graph from untrusted bytes, running its readObject().
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
            Object obj = ois.readObject();
            return "desserializado: " + obj.getClass().getName()
                    + " | efeito colateral executado durante readObject: " + LabGadget.lastSideEffect;
        }
    }
}

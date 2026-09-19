package com.arthur.security.imports;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Imports data as JSON into a fixed, known type - the safe alternative to native deserialization
 * (OWASP A08:2021, CWE-502 - deserialization of untrusted data).
 *
 * <p>Java's {@code ObjectInputStream.readObject()} rebuilds arbitrary object graphs and runs code
 * during the process (via {@code readObject}, {@code readResolve}, finalizers and library "gadgets"),
 * so deserializing attacker bytes is remote code execution. The fix is to not deserialize untrusted
 * native streams at all. Parsing JSON into an explicit DTO only ever populates the fields of that one
 * class - there is no mechanism to instantiate an attacker-chosen type or invoke a gadget chain.
 */
@RestController
public class ImportController {

    private final ObjectMapper objectMapper = new ObjectMapper();

    /** A deliberately small, explicit target type - never a polymorphic/Object binding. */
    public record ImportRequest(String name, int amount) {}

    @PostMapping("/api/import")
    public String importData(@RequestBody String json) {
        try {
            ImportRequest request = objectMapper.readValue(json, ImportRequest.class);
            return "imported name=" + request.name() + " amount=" + request.amount();
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid JSON");
        }
    }
}

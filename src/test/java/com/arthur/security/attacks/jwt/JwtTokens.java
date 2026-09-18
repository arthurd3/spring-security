package com.arthur.security.attacks.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;

/**
 * Test-only helpers for crafting attacker tokens. Nothing external is touched — tokens are strings.
 */
final class JwtTokens {

    private JwtTokens() {
    }

    /** Forges an unsigned {@code alg=none} token with arbitrary claims (no signature at all). */
    static String algNone(String subject, List<String> roles) {
        String header = base64Url("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        String payload = base64Url("{\"sub\":\"" + subject + "\",\"roles\":" + jsonArray(roles) + "}");
        return header + "." + payload + ".";
    }

    /** Signs an HS256 token with the given secret (used to test wrong-key / weak-secret scenarios). */
    static String signedHs256(String secret, String subject, List<String> roles, Instant expiresAt)
            throws JOSEException {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(subject)
                .claim("roles", roles)
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(expiresAt))
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
        jwt.sign(new MACSigner(secret.getBytes(StandardCharsets.UTF_8)));
        return jwt.serialize();
    }

    private static String base64Url(String value) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String jsonArray(List<String> values) {
        return "[" + String.join(",", values.stream().map(v -> "\"" + v + "\"").toList()) + "]";
    }
}

package com.arthur.security.attacks.jwt;

import com.arthur.security.attacks.AbstractSecurityIntegrationTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

import java.time.Instant;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The OAuth2 resource server verifies the signature and expiry of every bearer token, so all four
 * attacker tokens are rejected while a genuine one is accepted.
 */
class JwtDefenseTest extends AbstractSecurityIntegrationTest {

    @Autowired
    private JwtEncoder jwtEncoder;

    private String mint(Instant issuedAt, Instant expiresAt) {
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .subject("arthur")
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .claim("roles", List.of("USER"))
                .build();
        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    @Test
    @DisplayName("DEFENSE: a properly signed, unexpired token is accepted")
    void validTokenAccepted() throws Exception {
        Instant now = Instant.now();
        String token = mint(now, now.plusSeconds(3600));

        mvc.perform(get("/api/v1/user").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("DEFENSE: an alg=none forged token is rejected")
    void algNoneRejected() throws Exception {
        String token = JwtTokens.algNone("arthur", List.of("ADMIN"));

        mvc.perform(get("/api/v1/user").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("DEFENSE: a token signed with the wrong key is rejected")
    void wrongKeyRejected() throws Exception {
        String token = JwtTokens.signedHs256(
                "a-totally-different-secret-key-32bytes!", "arthur", List.of("USER"),
                Instant.now().plusSeconds(3600));

        mvc.perform(get("/api/v1/user").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("DEFENSE: an expired token is rejected")
    void expiredTokenRejected() throws Exception {
        Instant now = Instant.now();
        String token = mint(now.minusSeconds(600), now.minusSeconds(300));

        mvc.perform(get("/api/v1/user").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }
}

package com.arthur.security.auth;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * Mints signed JWTs for an authenticated principal.
 *
 * <p>Roles are written to a {@code roles} claim <i>without</i> the {@code ROLE_} prefix; the resource
 * server's {@code JwtAuthenticationConverter} adds the prefix back when it reads the token. The token is
 * signed with the HMAC key from {@code JwtConfig}, so a tampered or unsigned token fails verification.
 */
@Service
public class TokenService {

    private static final long TTL_SECONDS = 3600;

    private final JwtEncoder encoder;
    private final Clock clock;

    public TokenService(JwtEncoder encoder, Clock clock) {
        this.encoder = encoder;
        this.clock = clock;
    }

    public String generateToken(Authentication authentication) {
        Instant now = Instant.now(clock);
        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .map(authority -> authority.startsWith("ROLE_") ? authority.substring(5) : authority)
                .toList();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("spring-security-lab")
                .issuedAt(now)
                .expiresAt(now.plus(TTL_SECONDS, ChronoUnit.SECONDS))
                .subject(authentication.getName())
                .claim("roles", roles)
                .build();

        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }
}

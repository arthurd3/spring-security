package com.arthur.security.auth;

import com.arthur.security.user.AppUser;
import com.arthur.security.user.AppUserRepository;
import com.arthur.security.user.UserProfile;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Self-service registration, written to be immune to mass assignment (OWASP A08:2021, CWE-915).
 *
 * <p>The request is bound to {@link RegistrationRequest}, a record with exactly two components. It has
 * no {@code roles} component at all, so a request body carrying {@code "roles": "ADMIN"} has nothing to
 * bind to and Jackson discards it. The role is then assigned by the server - never by the client.
 *
 * <p>Binding {@code @RequestBody AppUser} instead would hand the attacker every column of the entity,
 * including {@code roles} and {@code lockedUntil}. That is exactly what the vulnerable controller in
 * the {@code attacks.massassignment} test package does, and what its test proves.
 */
@RestController
@RequestMapping("/api/auth")
public class RegistrationController {

    /** Every self-registered account gets this role, regardless of what the request asked for. */
    private static final String DEFAULT_ROLES = "USER";

    private final AppUserRepository users;
    private final PasswordEncoder encoder;

    public RegistrationController(AppUserRepository users, PasswordEncoder encoder) {
        this.users = users;
        this.encoder = encoder;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public UserProfile register(@Valid @RequestBody RegistrationRequest request) {
        if (users.findByUsername(request.username()).isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username already taken");
        }

        AppUser user = new AppUser(request.username(), encoder.encode(request.password()), DEFAULT_ROLES);
        return UserProfile.from(users.save(user));
    }

    /** Deliberately narrow: the client can supply a username and a password, and nothing else. */
    public record RegistrationRequest(
            @NotBlank @Size(min = 3, max = 50) String username,
            @NotBlank @Size(min = 8, max = 100) String password) {
    }
}

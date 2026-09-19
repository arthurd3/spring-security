package com.arthur.security.user;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/**
 * A persisted application user.
 *
 * <p>The {@code password} column stores a value in Spring Security's
 * {@code DelegatingPasswordEncoder} format, e.g. {@code {bcrypt}$2a$10$...} — never plaintext.
 * {@code lockedUntil} backs the brute-force lockout demo: while it is set to a future instant the
 * account is treated as locked.
 */
@Entity
@Table(name = "app_users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AppUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    /**
     * Encoded password, prefixed with the encoder id (e.g. {@code {bcrypt}}).
     *
     * <p>{@code @JsonIgnore} is defense in depth against sensitive-data exposure: even if this entity
     * is ever returned from a controller by mistake, the hash is never serialised into a response.
     * The primary defense is still to return a DTO - see {@code UserProfile} - rather than the entity.
     */
    @JsonIgnore
    @Column(nullable = false)
    private String password;

    /** Comma-separated role names without the {@code ROLE_} prefix, e.g. {@code "USER,ADMIN"}. */
    @Column(nullable = false)
    private String roles;

    /** When set to a future instant, the account is locked until that time. */
    private Instant lockedUntil;

    public AppUser(String username, String password, String roles) {
        this.username = username;
        this.password = password;
        this.roles = roles;
    }

    public String[] roleArray() {
        return roles.split(",");
    }
}

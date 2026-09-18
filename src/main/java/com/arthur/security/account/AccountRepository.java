package com.arthur.security.account;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AccountRepository extends JpaRepository<Account, Long> {

    /**
     * The "scope the query to the principal" pattern from the OWASP IDOR cheat sheet — an alternative
     * (or complement) to the {@code @PostAuthorize} ownership check.
     */
    Optional<Account> findByIdAndOwner(Long id, String owner);
}

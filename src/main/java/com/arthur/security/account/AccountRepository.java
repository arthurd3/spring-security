package com.arthur.security.account;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface AccountRepository extends JpaRepository<Account, Long> {

    /**
     * The "scope the query to the principal" pattern from the OWASP IDOR cheat sheet - an alternative
     * (or complement) to the {@code @PostAuthorize} ownership check.
     */
    Optional<Account> findByIdAndOwner(Long id, String owner);

    /**
     * Backs the SQL-injection demo. Spring Data derives a {@code PreparedStatement} with a bind
     * parameter for {@code owner}, so the argument is always sent as data and can never be parsed as
     * SQL - a payload like {@code ' OR '1'='1} is looked up as a literal username and matches nothing.
     */
    List<Account> findByOwner(String owner);
}

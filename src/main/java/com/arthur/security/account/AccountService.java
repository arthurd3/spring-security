package com.arthur.security.account;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

/**
 * Object-level authorization for accounts - the real fix for IDOR.
 *
 * <p>{@code @PostAuthorize} runs after the method returns and evaluates the SpEL against the returned
 * object: the caller may see the account only if they own it (or are an admin). Without this check any
 * authenticated user could read {@code /api/accounts/{id}} for any id.
 */
@Service
public class AccountService {

    private final AccountRepository accounts;

    public AccountService(AccountRepository accounts) {
        this.accounts = accounts;
    }

    @PostAuthorize("returnObject.owner == authentication.name or hasRole('ADMIN')")
    public Account getAccount(Long id) {
        return accounts.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Account not found"));
    }

    /**
     * Admin-only owner lookup, and the SQL-injection counter-example.
     *
     * <p>The query is a Spring Data derived query, so the {@code owner} argument travels as a bind
     * parameter rather than being concatenated into the statement. Compare with the string-building
     * DAO in the {@code attacks.sqli} test package, where the same input rewrites the WHERE clause.
     */
    @PreAuthorize("hasRole('ADMIN')")
    public List<Account> searchByOwner(String owner) {
        return accounts.findByOwner(owner);
    }
}

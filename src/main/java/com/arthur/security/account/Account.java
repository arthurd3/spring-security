package com.arthur.security.account;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.math.BigDecimal;

/**
 * A bank-account-like resource used to demonstrate IDOR (Insecure Direct Object Reference).
 *
 * <p>The {@code owner} field is the username that may access this account. The whole point of the demo
 * is that the id in {@code /api/accounts/{id}} is guessable, so authorization must be enforced on the
 * <i>object</i>, not merely on "is the caller logged in?".
 */
@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Account {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String owner;

    private BigDecimal balance;

    public Account(String owner, BigDecimal balance) {
        this.owner = owner;
        this.balance = balance;
    }
}

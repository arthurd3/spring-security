package com.arthur.security.config;

import com.arthur.security.account.Account;
import com.arthur.security.account.AccountRepository;
import com.arthur.security.user.AppUser;
import com.arthur.security.user.AppUserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;

/**
 * Seeds demo users and accounts on startup.
 *
 * <p>Passwords are run through the {@link PasswordEncoder}, so the database only ever stores
 * {@code {bcrypt}$2a$...} hashes — never plaintext. Each account is owned by a specific user, which is
 * what the IDOR demo exercises.
 */
@Component
public class DataSeeder implements CommandLineRunner {

    private final AppUserRepository users;
    private final AccountRepository accounts;
    private final PasswordEncoder encoder;

    public DataSeeder(AppUserRepository users, AccountRepository accounts, PasswordEncoder encoder) {
        this.users = users;
        this.accounts = accounts;
        this.encoder = encoder;
    }

    @Override
    public void run(String... args) {
        if (users.count() > 0) {
            return;
        }

        users.save(new AppUser("arthur", encoder.encode("password"), "USER"));
        users.save(new AppUser("admin", encoder.encode("password"), "ADMIN,USER"));

        accounts.save(new Account("arthur", new BigDecimal("1500.00")));
        accounts.save(new Account("admin", new BigDecimal("9999.00")));
    }
}

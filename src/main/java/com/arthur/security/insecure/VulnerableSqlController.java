package com.arthur.security.insecure;

import jakarta.annotation.PostConstruct;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Deliberately INSECURE: builds SQL by string concatenation against a real H2 table (CWE-89).
 * Hardened counterpart: {@code /api/accounts/search} (bind parameter).
 */
@RestController
@Profile("insecure")
public class VulnerableSqlController {

    private final JdbcTemplate jdbc;

    public VulnerableSqlController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @PostConstruct
    void seed() {
        jdbc.execute("DROP TABLE IF EXISTS demo_accounts");
        jdbc.execute("CREATE TABLE demo_accounts (owner VARCHAR(50) PRIMARY KEY, balance INT)");
        jdbc.update("INSERT INTO demo_accounts VALUES ('alice', 1500)");
        jdbc.update("INSERT INTO demo_accounts VALUES ('bob', 250)");
        jdbc.update("INSERT INTO demo_accounts VALUES ('carol', 9900)");
    }

    @GetMapping("/vulnerable/accounts/search")
    public List<String> search(@RequestParam String owner) {
        // BUG: owner concatenated into the SQL string.
        String sql = "SELECT owner FROM demo_accounts WHERE owner = '" + owner + "'";
        return jdbc.queryForList(sql, String.class);
    }
}

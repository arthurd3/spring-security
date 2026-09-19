package com.arthur.security.attacks.sqli;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * A deliberately INSECURE DAO that builds SQL by string concatenation (OWASP A03:2021, CWE-89).
 *
 * <p>The user's input is pasted straight into the statement text, so the database cannot tell where
 * the developer's query ends and the attacker's input begins. A quote in the input closes the string
 * literal early and everything after it is parsed as SQL.
 *
 * <p>This class lives under {@code src/test} and is never component-scanned, so it cannot reach the
 * running application. The safe counterpart is {@code AccountService#searchByOwner}, which uses a
 * Spring Data derived query - a {@code PreparedStatement} with a bind parameter.
 */
class VulnerableAccountDao {

    private final Connection connection;

    VulnerableAccountDao(Connection connection) {
        this.connection = connection;
    }

    /** BUG: {@code owner} is concatenated, so {@code ' OR '1'='1} rewrites the WHERE clause. */
    List<String> findByOwner(String owner) throws SQLException {
        String sql = "SELECT owner FROM demo_accounts WHERE owner = '" + owner + "'";
        List<String> found = new ArrayList<>();
        try (Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(sql)) {
            while (rs.next()) {
                found.add(rs.getString("owner"));
            }
        }
        return found;
    }

    /** BUG: the same flaw on a login query turns into a full authentication bypass. */
    boolean authenticate(String owner, String password) throws SQLException {
        String sql = "SELECT owner FROM demo_accounts WHERE owner = '" + owner
                + "' AND password = '" + password + "'";
        try (Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(sql)) {
            return rs.next();
        }
    }
}

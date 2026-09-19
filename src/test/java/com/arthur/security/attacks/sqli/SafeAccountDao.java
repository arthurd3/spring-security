package com.arthur.security.attacks.sqli;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * The same two queries written with bind parameters, for a side-by-side contrast.
 *
 * <p>A {@link PreparedStatement} sends the statement text and the values over separate channels: the
 * database parses the query once, with {@code ?} as a placeholder, and the value is only ever compared
 * as data. No amount of quoting in the input can change the parsed statement, which is why
 * parameterization - not escaping or input filtering - is the actual fix for SQL injection.
 */
class SafeAccountDao {

    private final Connection connection;

    SafeAccountDao(Connection connection) {
        this.connection = connection;
    }

    List<String> findByOwner(String owner) throws SQLException {
        String sql = "SELECT owner FROM demo_accounts WHERE owner = ?";
        List<String> found = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, owner);
            try (ResultSet rs = statement.executeQuery()) {
                while (rs.next()) {
                    found.add(rs.getString("owner"));
                }
            }
        }
        return found;
    }

    boolean authenticate(String owner, String password) throws SQLException {
        String sql = "SELECT owner FROM demo_accounts WHERE owner = ? AND password = ?";
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, owner);
            statement.setString(2, password);
            try (ResultSet rs = statement.executeQuery()) {
                return rs.next();
            }
        }
    }
}

package com.arthur.security.attacks.sqli;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * A throwaway H2 database holding three accounts, so the injection demo runs against a real SQL engine
 * rather than a mock. Each test class uses its own database name, so they never interfere.
 */
final class DemoAccountsDb {

    private DemoAccountsDb() {
    }

    static Connection open(String name) throws SQLException {
        Connection connection = DriverManager.getConnection("jdbc:h2:mem:" + name + ";DB_CLOSE_DELAY=-1");
        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP TABLE IF EXISTS demo_accounts");
            statement.execute("""
                    CREATE TABLE demo_accounts (
                        owner    VARCHAR(50) PRIMARY KEY,
                        password VARCHAR(50) NOT NULL,
                        balance  DECIMAL(10, 2) NOT NULL
                    )
                    """);
            statement.execute("""
                    INSERT INTO demo_accounts (owner, password, balance) VALUES
                        ('alice', 'alice-secret', 1500.00),
                        ('bob',   'bob-secret',    250.00),
                        ('carol', 'carol-secret', 9900.00)
                    """);
        }
        return connection;
    }
}

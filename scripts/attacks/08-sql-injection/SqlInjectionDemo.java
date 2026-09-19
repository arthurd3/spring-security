// Self-contained SQL Injection deep-dive (CWE-89). Real in-memory H2 DB (on the classpath).
// Each VARIANT shows a real technique: the vulnerable code, the attack, and the parameterized fix.
// Techniques reimplemented from OWASP WebGoat / PayloadsAllTheThings / sqlmap docs (see DEEP-DIVE.md).
//
// Run: java -cp "$(cat scripts/lib/classpath.txt)" SqlInjectionDemo.java
import java.sql.*;
import java.util.*;

public class SqlInjectionDemo {

    static Connection db() throws Exception {
        Connection c = DriverManager.getConnection("jdbc:h2:mem:sqli;DB_CLOSE_DELAY=-1");
        try (Statement s = c.createStatement()) {
            s.execute("DROP TABLE IF EXISTS accounts; DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS audit");
            s.execute("CREATE TABLE accounts(owner VARCHAR(50), balance INT)");
            s.execute("CREATE TABLE users(username VARCHAR(50), password VARCHAR(50))");
            s.execute("CREATE TABLE audit(note VARCHAR(200))");
            s.execute("INSERT INTO accounts VALUES ('alice',1500),('bob',250),('carol',9900)");
            s.execute("INSERT INTO users VALUES ('admin','S3cr3t'),('alice','alicepw')");
        }
        return c;
    }
    static List<String> rows(Connection c, String sql) throws Exception {
        List<String> out = new ArrayList<>();
        try (Statement s = c.createStatement(); ResultSet r = s.executeQuery(sql)) {
            int cols = r.getMetaData().getColumnCount();
            while (r.next()) { StringBuilder b = new StringBuilder();
                for (int i = 1; i <= cols; i++) b.append(i > 1 ? "," : "").append(r.getString(i)); out.add(b.toString()); }
        }
        return out;
    }

    // ============ VARIANT 1: tautology (auth bypass / full dump) ============
    // real-world: MOVEit CVE-2023-34362; OWASP WebGoat SqlInjection lessons
    static void tautology(Connection c) throws Exception {
        System.out.println("[VARIANT] 1) Tautologia  ' OR '1'='1   (dump / bypass)");
        String payload = "x' OR '1'='1";
        String vuln = "SELECT owner FROM accounts WHERE owner = '" + payload + "'"; // BUG: concatenation
        System.out.println("[VULNERAVEL] " + vuln);
        System.out.println("[VULNERAVEL] -> " + rows(c, vuln) + "  (a tabela inteira vazou)");
        try (PreparedStatement p = c.prepareStatement("SELECT owner FROM accounts WHERE owner = ?")) {
            p.setString(1, payload);
            try (ResultSet r = p.executeQuery()) { List<String> o = new ArrayList<>(); while (r.next()) o.add(r.getString(1));
                System.out.println("[DEFENDIDO] bind param -> " + o + "  (payload tratado como nome literal)"); }
        }
    }

    // ============ VARIANT 2: UNION-based (exfiltrate other tables) ============
    // real-world: classic UNION exfiltration; PayloadsAllTheThings SQLi/Union
    static void unionBased(Connection c) throws Exception {
        System.out.println("[VARIANT] 2) UNION SELECT  (rouba dados de OUTRA tabela)");
        String payload = "x' UNION SELECT password FROM users --";
        String vuln = "SELECT owner FROM accounts WHERE owner = '" + payload + "'";
        System.out.println("[VULNERAVEL] " + vuln);
        System.out.println("[VULNERAVEL] -> " + rows(c, vuln) + "  (senhas da tabela users exfiltradas)");
        try (PreparedStatement p = c.prepareStatement("SELECT owner FROM accounts WHERE owner = ?")) {
            p.setString(1, payload);
            try (ResultSet r = p.executeQuery()) { List<String> o = new ArrayList<>(); while (r.next()) o.add(r.getString(1));
                System.out.println("[DEFENDIDO] bind param -> " + o + "  (UNION nunca e interpretado)"); }
        }
    }

    // ============ VARIANT 3: boolean-blind (infer a secret char by char) ============
    // real-world: sqlmap boolean-based blind; used when no data/error is shown, only true/false
    static void booleanBlind(Connection c) throws Exception {
        System.out.println("[VARIANT] 3) Blind booleano  (extrai a senha 1 caractere por vez)");
        String charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder recovered = new StringBuilder();
        for (int pos = 1; pos <= 6; pos++) {
            for (char ch : charset.toCharArray()) {
                // The app only reveals TRUE/FALSE (a row exists or not) - enough to leak the secret.
                String payload = "alice' AND SUBSTRING((SELECT password FROM users WHERE username='admin')," + pos + ",1)='" + ch + "";
                String vuln = "SELECT owner FROM accounts WHERE owner = '" + payload + "'";
                if (!rows(c, vuln).isEmpty()) { recovered.append(ch); break; }
            }
        }
        System.out.println("[VULNERAVEL] senha do admin reconstruida por respostas true/false -> " + recovered);
        // Defense: parameterized -> the whole payload is one literal username that does not exist.
        boolean any = false;
        try (PreparedStatement p = c.prepareStatement("SELECT owner FROM accounts WHERE owner = ?")) {
            p.setString(1, "alice' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='S");
            try (ResultSet r = p.executeQuery()) { any = r.next(); }
        }
        System.out.println("[DEFENDIDO] bind param -> match=" + any + "  (sem oraculo true/false para vazar nada)");
    }

    // ============ VARIANT 4: second-order (stored payload triggers later) ============
    // real-world: second-order SQLi - safe insert, unsafe later read
    static void secondOrder(Connection c) throws Exception {
        System.out.println("[VARIANT] 4) Second-order  (payload gravado agora, dispara depois)");
        String username = "eve'; DROP TABLE audit; --";
        try (PreparedStatement p = c.prepareStatement("INSERT INTO users(username,password) VALUES(?,?)")) {
            p.setString(1, username); p.setString(2, "x"); p.executeUpdate(); // stored safely...
        }
        // ...but a later feature concatenates the stored username into SQL:
        String vuln = "SELECT password FROM users WHERE username = '" + username + "'"; // BUG later
        boolean tableGone = false;
        try (Statement s = c.createStatement()) { s.execute(vuln); } catch (SQLException e) { /* multi-stmt */ }
        try (Statement s = c.createStatement()) { s.executeQuery("SELECT COUNT(*) FROM audit"); }
        catch (SQLException e) { tableGone = true; }
        System.out.println("[VULNERAVEL] valor armazenado reusado em SQL cru; tabela audit destruida? " + tableGone
                + "  (o dado 'confiavel' do proprio banco virou ataque)");
        System.out.println("[DEFENDIDO] a leitura posterior tambem deve usar bind param -> valor nunca vira comando");
    }

    // ============ VARIANT 5: ORDER BY injection (can't bind a column) ============
    // real-world: Apache Fineract orderBy SQLi; sort params are a classic sink -> use an allowlist
    static void orderByInjection(Connection c) throws Exception {
        System.out.println("[VARIANT] 5) ORDER BY  (coluna nao aceita bind param -> allowlist)");
        String evil = "CASE WHEN (SELECT password FROM users WHERE username='admin')='S3cr3t' THEN balance ELSE owner END";
        String vuln = "SELECT owner FROM accounts ORDER BY " + evil; // BUG: column concatenated
        boolean worked;
        try { rows(c, vuln); worked = true; } catch (SQLException e) { worked = false; }
        System.out.println("[VULNERAVEL] ORDER BY com subquery/CASE aceito? " + worked + "  (ordena por dado secreto -> inferencia)");
        Set<String> allowed = Set.of("owner", "balance");
        String userCol = "balance; DROP TABLE users";
        String safeCol = allowed.contains(userCol) ? userCol : "owner"; // FIX: allowlist of column names
        System.out.println("[DEFENDIDO] coluna fora da allowlist ('" + userCol + "') -> usa '" + safeCol + "' (default seguro)");
    }

    public static void main(String[] args) throws Exception {
        Connection c = db();
        tautology(c);
        unionBased(c);
        booleanBlind(c);
        secondOrder(c);
        orderByInjection(c);
    }
}

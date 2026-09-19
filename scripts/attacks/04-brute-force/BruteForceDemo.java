// Self-contained Brute Force deep-dive (CWE-307). JDK-only. Variants: vertical, spraying, stuffing.
// Reimplemented from OWASP Authentication guidance (see DEEP-DIVE.md). Run: java BruteForceDemo
import java.util.*;

public class BruteForceDemo {
    // Directory: user -> password
    static final Map<String, String> USERS = Map.of(
        "arthur", "correct-horse", "bob", "Winter2025!", "carol", "P@ssw0rd", "dave", "hunter2");
    // A small "known-breached passwords" list (like HaveIBeenPwned checks).
    static final Set<String> BREACHED = Set.of("P@ssw0rd", "hunter2", "123456", "password");

    static boolean check(String u, String p) { return USERS.getOrDefault(u, "\0").equals(p); }

    public static void main(String[] args) {
        // VARIANT 1: vertical brute force - one user, many passwords, no lockout
        System.out.println("[VARIANT] 1) Brute force vertical  (1 usuario, N senhas, sem lockout)");
        Map<String, Integer> fails = new HashMap<>();
        int tries = 0; boolean cracked = false;
        for (String guess : List.of("admin","123","letmein","correct-horse")) { tries++; if (check("arthur", guess)) { cracked = true; break; } }
        System.out.println("[VULNERAVEL] " + tries + " tentativas processadas, senha quebrada? " + cracked + "  (nada trava)");
        // FIX: lockout after N failures
        int lockTries = 0; boolean lockedOut = false;
        for (String guess : List.of("admin","123","letmein","correct-horse")) {
            if (fails.getOrDefault("arthur", 0) >= 3) { lockedOut = true; break; }
            lockTries++; if (!check("arthur", guess)) fails.merge("arthur", 1, Integer::sum);
        }
        System.out.println("[DEFENDIDO] lockout apos 3 -> travou na tentativa " + lockTries + "? " + lockedOut);

        // VARIANT 2: password spraying - one password, many users (beats per-account lockout!)
        System.out.println("[VARIANT] 2) Password spraying  (1 senha comum, N usuarios)");
        String spray = "Winter2025!"; List<String> hit = new ArrayList<>();
        for (String u : USERS.keySet()) if (check(u, spray)) hit.add(u);
        System.out.println("[VULNERAVEL] senha '" + spray + "' abriu contas: " + hit
                + "  (1 tentativa por usuario NAO dispara lockout por conta)");
        System.out.println("[DEFENDIDO] precisa de limite GLOBAL/por-IP + deteccao de spraying + MFA (lockout por conta nao basta)");

        // VARIANT 3: credential stuffing - reuse leaked pairs; defense = block breached passwords + MFA
        System.out.println("[VARIANT] 3) Credential stuffing  (pares vazados reusados)");
        System.out.println("[VULNERAVEL] par vazado (carol:P@ssw0rd) funciona? " + check("carol", "P@ssw0rd"));
        System.out.println("[DEFENDIDO] senha em lista de vazadas? bloquear no cadastro/login -> "
                + BREACHED.contains("P@ssw0rd") + "  (+ MFA neutraliza a reutilizacao)");
    }
}

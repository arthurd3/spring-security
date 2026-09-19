// Self-contained Username Enumeration deep-dive (CWE-204). Uses BCrypt (classpath) for a real timing gap.
// Reimplemented from OWASP WSTG / Authentication guidance (see DEEP-DIVE.md).
// Run: java -cp "$(cat scripts/lib/classpath.txt)" UserEnumerationDemo.java
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import java.util.*;

public class UserEnumerationDemo {
    static final BCryptPasswordEncoder ENC = new BCryptPasswordEncoder();
    static final Map<String, String> USERS = new HashMap<>();
    // A precomputed dummy hash so the "unknown user" path can spend the SAME time as a real check.
    static final String DUMMY_HASH = ENC.encode("dummy-password-for-timing");
    static { USERS.put("arthur", ENC.encode("password")); }
    static final Set<String> EMAILS = new HashSet<>(Set.of("arthur@example.com"));

    static long timeMillis(Runnable r) { long t = System.nanoTime(); r.run(); return (System.nanoTime() - t) / 1_000_000; }

    public static void main(String[] args) {
        // VARIANT 1: message difference on login
        System.out.println("[VARIANT] 1) Diferenca de mensagem (login)");
        System.out.println("[VULNERAVEL] user inexistente -> " + vulnLoginMsg("ghost", "x"));
        System.out.println("[VULNERAVEL] user existente    -> " + vulnLoginMsg("arthur", "x") + "  (as respostas se distinguem)");
        System.out.println("[DEFENDIDO] inexistente -> " + safeLoginMsg("ghost", "x") + " | existente -> " + safeLoginMsg("arthur", "x") + "  (identicos)");

        // VARIANT 2: timing side-channel
        System.out.println("[VARIANT] 2) Canal lateral por tempo");
        long tUnknownVuln = timeMillis(() -> vulnLoginMsg("ghost", "x"));   // returns fast (no hash)
        long tKnownVuln   = timeMillis(() -> vulnLoginMsg("arthur", "x"));  // runs bcrypt (slow)
        System.out.println("[VULNERAVEL] tempo inexistente=" + tUnknownVuln + "ms vs existente=" + tKnownVuln
                + "ms  (gap denuncia contas)");
        long tUnknownSafe = timeMillis(() -> safeLoginMsg("ghost", "x"));   // runs dummy bcrypt
        long tKnownSafe   = timeMillis(() -> safeLoginMsg("arthur", "x"));
        System.out.println("[DEFENDIDO] tempo inexistente=" + tUnknownSafe + "ms vs existente=" + tKnownSafe
                + "ms  (parecidos: sempre roda o hash)");

        // VARIANT 3: registration
        System.out.println("[VARIANT] 3) Cadastro");
        System.out.println("[VULNERAVEL] register(arthur@example.com) -> " + vulnRegister("arthur@example.com"));
        System.out.println("[DEFENDIDO] register(arthur@example.com)  -> " + safeRegister("arthur@example.com") + "  (mesma msg + email de verificacao)");

        // VARIANT 4: password reset
        System.out.println("[VARIANT] 4) Recuperacao de senha");
        System.out.println("[VULNERAVEL] reset(ghost@x.com) -> " + vulnReset("ghost@x.com"));
        System.out.println("[DEFENDIDO] reset(ghost@x.com)  -> " + safeReset("ghost@x.com") + "  (sempre a mesma resposta)");
    }

    // Vulnerable: reveals which usernames exist (message AND timing).
    static String vulnLoginMsg(String u, String p) {
        if (!USERS.containsKey(u)) return "404 No account with that username";
        return ENC.matches(p, USERS.get(u)) ? "200 Welcome" : "401 Wrong password";
    }
    // Safe: identical message and comparable time (always run a hash).
    static String safeLoginMsg(String u, String p) {
        String hash = USERS.getOrDefault(u, DUMMY_HASH);
        boolean ok = ENC.matches(p, hash) && USERS.containsKey(u);
        return ok ? "200 Welcome" : "401 Invalid credentials";
    }
    static String vulnRegister(String e) { return EMAILS.contains(e) ? "400 Email already registered" : "201 Created"; }
    static String safeRegister(String e) { return "200 If the email is valid, we sent a verification link"; }
    static String vulnReset(String e) { return EMAILS.contains(e) ? "200 Reset link sent" : "404 No such user"; }
    static String safeReset(String e) { return "200 If that email exists, a reset link was sent"; }
}

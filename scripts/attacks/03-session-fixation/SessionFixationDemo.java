// Self-contained Session Fixation deep-dive (CWE-384). JDK-only; a tiny in-memory session manager.
// Reimplemented from OWASP Session Management guidance (see DEEP-DIVE.md). Run: java SessionFixationDemo
import java.security.SecureRandom;
import java.util.*;

public class SessionFixationDemo {
    static final SecureRandom RNG = new SecureRandom();
    static String newId() { byte[] b = new byte[12]; RNG.nextBytes(b);
        StringBuilder s = new StringBuilder(); for (byte x : b) s.append(String.format("%02x", x)); return s.toString(); }

    // A session store: id -> authenticated user (null = anonymous session).
    static final Map<String, String> SESSIONS = new HashMap<>();

    public static void main(String[] args) {
        // VARIANT 1: keep vs rotate the id at login
        System.out.println("[VARIANT] 1) Rotacao no login  (fixacao classica)");
        String fixed = "ATTACKER-KNOWN-0001"; SESSIONS.put(fixed, null); // anon session the attacker planted
        String afterVuln = fixed; SESSIONS.put(afterVuln, "victim");     // BUG: login keeps the same id
        System.out.println("[VULNERAVEL] id apos login = " + afterVuln + (afterVuln.equals(fixed) ? "  (INALTERADO: atacante herda a sessao)" : ""));
        String afterSafe = newId(); SESSIONS.remove(fixed); SESSIONS.put(afterSafe, "victim"); // FIX: rotate
        System.out.println("[DEFENDIDO] id apos login = " + afterSafe.substring(0,12) + "...  (ROTACIONADO: id fixado inutil)");

        // VARIANT 2: accepting a session id supplied by the client (URL/param)
        System.out.println("[VARIANT] 2) Aceitar id vindo do cliente  (;jsessionid=... na URL)");
        String clientSupplied = "EVILFIXED-FROM-URL";
        // BUG: server trusts the client-provided id and creates a session with it
        SESSIONS.put(clientSupplied, "victim");
        System.out.println("[VULNERAVEL] servidor criou sessao com id do cliente? " + SESSIONS.containsKey(clientSupplied));
        // FIX: never trust a client id; always mint server-side (and drop unknown ids)
        String serverId = newId();
        boolean acceptsClientId = false; // safe server ignores client-supplied ids
        System.out.println("[DEFENDIDO] aceita id do cliente? " + acceptsClientId + "  (sempre gera no servidor: " + serverId.substring(0,12) + "...)");

        // VARIANT 3: no invalidation on logout
        System.out.println("[VARIANT] 3) Invalidacao no logout");
        String sid = newId(); SESSIONS.put(sid, "victim");
        // BUG: logout that forgets to invalidate leaves the id usable
        boolean stillValidVuln = SESSIONS.get(sid) != null; // (vuln: nothing removed)
        System.out.println("[VULNERAVEL] apos 'logout' sem invalidar, sessao ainda vale? " + stillValidVuln);
        SESSIONS.remove(sid); // FIX: invalidate on logout
        System.out.println("[DEFENDIDO] apos logout com invalidacao, sessao vale? " + (SESSIONS.get(sid) != null));
    }
}

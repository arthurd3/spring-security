// Self-contained Broken Access Control / IDOR deep-dive (CWE-639 / OWASP API1 BOLA). JDK-only.
// Reimplemented from OWASP Access Control guidance (see DEEP-DIVE.md). Run: java IdorDemo
import java.util.*;

public class IdorDemo {
    static final Map<Long, String> ACCOUNT_OWNER = Map.of(1L,"alice", 2L,"bob", 3L,"carol");
    // nested: document id -> owning account id
    static final Map<Long, Long> DOC_ACCOUNT = Map.of(100L,1L, 200L,2L);

    // BUG: fetch by id, no ownership check
    static String vulnRead(long id) { return "account " + id + " (owner=" + ACCOUNT_OWNER.get(id) + ", balance=9999)"; }
    // FIX: object-level authorization
    static String safeRead(long id, String caller, boolean admin) {
        if (!admin && !caller.equals(ACCOUNT_OWNER.get(id))) return "403 FORBIDDEN ('" + caller + "' nao e dono)";
        return "account " + id + " (owner=" + ACCOUNT_OWNER.get(id) + ")";
    }

    public static void main(String[] args) {
        // VARIANT 1: horizontal - read another user's object
        System.out.println("[VARIANT] 1) Horizontal  (bob le a conta de alice)");
        System.out.println("[VULNERAVEL] vulnRead(1) as bob -> " + vulnRead(1));
        System.out.println("[DEFENDIDO] safeRead(1, bob) -> " + safeRead(1, "bob", false));

        // VARIANT 2: vertical - reach an admin-only function
        System.out.println("[VARIANT] 2) Vertical  (usuario comum chama funcao de admin)");
        System.out.println("[VULNERAVEL] deleteAllAccounts() sem checar papel -> executado");
        boolean isAdmin = false;
        System.out.println("[DEFENDIDO] exige ROLE_ADMIN -> " + (isAdmin ? "executado" : "403 FORBIDDEN"));

        // VARIANT 3: mass enumeration via sequential ids
        System.out.println("[VARIANT] 3) Enumeracao  (ids sequenciais 1..N)");
        List<String> scraped = new ArrayList<>();
        for (long id = 1; id <= 3; id++) scraped.add(vulnRead(id));       // BUG: scrape everything
        System.out.println("[VULNERAVEL] varreu todos os ids -> " + scraped.size() + " contas raspadas");
        int allowed = 0; for (long id = 1; id <= 3; id++) if (safeRead(id, "bob", false).startsWith("account")) allowed++;
        System.out.println("[DEFENDIDO] varredura como bob -> so " + allowed + " conta acessivel (a dele)");
        System.out.println("[INFO] UUID no lugar de id sequencial DIFICULTA adivinhar, mas NAO e autorizacao");

        // VARIANT 4: nested resource IDOR - /accounts/{a}/docs/{d}
        System.out.println("[VARIANT] 4) Recurso aninhado  (/accounts/{a}/docs/{d})");
        long docId = 100, viaAccount = 2; // bob (account 2) pede doc 100 que pertence a account 1
        boolean vulnOk = DOC_ACCOUNT.containsKey(docId);                  // BUG: so checa se o doc existe
        System.out.println("[VULNERAVEL] doc " + docId + " via account " + viaAccount + " -> " + (vulnOk ? "entregue" : "404"));
        boolean owns = DOC_ACCOUNT.get(docId) == viaAccount;             // FIX: doc pertence ao account do caller?
        System.out.println("[DEFENDIDO] confere doc.account == caller.account -> " + (owns ? "entregue" : "403 FORBIDDEN"));
    }
}

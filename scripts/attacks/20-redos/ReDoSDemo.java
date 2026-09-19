// Self-contained ReDoS deep-dive (CWE-1333). JDK-only; runs regexes in a watched thread (no hangs).
// Reimplemented from Cloudflare 2019 postmortem / OWASP (see DEEP-DIVE.md). Run: java ReDoSDemo
import java.util.regex.Pattern;

public class ReDoSDemo {
    static final int MAX_LEN = 200;

    // Runs a match in a daemon thread; returns elapsed ms, or -1 if still running after budget.
    static long timedMatch(Pattern p, String input, long budgetMs) throws InterruptedException {
        Thread t = new Thread(() -> p.matcher(input).matches()); t.setDaemon(true);
        long start = System.currentTimeMillis(); t.start(); t.join(budgetMs);
        return t.isAlive() ? -1 : System.currentTimeMillis() - start;
    }

    // Safe validation: length cap + linear scan (no backtracking).
    static String safeCheck(String input) {
        if (input.length() > MAX_LEN) return "REJECTED: acima de " + MAX_LEN + " chars (length cap)";
        boolean allowed = input.chars().allMatch(c -> Character.isLetterOrDigit(c) || c=='@' || c=='.');
        return "match=" + allowed + " (linear, instantaneo)";
    }

    public static void main(String[] args) throws Exception {
        // VARIANT 1: bounded repetition of a greedy group - catastrophic even on modern JDK
        System.out.println("[VARIANT] 1) (.*a){20}  sobre 'aaaa...aX'");
        long v1 = timedMatch(Pattern.compile("(.*a){20}"), "a".repeat(28)+"X", 1200);
        System.out.println("[VULNERAVEL] " + (v1<0 ? "ainda rodando apos 1200ms (backtracking catastrofico)" : "terminou em "+v1+"ms"));
        System.out.println("[DEFENDIDO] safeCheck -> " + safeCheck("a".repeat(28)+"X"));

        // VARIANT 2: an evil "email-ish" pattern - also catastrophic
        System.out.println("[VARIANT] 2) (.*@){12}  regex 'de email' mal escrita");
        long v2 = timedMatch(Pattern.compile("(.*@){12}"), "@".repeat(30)+"X", 1200);
        System.out.println("[VULNERAVEL] " + (v2<0 ? "ainda rodando apos 1200ms" : "terminou em "+v2+"ms"));
        System.out.println("[DEFENDIDO] safeCheck -> " + safeCheck("@".repeat(30)+"X"));

        // VARIANT 3: engine dependence - the textbook (a+)+ is optimized away on JDK 21 (but not everywhere!)
        System.out.println("[VARIANT] 3) (a+)+$  (classico) - depende do motor");
        long v3 = timedMatch(Pattern.compile("(a+)+$"), "a".repeat(40)+"X", 1200);
        System.out.println("[INFO] (a+)+$ terminou em " + v3 + "ms neste JDK (otimizado); em outros motores/versoes EXPLODE");
        System.out.println("[DEFENDIDO] nao dependa do motor: escreva verificacao linear + length cap + timeout");

        // VARIANT 4: generic mitigation - run untrusted regex work under a timeout
        System.out.println("[VARIANT] 4) Mitigacao generica: timeout + length cap");
        System.out.println("[VULNERAVEL] input gigante (5000 chars) sem limite alimenta o motor");
        System.out.println("[DEFENDIDO] " + safeCheck("a".repeat(5000)) + "  (cortado antes de qualquer regex)");
    }
}

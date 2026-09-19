// Self-contained SpEL / SSTI deep-dive (CWE-917). Uses Spring Expression (classpath).
// Reimplemented from Spring4Shell analyses & java-sec-code (see DEEP-DIVE.md).
// Run: java -cp "$(cat scripts/lib/classpath.txt)" SpelDemo.java
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;

public class SpelDemo {
    static final SpelExpressionParser P = new SpelExpressionParser();

    // BUG: evaluates user input with the FULL context (type refs, methods, constructors allowed).
    static Object vulnEval(String expr) { return P.parseExpression(expr).getValue(); }
    // FIX (primary): do NOT evaluate user input - treat it as text.
    static String safeText(String s) { return "Hello, " + s + "!"; }
    // FIX (when you MUST evaluate): SimpleEvaluationContext forbids T()/constructors/most methods.
    static Object safeEval(String expr) {
        EvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        return P.parseExpression(expr).getValue(ctx);
    }

    public static void main(String[] args) {
        // VARIANT 1: arithmetic eval - proves input runs as code
        System.out.println("[VARIANT] 1) Avaliacao basica  (7*7 -> 49)");
        System.out.println("[VULNERAVEL] vulnEval(\"7*7\") -> " + vulnEval("7*7"));
        System.out.println("[DEFENDIDO] safeText(\"7*7\") -> " + safeText("7*7") + "  (texto literal)");

        // VARIANT 2: type access leaks server data - real-world: SpEL info disclosure
        System.out.println("[VARIANT] 2) Acesso a tipos  T(java.lang.System)");
        System.out.println("[VULNERAVEL] user.name -> " + vulnEval("T(java.lang.System).getProperty('user.name')"));
        try { safeEval("T(java.lang.System).getProperty('user.name')"); }
        catch (Exception e) { System.out.println("[DEFENDIDO] SimpleEvaluationContext -> BLOQUEADO (" + e.getClass().getSimpleName() + ": sem T())"); }

        // VARIANT 3: RCE - run a real OS command through the expression
        System.out.println("[VARIANT] 3) RCE  (executa comando do SO via expressao)");
        String rce = "new java.util.Scanner(T(java.lang.Runtime).getRuntime()"
                + ".exec(new String[]{'echo','RCE-via-SpEL'}).getInputStream()).nextLine()";
        System.out.println("[VULNERAVEL] Runtime.exec -> " + vulnEval(rce));
        System.out.println("[DEFENDIDO] safeText -> " + safeText("<expr>") + "  (nunca avaliado)");

        // VARIANT 4: blacklist bypass - blocking "Runtime" is not enough (ProcessBuilder also works)
        System.out.println("[VARIANT] 4) Bypass de blacklist  (bloquear 'Runtime' nao basta)");
        String payload = "new java.lang.ProcessBuilder(new String[]{'echo','bypass'}).start().class.name";
        String naive = payload.contains("Runtime") ? "<blocked>" : payload; // naive filter only blocks Runtime
        System.out.println("[VULNERAVEL] filtro so bloqueia 'Runtime' -> executou ProcessBuilder: " + vulnEval(naive));
        System.out.println("[DEFENDIDO] nao avaliar (ou SimpleEvaluationContext) -> input tratado como dado");
    }
}

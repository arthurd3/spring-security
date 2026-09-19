// Self-contained OS Command Injection deep-dive (CWE-78). Pure JDK. Each VARIANT is a real technique.
// Reimplemented from OWASP WebGoat / PayloadsAllTheThings (see DEEP-DIVE.md). Run: java CommandInjectionDemo
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class CommandInjectionDemo {

    // Runs "echo pinging <host>" through a shell (the BUG: a shell parses metacharacters).
    static String vulnShell(String host) throws Exception {
        Process p = new ProcessBuilder("sh", "-c", "echo pinging " + host).start();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            return r.lines().collect(Collectors.joining(" | "));
        }
    }
    // FIX: strict allowlist; a real impl would also use an argument list (no shell) instead of sh -c.
    private static final Pattern SAFE_HOST = Pattern.compile("^[a-zA-Z0-9.-]{1,253}$");
    static String safePing(String host) {
        return SAFE_HOST.matcher(host).matches() ? "OK: '" + host + "' accepted (no shell)" : "REJECTED (400)";
    }

    public static void main(String[] args) throws Exception {
        // VARIANT 1: separator ';' - real-world: Shellshock-era CGI, countless appliance RCEs
        System.out.println("[VARIANT] 1) Separador ';'  (roda um segundo comando)");
        System.out.println("[VULNERAVEL] host='x; echo PWNED' -> " + vulnShell("x; echo PWNED"));
        System.out.println("[DEFENDIDO] safePing -> " + safePing("x; echo PWNED"));

        // VARIANT 2: command substitution $(...) - real-world: PayloadsAllTheThings command injection
        System.out.println("[VARIANT] 2) Substituicao $(...)  (executa e injeta a saida)");
        System.out.println("[VULNERAVEL] host='$(echo SUBST)' -> " + vulnShell("$(echo SUBST)"));
        System.out.println("[DEFENDIDO] safePing -> " + safePing("$(echo SUBST)"));

        // VARIANT 3: pipe '|' - chains another program
        System.out.println("[VARIANT] 3) Pipe '|'  (encadeia outro programa)");
        System.out.println("[VULNERAVEL] host='localhost | echo PIPED' -> " + vulnShell("localhost | echo PIPED"));
        System.out.println("[DEFENDIDO] safePing -> " + safePing("localhost | echo PIPED"));

        // VARIANT 4: blind/time-based - no output? measure the delay of an injected sleep
        System.out.println("[VARIANT] 4) Blind por tempo  (sem saida: mede o atraso)");
        long t0 = System.currentTimeMillis();
        vulnShell("localhost; sleep 1");
        long ms = System.currentTimeMillis() - t0;
        System.out.println("[VULNERAVEL] host='x; sleep 1' -> resposta em " + ms + "ms (injecao confirmada por atraso)");
        System.out.println("[DEFENDIDO] safePing -> " + safePing("x; sleep 1"));

        // VARIANT 5: naive blacklist bypass - blocking ';' is not enough
        System.out.println("[VARIANT] 5) Bypass de blacklist  (bloquear ';' nao basta)");
        String naiveFiltered = "x | echo BYPASS".replace(";", ""); // a naive filter only strips ';'
        System.out.println("[VULNERAVEL] blacklist so remove ';' -> " + vulnShell(naiveFiltered) + "  ('|' passou)");
        System.out.println("[DEFENDIDO] allowlist recusa qualquer metacaractere -> " + safePing("x | echo BYPASS"));
    }
}

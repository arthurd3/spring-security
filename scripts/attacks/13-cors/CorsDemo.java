// Self-contained CORS Misconfiguration deep-dive (CWE-942). JDK-only.
// Reimplemented from PortSwigger CORS / OWASP (see DEEP-DIVE.md). Run: java CorsDemo
import java.util.List;

public class CorsDemo {
    static final List<String> ALLOWED = List.of("https://app.trusted.com"); // exact origins

    // Vulnerable strategies:
    static String reflect(String origin){ return "ACAO:" + origin + " | ACAC:true"; }                 // reflect + creds
    static String allowNull(String origin){ return origin.equals("null") ? "ACAO:null | ACAC:true" : reflect(origin); }
    static boolean naiveEndsWith(String o){ return o.endsWith("trusted.com"); }                         // BUG
    static boolean naiveStartsWith(String o){ return o.startsWith("https://app.trusted.com"); }          // BUG
    // Safe: exact allowlist match, never reflect, never null.
    static String safe(String origin){ return ALLOWED.contains(origin) ? "ACAO:" + origin : "(sem ACAO -> navegador bloqueia)"; }

    public static void main(String[] args) {
        // VARIANT 1: reflect any origin + credentials
        System.out.println("[VARIANT] 1) Refletir origin + credenciais");
        System.out.println("[VULNERAVEL] Origin: https://evil.example -> " + reflect("https://evil.example"));
        System.out.println("[DEFENDIDO] " + safe("https://evil.example"));

        // VARIANT 2: null origin allowed (sandboxed iframe, redirects, file://)
        System.out.println("[VARIANT] 2) Origin 'null' permitido");
        System.out.println("[VULNERAVEL] Origin: null -> " + allowNull("null") + "  (iframe sandbox/redirect forjam 'null')");
        System.out.println("[DEFENDIDO] " + safe("null"));

        // VARIANT 3: naive suffix/prefix match bypass
        System.out.println("[VARIANT] 3) Bypass de regex ingenua (endsWith/startsWith)");
        System.out.println("[VULNERAVEL] endsWith('trusted.com') aceita https://nottrusted.com? " + naiveEndsWith("https://nottrusted.com"));
        System.out.println("[VULNERAVEL] startsWith('https://app.trusted.com') aceita ...trusted.com.evil.com? "
                + naiveStartsWith("https://app.trusted.com.evil.com"));
        System.out.println("[DEFENDIDO] match EXATO -> nottrusted.com=" + safe("https://nottrusted.com")
                + " ; sub.evil=" + safe("https://app.trusted.com.evil.com"));

        // VARIANT 4: trusting Origin/Referer for authorization
        System.out.println("[VARIANT] 4) Confiar no Origin p/ autorizacao");
        System.out.println("[VULNERAVEL] 'se Origin==app.trusted.com entao admin' -> Origin e spoofavel fora do navegador (curl)");
        System.out.println("[DEFENDIDO] CORS controla LEITURA cross-origin; autorizacao vem de sessao/token no servidor");

        // legit
        System.out.println("[VARIANT] 5) Uso legitimo");
        System.out.println("[DEFENDIDO] Origin: https://app.trusted.com -> " + safe("https://app.trusted.com"));
    }
}

// Self-contained Open Redirect deep-dive (CWE-601). JDK-only. Shows naive checks and their bypasses.
// Reimplemented from PortSwigger / PayloadsAllTheThings (see DEEP-DIVE.md). Run: java OpenRedirectDemo
import java.net.URI;
import java.util.List;
import java.util.Locale;

public class OpenRedirectDemo {
    static final List<String> ALLOWED_HOSTS = List.of("trusted.com");

    // Naive checks (all bypassable):
    static boolean naiveStartsWithSlash(String t) { return t.startsWith("/"); }          // //evil, /\evil pass
    static boolean naiveContainsHost(String t) { return t.contains("trusted.com"); }      // trusted.com.evil.com passes
    // Robust check: relative path only, or absolute URL whose PARSED host is allowlisted.
    static boolean safe(String t) {
        if (t == null || t.isBlank()) return false;
        for (int i = 0; i < t.length(); i++) if (Character.isISOControl(t.charAt(i))) return false;
        String n = t.replace('\\', '/');
        if (n.startsWith("/")) return !n.startsWith("//");
        try {
            URI u = new URI(t);
            if (u.getHost() == null || !u.isAbsolute()) return false;
            String scheme = u.getScheme().toLowerCase(Locale.ROOT);
            if (!scheme.equals("http") && !scheme.equals("https")) return false;
            return ALLOWED_HOSTS.contains(u.getHost().toLowerCase(Locale.ROOT));
        } catch (Exception e) { return false; }
    }

    static void variant(String name, String payload) {
        System.out.println("[VARIANT] " + name + "   payload: " + payload);
        System.out.println("[VULNERAVEL] naive startsWith('/')=" + naiveStartsWithSlash(payload)
                + "  naive contains('trusted.com')=" + naiveContainsHost(payload) + "  (um deles deixa passar)");
        System.out.println("[DEFENDIDO] safe() -> " + (safe(payload) ? "PERMITIDO" : "400 BLOQUEADO"));
    }

    public static void main(String[] args) {
        variant("1) Absoluto off-site", "https://evil.example/login");
        variant("2) Protocolo-relativo //host", "//evil.example");
        variant("3) Backslash \\\\host", "/\\evil.example");
        variant("4) Bypass por userinfo @", "https://trusted.com@evil.example");
        variant("5) Bypass por subdominio", "https://trusted.com.evil.example");
        System.out.println("[VARIANT] 6) Uso legitimo (caminho relativo)");
        System.out.println("[DEFENDIDO] safe(\"/dashboard\") -> " + (safe("/dashboard") ? "PERMITIDO" : "BLOQUEADO"));
        System.out.println("[DEFENDIDO] safe(\"https://trusted.com/x\") -> " + (safe("https://trusted.com/x") ? "PERMITIDO" : "BLOQUEADO"));
    }
}

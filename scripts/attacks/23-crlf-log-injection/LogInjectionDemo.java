// Self-contained CRLF Injection deep-dive (CWE-117 log injection / CWE-113 response splitting). JDK-only.
// Reimplemented from OWASP Log Injection / HTTP Response Splitting (see DEEP-DIVE.md). Run: java LogInjectionDemo
public class LogInjectionDemo {

    // FIX: strip CR/LF/tab/control chars before using the value in a log line or header.
    static String sanitize(String s) { return s.replaceAll("[\\r\\n\\t\\p{Cntrl}]", "_"); }

    static void showLines(String tag, String s) {
        String[] ls = s.split("\n", -1);
        System.out.println(tag + (ls.length > 1 ? " => " + ls.length + " linhas:" : " => 1 linha:"));
        for (String l : ls) System.out.println("        LOG| " + l);
    }

    public static void main(String[] args) {
        // VARIANT 1: log forging - a newline injects a whole fake log entry
        System.out.println("[VARIANT] 1) Log forging  (uma nova linha cria uma entrada de log falsa)");
        String user = "mallory\nINFO [auth] user=admin login=SUCCESS from=10.0.0.1";
        System.out.println("[VULNERAVEL] log cru:");
        showLines("           ", "login attempt user=" + user);       // BUG: raw
        System.out.println("[DEFENDIDO] log sanitizado:");
        showLines("           ", "login attempt user=" + sanitize(user)); // FIX

        // VARIANT 2: HTTP response splitting - CRLF in a header value injects a new header/body
        System.out.println("[VARIANT] 2) HTTP response splitting  (CRLF injeta header/corpo)");
        String next = "/dashboard\r\nSet-Cookie: role=admin\r\n\r\n<html>phish</html>";
        String vuln = "HTTP/1.1 302 Found\r\nLocation: " + next;      // BUG: raw into headers
        System.out.println("[VULNERAVEL] resposta forjada tem " + vuln.split("\r\n").length
                + " linhas de cabecalho (Set-Cookie e corpo injetados):");
        for (String l : vuln.split("\r\n")) System.out.println("        HTTP| " + l);
        String safe = "HTTP/1.1 302 Found\r\nLocation: " + sanitize(next);
        System.out.println("[DEFENDIDO] Location sanitizado -> " + safe.replace("\r\n", " <CRLF> "));

        // VARIANT 3: other control chars (bare \r, tab) also break log parsers/terminals
        System.out.println("[VARIANT] 3) Outros controles  (\\r isolado, tab)");
        String tricky = "user\r\radmin\tFAKE";
        System.out.println("[VULNERAVEL] contem controles? " + tricky.chars().anyMatch(Character::isISOControl));
        System.out.println("[DEFENDIDO] sanitizado -> " + sanitize(tricky));
    }
}

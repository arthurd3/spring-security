// Self-contained CSRF deep-dive (CWE-352). JDK-only; models the server-side checks that stop forgery.
// Reimplemented from OWASP CSRF Prevention (see DEEP-DIVE.md). Run: java CsrfDemo
public class CsrfDemo {
    static final String SESSION_TOKEN = "s3cr3t-per-session-csrf-token"; // the legit page embeds this

    // Vulnerable: state changes with no anti-CSRF check.
    static String vulnStateChange(String httpMethod, String token) { return "EXECUTED (" + httpMethod + ", token=" + token + ")"; }
    // Defense A: synchronizer token - reject if missing/wrong.
    static String safeSynchronizer(String token) { return SESSION_TOKEN.equals(token) ? "EXECUTED" : "403 FORBIDDEN (token CSRF invalido)"; }
    // Defense B: double-submit cookie - cookie token must equal header/body token.
    static String safeDoubleSubmit(String cookieTok, String headerTok) {
        return cookieTok != null && cookieTok.equals(headerTok) ? "EXECUTED" : "403 FORBIDDEN (double-submit nao confere)"; }
    // Defense C: SameSite cookie - on a cross-site request the browser does NOT attach the cookie.
    static boolean cookieSentCrossSite(String sameSite, boolean crossSite) { return !crossSite || sameSite.equalsIgnoreCase("None"); }

    public static void main(String[] args) {
        // VARIANT 1: GET-based state change (a mere <img src> forges it)
        System.out.println("[VARIANT] 1) Mudanca de estado via GET");
        System.out.println("[VULNERAVEL] GET /transfer?to=attacker (basta um <img src>) -> " + vulnStateChange("GET", null));
        System.out.println("[DEFENDIDO] mudancas so via POST + token; GET e seguro/idempotente");

        // VARIANT 2: POST without token
        System.out.println("[VARIANT] 2) POST sem token");
        System.out.println("[VULNERAVEL] POST /transfer sem token -> " + vulnStateChange("POST", null));
        System.out.println("[DEFENDIDO] synchronizer token -> " + safeSynchronizer(null) + " | com token -> " + safeSynchronizer(SESSION_TOKEN));

        // VARIANT 3: JSON / simple-request bypass (no preflight if content-type is text/plain)
        System.out.println("[VARIANT] 3) 'Simple request' (text/plain evita preflight CORS)");
        System.out.println("[VULNERAVEL] form auto-submit com enctype=text/plain envia JSON sem preflight -> aceito se nao checar token");
        System.out.println("[DEFENDIDO] exigir token CSRF (e/ou Content-Type application/json + checagem) -> " + safeSynchronizer(null));

        // VARIANT 4: double-submit cookie
        System.out.println("[VARIANT] 4) Double-submit cookie");
        System.out.println("[VULNERAVEL] atacante nao le o cookie (SOP) mas tambem nao envia o header casado -> " + safeDoubleSubmit("tokA", null));
        System.out.println("[DEFENDIDO] pagina legitima envia cookie==header -> " + safeDoubleSubmit("tokA", "tokA"));

        // VARIANT 5: SameSite cookie
        System.out.println("[VARIANT] 5) Cookie SameSite");
        System.out.println("[VULNERAVEL] SameSite=None cross-site -> cookie enviado? " + cookieSentCrossSite("None", true) + " (CSRF possivel)");
        System.out.println("[DEFENDIDO] SameSite=Lax/Strict cross-site -> cookie enviado? " + cookieSentCrossSite("Lax", true) + " (sem cookie, sem CSRF)");

        // VARIANT 6: login CSRF
        System.out.println("[VARIANT] 6) Login CSRF");
        System.out.println("[VULNERAVEL] forcar a vitima a logar na CONTA DO ATACANTE (dados da vitima vao p/ o atacante)");
        System.out.println("[DEFENDIDO] token CSRF tambem no formulario de LOGIN -> " + safeSynchronizer(null));
    }
}

// Self-contained XSS deep-dive (CWE-79). JDK-only. Reflected/stored + context-aware encoding + CSP.
// Reimplemented from OWASP XSS Prevention Cheat Sheet (see DEEP-DIVE.md). Run: java XssDemo
import java.util.*;

public class XssDemo {
    // Context-aware encoders (the core lesson: the right encoding depends on WHERE output lands).
    static String htmlEscape(String s){ return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
            .replace("\"","&quot;").replace("'","&#39;"); }
    static String attrEscape(String s){ return htmlEscape(s); } // plus: always quote the attribute
    static String jsEscape(String s){ StringBuilder b=new StringBuilder(); for(char c: s.toCharArray())
            b.append(c<128 && !Character.isLetterOrDigit(c) ? String.format("\\u%04x", (int)c) : c); return b.toString(); }

    static final List<String> store = new ArrayList<>(); // toy "database" for stored XSS

    public static void main(String[] args) {
        String payload = "<script>alert(document.cookie)</script>";

        // VARIANT 1: reflected, HTML body context
        System.out.println("[VARIANT] 1) Refletido (contexto HTML)");
        System.out.println("[VULNERAVEL] <div>Ola " + payload + "</div>  (script executa)");
        System.out.println("[DEFENDIDO] <div>Ola " + htmlEscape(payload) + "</div>  (texto inerte)");

        // VARIANT 2: stored (persisted then served to everyone)
        System.out.println("[VARIANT] 2) Armazenado (persistido e servido a todos)");
        store.add(payload);                                   // BUG: raw persisted
        System.out.println("[VULNERAVEL] comentario servido -> <li>" + store.get(0) + "</li>  (afeta todo visitante)");
        System.out.println("[DEFENDIDO] servido escapado -> <li>" + htmlEscape(store.get(0)) + "</li>");

        // VARIANT 3: attribute context (breaking out of an attribute)
        System.out.println("[VARIANT] 3) Contexto de atributo");
        String attr = "\" onmouseover=alert(1) x=\"";
        System.out.println("[VULNERAVEL] <input value=\"" + attr + "\">  (quebra o atributo -> onmouseover)");
        System.out.println("[DEFENDIDO] <input value=\"" + attrEscape(attr) + "\">  (aspas neutralizadas)");

        // VARIANT 4: JavaScript context (inside a <script> string)
        System.out.println("[VARIANT] 4) Contexto JavaScript");
        String js = "';alert(1);//";
        System.out.println("[VULNERAVEL] <script>var u='" + js + "';</script>  (fecha a string -> executa)");
        System.out.println("[DEFENDIDO] <script>var u='" + jsEscape(js) + "';</script>  (encoding \\uXXXX)");

        // VARIANT 5: defense-in-depth headers (CSP / nosniff)
        System.out.println("[VARIANT] 5) Camada extra: cabecalhos");
        System.out.println("[DEFENDIDO] Content-Security-Policy: default-src 'self'; script-src 'self'  (barra inline)");
        System.out.println("[DEFENDIDO] X-Content-Type-Options: nosniff  (nao adivinha tipo)");
    }
}

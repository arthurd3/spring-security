// Self-contained Host Header Injection deep-dive (CWE-644). JDK-only.
// Reimplemented from PortSwigger Host header attacks (see DEEP-DIVE.md). Run: java HostHeaderDemo
import java.util.*;

public class HostHeaderDemo {
    static final String CONFIGURED_BASE = "https://myapp.example";      // trusted, server-side config
    static final Map<String, String> cache = new HashMap<>();          // toy web cache

    // BUG variants: build security-relevant URLs from client-controlled headers.
    static String vulnResetLink(String user, String host) { return "http://" + host + "/reset?token=T-" + user; }
    static String vulnLinkXFH(String user, Map<String,String> headers) {
        String host = headers.getOrDefault("X-Forwarded-Host", headers.get("Host"));
        return "http://" + host + "/reset?token=T-" + user;
    }
    // FIX: always use the configured base URL; ignore Host/X-Forwarded-Host.
    static String safeResetLink(String user) { return CONFIGURED_BASE + "/reset?token=T-" + user; }

    public static void main(String[] args) {
        // VARIANT 1: password reset poisoning via Host
        System.out.println("[VARIANT] 1) Reset poisoning (Host)");
        System.out.println("[VULNERAVEL] Host: evil.example -> " + vulnResetLink("alice", "evil.example"));
        System.out.println("[DEFENDIDO] base configurada -> " + safeResetLink("alice"));

        // VARIANT 2: X-Forwarded-Host override
        System.out.println("[VARIANT] 2) Override via X-Forwarded-Host");
        Map<String,String> h = new HashMap<>(); h.put("Host", "myapp.example"); h.put("X-Forwarded-Host", "evil.example");
        System.out.println("[VULNERAVEL] Host bom, XFH malicioso -> " + vulnLinkXFH("alice", h) + "  (XFH venceu)");
        System.out.println("[DEFENDIDO] ignora XFH, usa base configurada -> " + safeResetLink("alice"));

        // VARIANT 3: web cache poisoning (reflected, unkeyed header)
        System.out.println("[VARIANT] 3) Cache poisoning (header refletido nao-chaveado)");
        // The cache key is only the path; the response reflects Host -> one attacker poisons everyone.
        String key = "/home";
        cache.put(key, "<link href=http://evil.example/x.css>"); // attacker's request cached under /home
        System.out.println("[VULNERAVEL] resposta em cache p/ " + key + " -> " + cache.get(key) + "  (serve a todos)");
        System.out.println("[DEFENDIDO] nao refletir Host em conteudo cacheavel; incluir Host na chave / usar base fixa");

        // VARIANT 4: routing/absolute-URL from Host (SSRF-ish, auth bypass)
        System.out.println("[VARIANT] 4) Roteamento por Host absoluto");
        System.out.println("[VULNERAVEL] confiar no Host p/ decidir tenant/backend -> spoof troca de contexto");
        System.out.println("[DEFENDIDO] validar Host contra allowlist de dominios conhecidos; base fixa p/ links");
    }
}

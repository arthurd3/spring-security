// Self-contained SSRF deep-dive (CWE-918). JDK-only; loopback HttpServer stands in for internal services.
// Reimplemented from OWASP SSRF Prevention / Capital One analyses (see DEEP-DIVE.md). Run: java SsrfDemo
import com.sun.net.httpserver.HttpServer;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.List;
import java.util.Locale;

public class SsrfDemo {
    static final List<String> ALLOWED_HOSTS = List.of("api.partner.example");

    // BUG: fetch any URL, any scheme, follow redirects.
    static String vulnFetch(String url) throws Exception {
        HttpURLConnection.setFollowRedirects(true);
        URLConnection c = URI.create(url).toURL().openConnection();
        try (InputStream in = c.getInputStream()) { return new String(in.readAllBytes(), StandardCharsets.UTF_8).trim(); }
    }
    // FIX: scheme allowlist + host allowlist + resolved-address check + no redirects.
    static String safeFetch(String url) {
        try {
            URI u = new URI(url);
            String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
            if (!scheme.equals("http") && !scheme.equals("https")) return "400: scheme '" + scheme + "' nao permitido";
            String host = u.getHost();
            if (host == null || !ALLOWED_HOSTS.contains(host.toLowerCase(Locale.ROOT))) return "400: host fora da allowlist";
            for (InetAddress a : InetAddress.getAllByName(host))
                if (a.isLoopbackAddress()||a.isSiteLocalAddress()||a.isLinkLocalAddress()||a.isAnyLocalAddress())
                    return "400: host resolve p/ endereco interno (DNS rebinding barrado)";
            // (a real impl would also connect with redirects disabled)
            return "would fetch " + url;
        } catch (Exception e) { return "400: " + e.getMessage(); }
    }

    static HttpServer server(String path, String body, int redirectTo) throws Exception {
        HttpServer s = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        s.createContext(path, ex -> {
            byte[] b = body.getBytes(StandardCharsets.UTF_8);
            if (redirectTo > 0) { ex.getResponseHeaders().add("Location", "http://127.0.0.1:" + redirectTo + "/secret"); ex.sendResponseHeaders(302, -1); }
            else { ex.sendResponseHeaders(200, b.length); try (OutputStream o = ex.getResponseBody()) { o.write(b); } }
            ex.close();
        });
        s.start(); return s;
    }

    public static void main(String[] args) throws Exception {
        // VARIANT 1: file:// arbitrary file read
        System.out.println("[VARIANT] 1) file://  (leitura arbitraria de arquivo)");
        Path secret = Files.createTempFile("ssrf", ".txt"); Files.writeString(secret, "INTERNAL-CREDENTIAL");
        System.out.println("[VULNERAVEL] vulnFetch(file://secret) -> " + vulnFetch(secret.toUri().toString()));
        System.out.println("[DEFENDIDO] safeFetch(file://secret) -> " + safeFetch(secret.toUri().toString()));

        // VARIANT 2: reach an internal service (stands in for cloud metadata 169.254.169.254)
        System.out.println("[VARIANT] 2) Servico interno / metadata da nuvem (169.254.169.254)");
        HttpServer internal = server("/secret", "IAM-CREDENTIALS", 0);
        String iurl = "http://127.0.0.1:" + internal.getAddress().getPort() + "/secret";
        System.out.println("[VULNERAVEL] vulnFetch(" + iurl + ") -> " + vulnFetch(iurl));
        System.out.println("[DEFENDIDO] safeFetch(http://169.254.169.254/latest/meta-data/) -> " + safeFetch("http://169.254.169.254/latest/meta-data/"));
        internal.stop(0);

        // VARIANT 3: DNS rebinding - an allowlisted name that resolves to an internal address
        System.out.println("[VARIANT] 3) DNS rebinding  (host permitido resolve p/ interno)");
        System.out.println("[VULNERAVEL] allowlist so por NOME: 'localhost' passa e aponta p/ 127.0.0.1");
        System.out.println("[DEFENDIDO] safeFetch(http://localhost/) -> " + safeFetch("http://localhost/") + "  (checa o endereco resolvido)");

        // VARIANT 4: redirect bypass - allowlisted host 302 -> internal
        System.out.println("[VARIANT] 4) Bypass por redirect  (host permitido -> 302 -> interno)");
        HttpServer target = server("/secret", "REDIR-INTERNAL", 0);
        HttpServer redirector = server("/go", "", target.getAddress().getPort());
        String rurl = "http://127.0.0.1:" + redirector.getAddress().getPort() + "/go";
        System.out.println("[VULNERAVEL] segue o 302 -> " + vulnFetch(rurl));
        System.out.println("[DEFENDIDO] desabilitar redirects (e revalidar cada hop) -> destino interno nunca alcancado");
        redirector.stop(0); target.stop(0);
    }
}

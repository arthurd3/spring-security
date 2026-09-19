package com.arthur.security.insecure;

import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.StringReader;

/**
 * Deliberately INSECURE: builds an XPath query by string concatenation (CWE-643 - XPath injection).
 * Hardened counterpart: {@code /api/xlogin}.
 *
 * <p>{@code //user[name='<user>' and pass='<pass>']} - a payload of {@code pass=' or '1'='1} closes the
 * literal and turns the predicate into always-true, matching every user: authentication bypass.
 */
@RestController
@Profile("insecure")
public class VulnerableXpathLoginController {

    private static final String USERS_XML = """
            <users>
              <user><name>arthur</name><pass>password</pass></user>
              <user><name>admin</name><pass>admin-secret</pass></user>
            </users>
            """;

    @GetMapping("/vulnerable/xlogin")
    public String login(@RequestParam String user, @RequestParam String pass) throws Exception {
        Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder()
                .parse(new InputSource(new StringReader(USERS_XML)));
        XPath xpath = XPathFactory.newInstance().newXPath();
        // BUG: user/pass concatenated straight into the query.
        String query = "//user[name='" + user + "' and pass='" + pass + "']";
        NodeList nodes = (NodeList) xpath.evaluate(query, doc, XPathConstants.NODESET);
        return nodes.getLength() > 0 ? "authenticated" : "denied";
    }
}

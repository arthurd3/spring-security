package com.arthur.security.attacks.xxe;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.StringReader;

/**
 * A deliberately INSECURE XML parser that resolves DTDs and external entities (OWASP A05:2021,
 * CWE-611 - XML External Entity).
 *
 * <p>The features are set explicitly here so the demo is deterministic across JDKs, but they are
 * close to what a default {@link DocumentBuilderFactory} gives you: XXE is the classic case of an
 * insecure <i>default</i>, not of a developer switching protection off.
 *
 * <p>Once the parser resolves {@code SYSTEM "file:///..."}, any endpoint that echoes parsed content
 * becomes an arbitrary-file-read. The same primitive reaches internal HTTP services (XXE-to-SSRF),
 * and nested entity definitions turn it into a denial of service ("billion laughs").
 *
 * <p>This is a plain class with no stereotype annotation, so component scanning ignores it outright.
 */
class VulnerableXmlParser {

    String parseRootText(String xml) throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

        // BUG: every one of these is the wrong answer for untrusted input.
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", true);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", true);
        factory.setExpandEntityReferences(true);

        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));
        return document.getDocumentElement().getTextContent();
    }
}

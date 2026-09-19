package com.arthur.security.insecure;

import org.springframework.context.annotation.Profile;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;

/**
 * Deliberately INSECURE: parses XML with DTDs and external entities enabled (CWE-611, XXE).
 * Hardened counterpart: {@code /api/xml/parse}.
 */
@RestController
@Profile("insecure")
public class VulnerableXmlController {

    @PostMapping(value = "/vulnerable/xml/parse", consumes = MediaType.APPLICATION_XML_VALUE,
            produces = MediaType.TEXT_PLAIN_VALUE)
    public String parse(@RequestBody String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // BUG: external entities left enabled.
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", true);
        factory.setExpandEntityReferences(true);
        Document doc = factory.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
        return doc.getDocumentElement().getTextContent();
    }
}

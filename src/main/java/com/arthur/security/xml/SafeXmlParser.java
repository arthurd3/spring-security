package com.arthur.security.xml;

import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.StringReader;

/**
 * Parses XML with external entities and DTDs switched off - the fix for XXE (OWASP A05:2021, CWE-611).
 *
 * <p>A default {@link DocumentBuilderFactory} will happily resolve a {@code <!DOCTYPE>} that declares
 * an external entity, so {@code <!ENTITY xxe SYSTEM "file:///etc/passwd">} makes the parser read a
 * local file and splice its contents into the document the application then echoes back. The same
 * primitive reaches internal HTTP endpoints (XXE-to-SSRF) and can be turned into a denial of service
 * with nested entities ("billion laughs").
 *
 * <p>{@code disallow-doctype-decl} is the single most effective switch: with it the parser throws on
 * any DOCTYPE at all, so no entity can be declared in the first place. The remaining features are
 * belt-and-braces for parsers that do not honour it.
 */
@Service
public class SafeXmlParser {

    private static final String DISALLOW_DOCTYPE = "http://apache.org/xml/features/disallow-doctype-decl";
    private static final String EXTERNAL_GENERAL_ENTITIES = "http://xml.org/sax/features/external-general-entities";
    private static final String EXTERNAL_PARAMETER_ENTITIES = "http://xml.org/sax/features/external-parameter-entities";
    private static final String LOAD_EXTERNAL_DTD = "http://apache.org/xml/features/nonvalidating/load-external-dtd";

    /**
     * @throws SAXException when the document is malformed <i>or</i> declares a DOCTYPE - which is what
     *                      every XXE payload must do
     */
    public Document parse(String xml) throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature(DISALLOW_DOCTYPE, true);
        factory.setFeature(EXTERNAL_GENERAL_ENTITIES, false);
        factory.setFeature(EXTERNAL_PARAMETER_ENTITIES, false);
        factory.setFeature(LOAD_EXTERNAL_DTD, false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        setIfSupported(factory, XMLConstants.ACCESS_EXTERNAL_DTD);
        setIfSupported(factory, XMLConstants.ACCESS_EXTERNAL_SCHEMA);

        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new InputSource(new StringReader(xml)));
    }

    /** Returns the text of the document's root element, which is what the demo endpoint echoes. */
    public String rootText(String xml) throws ParserConfigurationException, SAXException, IOException {
        return parse(xml).getDocumentElement().getTextContent();
    }

    /** Not every implementation knows these properties; an unsupported one is not a security gap. */
    private static void setIfSupported(DocumentBuilderFactory factory, String property) {
        try {
            factory.setAttribute(property, "");
        } catch (IllegalArgumentException ignored) {
            // Parser does not recognise the property - the feature flags above already cover us.
        }
    }
}

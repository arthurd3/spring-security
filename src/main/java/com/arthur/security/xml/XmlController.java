package com.arthur.security.xml;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Accepts an XML document and echoes its root text - the shape of endpoint XXE usually hides in.
 * The hardening is entirely in {@link SafeXmlParser}; a rejected DOCTYPE surfaces as 400.
 */
@RestController
@RequestMapping("/api/xml")
public class XmlController {

    private final SafeXmlParser parser;

    public XmlController(SafeXmlParser parser) {
        this.parser = parser;
    }

    @PostMapping(value = "/parse", consumes = MediaType.APPLICATION_XML_VALUE,
            produces = MediaType.TEXT_PLAIN_VALUE)
    public String parse(@RequestBody String xml) {
        try {
            return parser.rootText(xml);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid XML");
        }
    }
}

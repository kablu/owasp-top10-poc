package com.security.poc.portswigger.serverside.xxe;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

/**
 * PortSwigger topic: <b>XML external entity (XXE) injection</b>.
 * <a href="https://portswigger.net/web-security/xxe">Reference</a>
 *
 * <p>An endpoint parses user-supplied XML with a parser that resolves external
 * entities. An attacker defines an entity pointing at a local file (or internal
 * URL) and references it in the document to read/exfiltrate it:
 * <pre>{@code
 * <?xml version="1.0"?>
 * <!DOCTYPE r [ <!ENTITY x SYSTEM "file:///etc/hostname"> ]>
 * <r>&x;</r>
 * }</pre>
 *
 * <p>Send the XML as the raw request body (Content-Type: application/xml).
 */
@RestController
@RequestMapping("/ps/serverside/xxe")
public class XxeController {

    // -----------------------------------------------------------------------
    // VULNERABLE
    // DOCTYPE + external general entities are ENABLED (parser defaults), so the
    // parser fetches whatever the SYSTEM identifier points to (local file / URL)
    // and inlines it into the document -> file disclosure and SSRF.
    // -----------------------------------------------------------------------
    @PostMapping(value = "/vuln/parse", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<?> vulnParse(@RequestBody String xml) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // No hardening: external entities resolve.
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
            return ResponseEntity.ok(Map.of("parsedText", serialize(doc),
                    "note", "If you referenced an external entity, its content was resolved above."));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getClass().getSimpleName() + ": " + e.getMessage()));
        }
    }

    // -----------------------------------------------------------------------
    // SECURE
    // Disable DOCTYPE declarations entirely (the single most effective control),
    // and turn off external general/parameter entities. A payload containing a
    // DOCTYPE now fails to parse instead of leaking files.
    // -----------------------------------------------------------------------
    @PostMapping(value = "/secure/parse", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<?> secureParse(@RequestBody String xml) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
            return ResponseEntity.ok(Map.of("parsedText", serialize(doc), "note", "DOCTYPE disallowed; XXE not possible."));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "XML rejected: " + e.getClass().getSimpleName()));
        }
    }

    private String serialize(Document doc) throws Exception {
        Transformer t = TransformerFactory.newInstance().newTransformer();
        t.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        StringWriter sw = new StringWriter();
        t.transform(new DOMSource(doc), new StreamResult(sw));
        return sw.toString();
    }
}

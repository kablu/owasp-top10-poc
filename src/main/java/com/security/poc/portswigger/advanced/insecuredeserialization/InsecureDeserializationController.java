package com.security.poc.portswigger.advanced.insecuredeserialization;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.Base64;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * PortSwigger topic: <b>Insecure deserialization</b>.
 * <a href="https://portswigger.net/web-security/deserialization">Reference</a>
 *
 * <p>Deserialising attacker-controlled data lets an attacker influence which
 * objects are created and how. With native Java serialization this reaches
 * "gadget chains" on the classpath and can lead to remote code execution.
 *
 * <p>The vulnerable endpoint reads a base64 Java object stream; the secure one
 * accepts plain JSON bound to a fixed DTO (no arbitrary types instantiated).
 */
@RestController
@RequestMapping("/ps/advanced/insecuredeserialization")
public class InsecureDeserializationController {

    private final ObjectMapper mapper = new ObjectMapper();

    // -----------------------------------------------------------------------
    // VULNERABLE
    // ObjectInputStream.readObject() instantiates whatever the byte stream says.
    // A crafted stream (e.g. a ysoserial gadget) can trigger side effects during
    // deserialization -> RCE. Never deserialize untrusted native Java objects.
    // -----------------------------------------------------------------------
    @PostMapping("/vuln/load")
    public ResponseEntity<?> vulnLoad(@RequestBody String base64) {
        try {
            byte[] data = Base64.getDecoder().decode(base64.trim());
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
                Object obj = ois.readObject();           // DANGEROUS
                return ResponseEntity.ok(Map.of("loaded", String.valueOf(obj)));
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getClass().getSimpleName()));
        }
    }

    /** The only shape we accept on the secure path. */
    public record Session(String user, String role) {}

    // -----------------------------------------------------------------------
    // SECURE
    // Use a data-only format (JSON) bound to an explicit type. No code executes
    // during binding and no unexpected classes are created. (If native
    // serialization is unavoidable, use an ObjectInputFilter allowlist.)
    // -----------------------------------------------------------------------
    @PostMapping("/secure/load")
    public ResponseEntity<?> secureLoad(@RequestBody String json) {
        try {
            Session s = mapper.readValue(json, Session.class);
            return ResponseEntity.ok(Map.of("user", s.user(), "role", s.role(), "note", "JSON bound to fixed DTO."));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid session json"));
        }
    }
}

package com.security.poc.a08integrityfailures;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * A08:2025 — Software or Data Integrity Failures.
 *
 * <p>Trusting data without verifying its origin/integrity. The vulnerable path
 * deserializes an untrusted Java object stream (RCE gadget-chain territory); the
 * secure path accepts JSON only after verifying an HMAC signature, then binds it
 * to a known type.
 */
@RestController
@RequestMapping("/a08")
public class A08Controller {

    private final ObjectMapper mapper = new ObjectMapper();
    private final byte[] hmacKey;

    public A08Controller(@Value("${poc.jwt.strong-secret}") String secret) {
        this.hmacKey = Base64.getDecoder().decode(secret);
    }

    // -----------------------------------------------------------------------
    // VULNERABLE: native Java deserialization of attacker-controlled bytes.
    // ObjectInputStream.readObject() can instantiate arbitrary classes on the
    // classpath and trigger gadget chains -> remote code execution. NEVER
    // deserialize untrusted input this way.
    // -----------------------------------------------------------------------
    @PostMapping("/vuln/import")
    public ResponseEntity<?> vulnImport(@RequestBody String base64Payload) {
        try {
            byte[] bytes = Base64.getDecoder().decode(base64Payload.trim());
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
                Object obj = ois.readObject();   // DANGEROUS: unrestricted class instantiation
                return ResponseEntity.ok(Map.of("deserialized", String.valueOf(obj),
                        "warning", "native deserialization of untrusted data = RCE risk"));
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getClass().getSimpleName()));
        }
    }

    // -----------------------------------------------------------------------
    // SECURE: accept a signed envelope {"payload":<json>, "sig":"<hmac>"}.
    // We recompute the HMAC over the exact payload and compare in constant time
    // BEFORE parsing, and bind only to a known, safe DTO. Tampered or unsigned
    // data is rejected.
    // -----------------------------------------------------------------------
    @PostMapping("/secure/import")
    public ResponseEntity<?> secureImport(@RequestBody Envelope envelope) {
        try {
            String expected = hmacHex(envelope.payload());
            if (!constantTimeEquals(expected, envelope.sig())) {
                return ResponseEntity.status(403).body(Map.of("error", "signature mismatch — rejected"));
            }
            ImportItem item = mapper.readValue(envelope.payload(), ImportItem.class);
            return ResponseEntity.ok(Map.of("verified", true, "item", item));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getClass().getSimpleName()));
        }
    }

    private String hmacHex(String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
        byte[] out = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : out) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /** Constant-time comparison to avoid timing side channels. */
    private boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) return false;
        int diff = 0;
        for (int i = 0; i < a.length(); i++) diff |= a.charAt(i) ^ b.charAt(i);
        return diff == 0;
    }

    /** Signed envelope: JSON payload + its HMAC-SHA256 hex signature. */
    public record Envelope(String payload, String sig) {}

    /** The only shape we are willing to bind untrusted input to. */
    public record ImportItem(String name, int quantity) {}
}

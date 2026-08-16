package com.security.poc.portswigger.advanced.jwt;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

/**
 * PortSwigger topic: <b>JWT attacks</b>.
 * <a href="https://portswigger.net/web-security/jwt">Reference</a>
 *
 * <p>JWTs are only as trustworthy as their signature verification. Classic flaws:
 * <ul>
 *   <li><b>No signature check</b> — the app reads claims without verifying, so an
 *       attacker edits {@code sub}/{@code role} freely.</li>
 *   <li><b>alg:none</b> — the app accepts an unsigned token.</li>
 *   <li><b>Weak key</b> — an HMAC key that can be brute-forced offline.</li>
 * </ul>
 * Pass a token to the vuln/secure verify endpoints. Get one from {@code /mint}.
 */
@RestController
@RequestMapping("/ps/advanced/jwt")
public class JwtAttacksController {

    private final SecretKey key;

    public JwtAttacksController(@Value("${poc.jwt.strong-secret}") String base64Secret) {
        this.key = Keys.hmacShaKeyFor(Base64.getDecoder().decode(base64Secret));
    }

    /** Helper: mint a properly signed token to experiment with. */
    @PostMapping("/mint")
    public Map<String, String> mint(@RequestParam(defaultValue = "salman") String sub,
                                    @RequestParam(defaultValue = "USER") String role) {
        String jwt = Jwts.builder().subject(sub).claim("role", role).signWith(key).compact();
        return Map.of("token", jwt);
    }

    // -----------------------------------------------------------------------
    // VULNERABLE
    // Splits the JWT and base64-decodes the payload WITHOUT verifying the
    // signature. An attacker changes "role":"USER" to "ADMIN", re-encodes, and
    // is trusted. (Same class of bug: accepting alg=none.)
    // -----------------------------------------------------------------------
    @PostMapping("/vuln/verify")
    public ResponseEntity<?> vulnVerify(@RequestParam String token) {
        try {
            String[] parts = token.split("\\.");
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            return ResponseEntity.ok(Map.of("trustedClaims", payload,
                    "note", "Signature NOT checked — any claims are accepted."));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "malformed token"));
        }
    }

    // -----------------------------------------------------------------------
    // SECURE
    // Verify the signature with the expected key and algorithm before reading any
    // claim. A tampered or alg:none token throws and is rejected. Use a strong,
    // high-entropy key; validate iss/aud/exp too.
    // -----------------------------------------------------------------------
    @PostMapping("/secure/verify")
    public ResponseEntity<?> secureVerify(@RequestParam String token) {
        try {
            Jws<Claims> jws = Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
            Claims c = jws.getPayload();
            return ResponseEntity.ok(Map.of("subject", c.getSubject(), "role", String.valueOf(c.get("role")),
                    "note", "Signature verified with the expected key/alg."));
        } catch (Exception e) {
            return ResponseEntity.status(401).body(Map.of("error", "invalid signature — rejected"));
        }
    }
}

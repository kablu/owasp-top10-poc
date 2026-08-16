package com.security.poc.a07authenticationfailures;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;

import javax.crypto.SecretKey;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

/**
 * Issues JWTs two ways to illustrate A07/A04 token weaknesses.
 */
class JwtUtil {

    /** WEAK: short, guessable HMAC key an attacker can brute-force offline. */
    private static final SecretKey WEAK_KEY =
            Keys.hmacShaKeyFor("secret-secret-secret-secret-1234".getBytes(StandardCharsets.UTF_8));

    /** STRONG: 32+ byte high-entropy key from configuration. */
    private final SecretKey strongKey;

    JwtUtil(String base64Secret) {
        byte[] raw = Base64.getDecoder().decode(base64Secret);
        this.strongKey = Keys.hmacShaKeyFor(raw);
    }

    /** Long-lived token signed with a weak key — forgeable once the key is cracked. */
    String issueWeak(String subject) {
        return Jwts.builder()
                .subject(subject)
                .expiration(new Date(System.currentTimeMillis() + 30L * 24 * 3600 * 1000)) // 30 days
                .signWith(WEAK_KEY)
                .compact();
    }

    /** Short-lived (15 min) token signed with a strong key. */
    String issueStrong(String subject) {
        return Jwts.builder()
                .subject(subject)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 15L * 60 * 1000))
                .signWith(strongKey)
                .compact();
    }
}

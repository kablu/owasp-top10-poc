package com.security.poc.a07authenticationfailures;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A07:2025 — Authentication Failures.
 *
 * <p>Contrasts an insecure login (plaintext compare, no lockout, weak token)
 * with a hardened one (constant-time BCrypt verify, account lockout to blunt
 * brute-force / credential stuffing, strongly-signed short-lived token).
 */
@RestController
@RequestMapping("/a07")
public class A07Controller {

    private final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(12);
    private final JwtUtil jwt;

    // Secure store: username -> bcrypt hash of the password.
    private final Map<String, String> hashedCredentials = new ConcurrentHashMap<>();
    // Vulnerable store: username -> PLAINTEXT password (bad on purpose).
    private final Map<String, String> plaintextCredentials = Map.of("salman", "P@ssw0rd1");

    // Lockout tracking for the secure endpoint.
    private final Map<String, AtomicInteger> failures = new ConcurrentHashMap<>();
    private static final int MAX_FAILURES = 5;

    public A07Controller(@Value("${poc.jwt.strong-secret}") String secret) {
        this.jwt = new JwtUtil(secret);
        hashedCredentials.put("salman", bcrypt.encode("P@ssw0rd1"));
    }

    // -----------------------------------------------------------------------
    // VULNERABLE:
    //   - passwords stored/compared in plaintext (== gives timing leaks too)
    //   - no lockout / throttling -> unlimited brute force & credential stuffing
    //   - token signed with a trivially guessable key ("secret") => forgeable
    //   - generic accounts enumeration via distinct error messages
    // -----------------------------------------------------------------------
    @PostMapping("/vuln/login")
    public ResponseEntity<?> vulnLogin(@RequestParam String username, @RequestParam String password) {
        String stored = plaintextCredentials.get(username);
        if (stored == null) {
            return ResponseEntity.status(401).body(Map.of("error", "no such user: " + username));
        }
        if (!stored.equals(password)) {
            return ResponseEntity.status(401).body(Map.of("error", "wrong password for " + username));
        }
        return ResponseEntity.ok(Map.of("token", jwt.issueWeak(username), "signing", "guessable key"));
    }

    // -----------------------------------------------------------------------
    // SECURE:
    //   - BCrypt verify (slow, salted, constant-time comparison)
    //   - account lockout after N failures
    //   - uniform error message (no user enumeration)
    //   - strongly-signed short-lived JWT (HS256, 32+ byte random secret)
    // -----------------------------------------------------------------------
    @PostMapping("/secure/login")
    public ResponseEntity<?> secureLogin(@RequestParam String username, @RequestParam String password) {
        if (failures.getOrDefault(username, new AtomicInteger()).get() >= MAX_FAILURES) {
            return ResponseEntity.status(423).body(Map.of("error", "account temporarily locked"));
        }
        String hash = hashedCredentials.get(username);
        boolean ok = hash != null && bcrypt.matches(password, hash);
        if (!ok) {
            failures.computeIfAbsent(username, k -> new AtomicInteger()).incrementAndGet();
            // Identical message whether the user exists or not.
            return ResponseEntity.status(401).body(Map.of("error", "invalid username or password"));
        }
        failures.remove(username);   // reset on success
        return ResponseEntity.ok(Map.of("token", jwt.issueStrong(username), "signing", "HS256 strong key"));
    }
}

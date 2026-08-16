package com.security.poc.portswigger.serverside.authentication;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PortSwigger topic: <b>Authentication</b> vulnerabilities.
 * <a href="https://portswigger.net/web-security/authentication">Reference</a>
 *
 * <p>Focuses on two classic flaws from the labs:
 * <ul>
 *   <li><b>Username enumeration</b> — different responses for "unknown user" vs
 *       "wrong password" let an attacker build a list of valid usernames.</li>
 *   <li><b>No brute-force protection</b> — unlimited attempts allow password
 *       guessing / credential stuffing.</li>
 * </ul>
 */
@RestController
@RequestMapping("/ps/serverside/authentication")
public class AuthenticationController {

    private final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder();
    private final Map<String, String> users = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> failures = new ConcurrentHashMap<>();
    private static final int MAX_ATTEMPTS = 3;

    public AuthenticationController() {
        users.put("salman", bcrypt.encode("Summer2026!"));
    }

    // -----------------------------------------------------------------------
    // VULNERABLE
    //   - Distinct error messages reveal whether the username exists.
    //   - No attempt counter -> unlimited guesses.
    // -----------------------------------------------------------------------
    @PostMapping("/vuln/login")
    public ResponseEntity<?> vulnLogin(@RequestParam String username, @RequestParam String password) {
        String hash = users.get(username);
        if (hash == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid username"));      // enumeration
        }
        if (!bcrypt.matches(password, hash)) {
            return ResponseEntity.status(401).body(Map.of("error", "Incorrect password"));     // enumeration
        }
        return ResponseEntity.ok(Map.of("status", "logged in"));
    }

    // -----------------------------------------------------------------------
    // SECURE
    //   - One identical message for every failure (no enumeration).
    //   - Lockout after N failures to blunt brute-force / credential stuffing.
    //   - (Real systems add: MFA, IP throttling, generic timing, CAPTCHA.)
    // -----------------------------------------------------------------------
    @PostMapping("/secure/login")
    public ResponseEntity<?> secureLogin(@RequestParam String username, @RequestParam String password) {
        if (failures.getOrDefault(username, new AtomicInteger()).get() >= MAX_ATTEMPTS) {
            return ResponseEntity.status(429).body(Map.of("error", "Too many attempts. Try again later."));
        }
        String hash = users.get(username);
        boolean ok = hash != null && bcrypt.matches(password, hash);
        if (!ok) {
            failures.computeIfAbsent(username, k -> new AtomicInteger()).incrementAndGet();
            return ResponseEntity.status(401).body(Map.of("error", "Invalid username or password"));
        }
        failures.remove(username);
        return ResponseEntity.ok(Map.of("status", "logged in"));
    }
}

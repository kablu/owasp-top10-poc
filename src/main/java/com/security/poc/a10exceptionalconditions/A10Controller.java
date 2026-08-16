package com.security.poc.a10exceptionalconditions;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A10:2025 — Mishandling of Exceptional Conditions.
 *
 * <p>Improper error handling: leaking stack traces (info disclosure), and
 * "fail-open" logic where an exception during a security check accidentally
 * grants access. The secure path fails closed and returns a sanitized error.
 */
@RestController
@RequestMapping("/a10")
public class A10Controller {

    // -----------------------------------------------------------------------
    // VULNERABLE #1: division by zero throws and we hand the raw stack trace
    // back to the client — leaking class names, file paths and internals that
    // help an attacker map the system.
    // -----------------------------------------------------------------------
    @GetMapping("/vuln/divide")
    public ResponseEntity<?> vulnDivide(@RequestParam int a, @RequestParam int b) {
        try {
            return ResponseEntity.ok(Map.of("result", a / b));
        } catch (Exception e) {
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            return ResponseEntity.status(500).body(Map.of("stackTrace", sw.toString())); // leaks internals
        }
    }

    // -----------------------------------------------------------------------
    // VULNERABLE #2: FAIL-OPEN. If the security check throws, the catch block
    // defaults to "grant". An exception (e.g. auth service down) becomes an
    // access bypass.
    // -----------------------------------------------------------------------
    @GetMapping("/vuln/access")
    public Map<String, Object> vulnAccess(@RequestParam String token) {
        boolean granted;
        try {
            granted = riskyCheck(token);
        } catch (Exception e) {
            granted = true;   // WRONG: error => access granted
        }
        return Map.of("granted", granted);
    }

    // -----------------------------------------------------------------------
    // SECURE: validate inputs up front, and let unexpected errors bubble to a
    // central handler that returns a generic message + correlation id (details
    // go to server logs only). Access checks FAIL CLOSED.
    // -----------------------------------------------------------------------
    @GetMapping("/secure/divide")
    public ResponseEntity<?> secureDivide(@RequestParam int a, @RequestParam int b) {
        if (b == 0) {
            return ResponseEntity.badRequest().body(Map.of("error", "divisor must be non-zero"));
        }
        return ResponseEntity.ok(Map.of("result", a / b));
    }

    @GetMapping("/secure/access")
    public Map<String, Object> secureAccess(@RequestParam String token) {
        boolean granted;
        try {
            granted = riskyCheck(token);
        } catch (Exception e) {
            granted = false;  // fail closed: error => deny
        }
        return Map.of("granted", granted);
    }

    /** Simulated flaky security check. */
    private boolean riskyCheck(String token) {
        if (token == null || token.isBlank()) {
            throw new IllegalStateException("auth backend unavailable");
        }
        return token.equals("valid-token");
    }
}

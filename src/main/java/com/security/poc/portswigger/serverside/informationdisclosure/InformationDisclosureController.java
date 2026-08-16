package com.security.poc.portswigger.serverside.informationdisclosure;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PortSwigger topic: <b>Information disclosure</b>.
 * <a href="https://portswigger.net/web-security/information-disclosure">Reference</a>
 *
 * <p>Sensitive information leaking to users: verbose error messages, stack
 * traces, framework versions, debug pages, and internal identifiers. Attackers
 * mine these for a foothold (versions -> known CVEs, paths -> further attacks).
 */
@RestController
@RequestMapping("/ps/serverside/informationdisclosure")
public class InformationDisclosureController {

    // -----------------------------------------------------------------------
    // VULNERABLE
    // On error, the raw exception (type, message, and a would-be stack trace) is
    // returned to the client, along with server internals. Great map for an
    // attacker; terrible for you.
    //   Trigger:  /vuln/lookup?id=abc  (non-numeric -> parse error leaked)
    // -----------------------------------------------------------------------
    @GetMapping("/vuln/lookup")
    public ResponseEntity<?> vulnLookup(@RequestParam String id) {
        try {
            int numeric = Integer.parseInt(id);
            return ResponseEntity.ok(Map.of("id", numeric, "value", "record-" + numeric));
        } catch (NumberFormatException e) {
            return ResponseEntity.status(500).body(Map.of(
                "exception", e.getClass().getName(),
                "message", e.getMessage(),
                "framework", "Spring Boot 3.3.5 / Java 21",
                "internalPath", "com.security.poc.portswigger...lookup",
                "dbUser", "sa"
            ));
        }
    }

    // -----------------------------------------------------------------------
    // SECURE
    // Validate input, and on any failure return a generic message with no
    // internal detail. Full detail goes only to server-side logs (with a
    // correlation id in real systems). Disable debug/verbose error pages in prod.
    // -----------------------------------------------------------------------
    @GetMapping("/secure/lookup")
    public ResponseEntity<?> secureLookup(@RequestParam String id) {
        if (!id.matches("\\d+")) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid id"));
        }
        int numeric = Integer.parseInt(id);
        return ResponseEntity.ok(Map.of("id", numeric, "value", "record-" + numeric));
    }
}

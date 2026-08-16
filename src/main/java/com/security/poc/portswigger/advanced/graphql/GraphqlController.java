package com.security.poc.portswigger.advanced.graphql;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PortSwigger topic: <b>GraphQL API vulnerabilities</b>.
 * <a href="https://portswigger.net/web-security/graphql">Reference</a>
 *
 * <p>Common GraphQL issues:
 * <ul>
 *   <li><b>Introspection exposed</b> — the full schema is readable, mapping the
 *       attack surface (including hidden/admin fields).</li>
 *   <li><b>Broken object-level auth (IDOR)</b> — fetch any object by id.</li>
 *   <li><b>No query cost/depth limit + aliasing</b> — batch many operations in
 *       one request for brute force / DoS.</li>
 * </ul>
 * Modelled with a tiny simulated resolver (no GraphQL engine wired in).
 */
@RestController
@RequestMapping("/ps/advanced/graphql")
public class GraphqlController {

    private static final Map<Integer, Map<String, String>> USERS = new LinkedHashMap<>();
    static {
        USERS.put(1, Map.of("username", "salman", "email", "salman@example.com"));
        USERS.put(2, Map.of("username", "administrator", "email", "admin@example.com"));
    }

    // -----------------------------------------------------------------------
    // VULNERABLE
    //   - Introspection is on for everyone.
    //   - user(id) has no authorization -> any user readable (IDOR).
    // -----------------------------------------------------------------------
    @GetMapping("/vuln/introspection")
    public Map<String, Object> vulnIntrospection() {
        return Map.of("__schema", Map.of("types", java.util.List.of("User", "AdminSettings", "InternalAuditLog")),
                "note", "Full schema exposed — including internal types.");
    }

    @GetMapping("/vuln/user")
    public ResponseEntity<?> vulnUser(@RequestParam int id) {
        Map<String, String> u = USERS.get(id);
        return u == null ? ResponseEntity.notFound().build()
                : ResponseEntity.ok(Map.of("user", u, "note", "No object-level auth (IDOR)."));
    }

    // -----------------------------------------------------------------------
    // SECURE
    //   - Disable introspection in production.
    //   - Enforce object-level authorization on every resolver.
    //   - Apply query depth/complexity limits + rate limiting; disable aliasing
    //     abuse; use persisted queries.
    // -----------------------------------------------------------------------
    @GetMapping("/secure/introspection")
    public ResponseEntity<?> secureIntrospection() {
        return ResponseEntity.status(403).body(Map.of("error", "introspection disabled in production"));
    }

    @GetMapping("/secure/user")
    public ResponseEntity<?> secureUser(@RequestParam int id,
                                        @RequestHeader(value = "X-User-Id", defaultValue = "0") int caller) {
        if (caller != id) {
            return ResponseEntity.status(403).body(Map.of("error", "you may only query your own user object"));
        }
        Map<String, String> u = USERS.get(id);
        return u == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(Map.of("user", u));
    }
}

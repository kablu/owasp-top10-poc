package com.security.poc.portswigger.serverside.accesscontrol;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PortSwigger topic: <b>Access control</b> (broken access control).
 * <a href="https://portswigger.net/web-security/access-control">Reference</a>
 *
 * <p>Two lab-style flaws:
 * <ul>
 *   <li><b>Horizontal (IDOR)</b> — read another user's record by changing an id.</li>
 *   <li><b>Vertical</b> — reach admin functionality without the admin role
 *       (unprotected admin URL / "security through obscurity").</li>
 * </ul>
 * Identity is passed via the {@code X-User} / {@code X-Role} headers to keep the
 * demo stateless for Postman. (In the real app this comes from the session/JWT.)
 */
@RestController
@RequestMapping("/ps/serverside/accesscontrol")
public class AccessControlController {

    private static final Map<Integer, Map<String, String>> ACCOUNTS = new LinkedHashMap<>();
    static {
        ACCOUNTS.put(1, Map.of("owner", "salman", "apiKey", "salman-KEY-111"));
        ACCOUNTS.put(2, Map.of("owner", "carlos", "apiKey", "carlos-KEY-222"));
    }

    // -------- Horizontal: IDOR --------

    // VULNERABLE: returns any account by id, no ownership check.
    //   Exploit:  GET /vuln/account/2  with X-User: salman  -> reads carlos' key
    @GetMapping("/vuln/account/{id}")
    public ResponseEntity<?> vulnAccount(@PathVariable int id) {
        Map<String, String> a = ACCOUNTS.get(id);
        return a == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(a);
    }

    // SECURE: only the owner may read their own account.
    @GetMapping("/secure/account/{id}")
    public ResponseEntity<?> secureAccount(@PathVariable int id, @RequestHeader(value = "X-User", defaultValue = "") String user) {
        Map<String, String> a = ACCOUNTS.get(id);
        if (a == null) return ResponseEntity.notFound().build();
        if (!a.get("owner").equals(user)) {
            return ResponseEntity.status(403).body(Map.of("error", "not your account"));
        }
        return ResponseEntity.ok(a);
    }

    // -------- Vertical: admin function --------

    // VULNERABLE: the "delete user" admin action has no role check — anyone who
    // discovers the URL can call it (unprotected functionality).
    @GetMapping("/vuln/admin/delete-user")
    public Map<String, Object> vulnAdmin() {
        return Map.of("action", "user deleted", "note", "no role check — vertical privilege escalation");
    }

    // SECURE: enforce the admin role server-side (never rely on hiding the URL).
    @GetMapping("/secure/admin/delete-user")
    public ResponseEntity<?> secureAdmin(@RequestHeader(value = "X-Role", defaultValue = "") String role) {
        if (!"ADMIN".equals(role)) {
            return ResponseEntity.status(403).body(Map.of("error", "admin role required"));
        }
        return ResponseEntity.ok(Map.of("action", "user deleted"));
    }
}

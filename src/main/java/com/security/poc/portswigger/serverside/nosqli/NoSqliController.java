package com.security.poc.portswigger.serverside.nosqli;

import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PortSwigger topic: <b>NoSQL injection</b>.
 * <a href="https://portswigger.net/web-security/nosql-injection">Reference</a>
 *
 * <p>MongoDB-style operator injection. A login builds a query from the JSON body.
 * If the raw JSON is passed to the driver, an attacker replaces a string value
 * with an operator object to bypass authentication:
 * <pre>{@code  { "username": "admin", "password": { "$ne": "x" } }  }</pre>
 * {@code $ne} ("not equal to x") matches admin's real password, logging the
 * attacker in without knowing it.
 *
 * <p><b>Safety note:</b> no real Mongo here — a tiny evaluator mimics how the
 * driver would interpret a {@code $ne} operator so the bypass is observable.
 */
@RestController
@RequestMapping("/ps/serverside/nosqli")
public class NoSqliController {

    private static final String ADMIN_USER = "admin";
    private static final String ADMIN_PASS = "s3cr3t-admin-pw";

    // -----------------------------------------------------------------------
    // VULNERABLE
    // The password field may be a STRING or an OPERATOR OBJECT, and we honour
    // operators just like an unsanitised Mongo query would -> auth bypass.
    // -----------------------------------------------------------------------
    @PostMapping(value = "/vuln/login", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> vulnLogin(@RequestBody Map<String, Object> body) {
        Object username = body.get("username");
        Object password = body.get("password");
        boolean match = ADMIN_USER.equals(username) && evaluate(password, ADMIN_PASS);
        return match
            ? ResponseEntity.ok(Map.of("status", "logged in as " + username, "note", "operator injection honoured"))
            : ResponseEntity.status(401).body(Map.of("error", "invalid credentials"));
    }

    // -----------------------------------------------------------------------
    // SECURE
    //   - Enforce that credentials are STRINGS (reject non-string / objects).
    //   - Compare as a plain string equality (parameterised in a real driver).
    //   An injected {"$ne": ...} object is rejected as a type error.
    // -----------------------------------------------------------------------
    @PostMapping(value = "/secure/login", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> secureLogin(@RequestBody Map<String, Object> body) {
        Object username = body.get("username");
        Object password = body.get("password");
        if (!(username instanceof String u) || !(password instanceof String p)) {
            return ResponseEntity.badRequest().body(Map.of("error", "username and password must be strings"));
        }
        boolean match = ADMIN_USER.equals(u) && ADMIN_PASS.equals(p);
        return match
            ? ResponseEntity.ok(Map.of("status", "logged in as " + u))
            : ResponseEntity.status(401).body(Map.of("error", "invalid credentials"));
    }

    /** Mimics a Mongo match: a string does equality; a {"$ne": v} object matches when actual != v. */
    @SuppressWarnings("unchecked")
    private boolean evaluate(Object supplied, String actual) {
        if (supplied instanceof String s) return s.equals(actual);
        if (supplied instanceof Map<?, ?> op && op.containsKey("$ne")) {
            return !actual.equals(String.valueOf(((Map<String, Object>) op).get("$ne")));
        }
        return false;
    }
}

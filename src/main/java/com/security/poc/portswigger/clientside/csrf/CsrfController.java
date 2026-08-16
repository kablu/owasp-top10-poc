package com.security.poc.portswigger.clientside.csrf;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PortSwigger topic: <b>Cross-site request forgery (CSRF)</b>.
 * <a href="https://portswigger.net/web-security/csrf">Reference</a>
 *
 * <p>CSRF makes a logged-in victim's browser send a state-changing request the
 * attacker chose, riding on the victim's ambient session cookie. The defence is
 * an unpredictable, per-session token the attacker's site cannot read or guess.
 *
 * <p>This REST demo models the synchronizer-token pattern explicitly (the whole
 * app also enables Spring Security's built-in CSRF for the browser-based
 * {@code /clientside} demo). Flow: GET a token, then POST it back.
 */
@RestController
@RequestMapping("/ps/clientside/csrf")
public class CsrfController {

    // Pretend session store: sessionId -> issued CSRF token.
    private final Map<String, String> tokens = new ConcurrentHashMap<>();
    private String email = "salman@example.com";

    /** Issue a CSRF token bound to the (demo) session. */
    @GetMapping("/token")
    public Map<String, String> token(@RequestHeader(value = "X-Session", defaultValue = "demo-session") String session) {
        String token = UUID.randomUUID().toString();
        tokens.put(session, token);
        return Map.of("csrfToken", token, "usage", "send it back as the _csrf parameter to /secure/change-email");
    }

    // -----------------------------------------------------------------------
    // VULNERABLE
    // A state-changing POST with NO anti-CSRF token. Any external page can
    // auto-submit this against a logged-in victim and change their email.
    // -----------------------------------------------------------------------
    @PostMapping("/vuln/change-email")
    public Map<String, Object> vulnChange(@RequestParam String email) {
        this.email = email;
        return Map.of("email", this.email, "note", "No token required — forgeable cross-site.");
    }

    // -----------------------------------------------------------------------
    // SECURE
    // Require the synchronizer token and verify it matches the one bound to the
    // session. A cross-site attacker cannot read it (same-origin policy), so the
    // forged request is rejected. Pair with SameSite=Lax/Strict cookies.
    // -----------------------------------------------------------------------
    @PostMapping("/secure/change-email")
    public ResponseEntity<?> secureChange(@RequestHeader(value = "X-Session", defaultValue = "demo-session") String session,
                                          @RequestParam String email,
                                          @RequestParam(name = "_csrf", defaultValue = "") String csrf) {
        String expected = tokens.get(session);
        if (expected == null || !expected.equals(csrf)) {
            return ResponseEntity.status(403).body(Map.of("error", "missing/invalid CSRF token"));
        }
        tokens.remove(session);         // single-use
        this.email = email;
        return ResponseEntity.ok(Map.of("email", this.email, "note", "Token validated."));
    }
}

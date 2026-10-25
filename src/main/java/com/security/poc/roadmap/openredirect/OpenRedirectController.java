package com.security.poc.roadmap.openredirect;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.util.Set;

/**
 * Roadmap Phase 4 — Input handling: <b>Open redirect</b> (CWE-601).
 *
 * <p>A redirect whose destination is taken from user input lets an attacker send
 * victims to an attacker-controlled site through a link that starts on the trusted
 * domain. It is a common building block for phishing and OAuth token theft
 * (a crafted {@code redirect_uri}).
 *
 * <pre>
 *   # safe internal target — both allow it
 *   GET /roadmap/openredirect/vuln/go?next=/roadmap
 *   GET /roadmap/openredirect/secure/go?next=/roadmap
 *
 *   # external target — vuln follows it, secure refuses (400)
 *   GET /roadmap/openredirect/vuln/go?next=https://evil.example/login
 *   GET /roadmap/openredirect/secure/go?next=https://evil.example/login
 *
 *   # protocol-relative bypass (//host) — still blocked by the secure path
 *   GET /roadmap/openredirect/secure/go?next=//evil.example
 * </pre>
 * Use {@code curl -i} so you can see the 302 Location header without following it.
 */
@RestController
@RequestMapping("/roadmap/openredirect")
public class OpenRedirectController {

    // Allow-list of in-app paths the secure endpoint is permitted to redirect to.
    private static final Set<String> ALLOWED_PATHS = Set.of("/roadmap", "/", "/index");

    // ---------------------------------------------------------------------
    // VULNERABLE — redirects to whatever the caller supplies. CWE-601.
    // ---------------------------------------------------------------------
    @GetMapping("/vuln/go")
    public ResponseEntity<Void> vulnGo(@RequestParam String next) {
        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(next))   // attacker-controlled Location
                .build();
    }

    // ---------------------------------------------------------------------
    // SECURE — only redirect to a known, in-app path from an allow-list.
    // Rules that matter:
    //   * Compare against an allow-list, never a denylist/substring check.
    //   * Reject absolute URLs and protocol-relative "//host" targets — both
    //     send the browser off-site even though they "look" local-ish.
    //   * Keep the mapping server-side; never trust the raw string as a URL.
    // ---------------------------------------------------------------------
    @GetMapping("/secure/go")
    public ResponseEntity<Void> secureGo(@RequestParam String next) {
        // Must be a single-slash absolute path and not protocol-relative "//".
        boolean localPath = next.startsWith("/") && !next.startsWith("//");
        if (!localPath || !ALLOWED_PATHS.contains(next)) {
            return ResponseEntity.badRequest().build();   // 400 — refuse off-list targets
        }
        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(next))
                .build();
    }
}

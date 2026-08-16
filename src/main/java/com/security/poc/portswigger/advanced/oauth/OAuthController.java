package com.security.poc.portswigger.advanced.oauth;

import java.util.List;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PortSwigger topic: <b>OAuth authentication</b> vulnerabilities.
 * <a href="https://portswigger.net/web-security/oauth">Reference</a>
 *
 * <p>Two of the most common OAuth flaws, both at the authorization endpoint:
 * <ul>
 *   <li><b>Unvalidated {@code redirect_uri}</b> — the server redirects the auth
 *       code to any URL, so an attacker steals the code/token (account takeover).</li>
 *   <li><b>Missing {@code state}</b> — no CSRF token on the callback, enabling
 *       login CSRF / forced account linking.</li>
 * </ul>
 */
@RestController
@RequestMapping("/ps/advanced/oauth")
public class OAuthController {

    /** Exactly-registered callback URLs for this client. */
    private static final List<String> REGISTERED_REDIRECTS = List.of("https://app.example.com/callback");

    // -----------------------------------------------------------------------
    // VULNERABLE
    // redirect_uri is used as-is (attacker sets it to their site) and there is no
    // state parameter. The authorization code is sent wherever the attacker wants.
    //   Exploit:  /vuln/authorize?redirect_uri=https://evil.example/steal
    // -----------------------------------------------------------------------
    @GetMapping("/vuln/authorize")
    public Map<String, Object> vulnAuthorize(@RequestParam String redirect_uri) {
        return Map.of("action", "302 redirect", "location", redirect_uri + "?code=AUTH_CODE_123",
                "note", "redirect_uri not validated + no state -> code theft / login CSRF.");
    }

    // -----------------------------------------------------------------------
    // SECURE
    //   - redirect_uri must EXACTLY match a pre-registered value (no prefix/substring
    //     matching, no attacker-controlled host).
    //   - Require an unguessable `state` and verify it on callback (CSRF defence).
    // -----------------------------------------------------------------------
    @GetMapping("/secure/authorize")
    public ResponseEntity<?> secureAuthorize(@RequestParam String redirect_uri,
                                             @RequestParam(defaultValue = "") String state) {
        if (!REGISTERED_REDIRECTS.contains(redirect_uri)) {
            return ResponseEntity.status(400).body(Map.of("error", "redirect_uri not registered"));
        }
        if (state.isBlank()) {
            return ResponseEntity.status(400).body(Map.of("error", "missing state parameter"));
        }
        return ResponseEntity.ok(Map.of("action", "302 redirect",
                "location", redirect_uri + "?code=AUTH_CODE_123&state=" + state,
                "note", "Exact redirect match + state echoed for callback verification."));
    }
}

package com.security.poc.portswigger.advanced.hostheader;

import java.util.List;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PortSwigger topic: <b>HTTP Host header attacks</b>.
 * <a href="https://portswigger.net/web-security/host-header">Reference</a>
 *
 * <p>Apps often build absolute URLs from the incoming {@code Host} header. In a
 * password-reset flow this is dangerous: an attacker sets {@code Host: evil.com},
 * so the reset link mailed to the victim points at the attacker's domain. When
 * the victim clicks it, the token leaks — <b>password reset poisoning</b>.
 */
@RestController
@RequestMapping("/ps/advanced/hostheader")
public class HostHeaderController {

    /** The canonical, trusted domains for this application. */
    private static final List<String> ALLOWED_HOSTS = List.of("app.example.com");

    // -----------------------------------------------------------------------
    // VULNERABLE
    // The reset link is built from the attacker-controllable Host header.
    //   Header:  Host: evil.example
    //   -> link: https://evil.example/reset?token=... (sent to the victim)
    // -----------------------------------------------------------------------
    @PostMapping("/vuln/reset")
    public Map<String, Object> vulnReset(@RequestHeader("Host") String host, @RequestParam String user) {
        String link = "https://" + host + "/reset?token=RESET_TOKEN_FOR_" + user;
        return Map.of("emailedLink", link, "note", "Link host taken from the request — poisonable.");
    }

    // -----------------------------------------------------------------------
    // SECURE
    // Never trust the Host header for security decisions. Build links from a
    // server-side configured canonical domain (or validate Host against a strict
    // allowlist and reject anything else).
    // -----------------------------------------------------------------------
    @PostMapping("/secure/reset")
    public ResponseEntity<?> secureReset(@RequestHeader("Host") String host, @RequestParam String user) {
        if (!ALLOWED_HOSTS.contains(host)) {
            return ResponseEntity.status(400).body(Map.of("error", "unexpected Host header: " + host));
        }
        String canonical = ALLOWED_HOSTS.get(0);            // configured, not from the request
        String link = "https://" + canonical + "/reset?token=RESET_TOKEN_FOR_" + user;
        return ResponseEntity.ok(Map.of("emailedLink", link, "note", "Link built from configured canonical host."));
    }
}

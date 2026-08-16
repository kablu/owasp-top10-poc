package com.security.poc.portswigger.clientside.clickjacking;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PortSwigger topic: <b>Clickjacking</b>.
 * <a href="https://portswigger.net/web-security/clickjacking">Reference</a>
 *
 * <p>Clickjacking loads a target page inside a transparent iframe on an attacker
 * site and tricks the victim into clicking something (e.g. "Delete account")
 * they can't see. The defence is to forbid framing by other origins via
 * {@code X-Frame-Options} and/or CSP {@code frame-ancestors}.
 */
@RestController
@RequestMapping("/ps/clientside/clickjacking")
public class ClickjackingController {

    private static final String PAGE =
        "<html><body><h2>Confirm: delete my account</h2>"
        + "<button>Delete</button></body></html>";

    // -----------------------------------------------------------------------
    // VULNERABLE
    // No framing protection headers, so any site can embed this sensitive page
    // in an invisible iframe and hijack the victim's click.
    // -----------------------------------------------------------------------
    @GetMapping(value = "/vuln/account", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> vulnPage() {
        return ResponseEntity.ok(PAGE);   // framimg allowed
    }

    // -----------------------------------------------------------------------
    // SECURE
    // Deny framing entirely (this page is never meant to be embedded). Modern
    // equivalent: Content-Security-Policy: frame-ancestors 'none'. Use 'self' or
    // a specific origin if legitimate framing is required.
    // -----------------------------------------------------------------------
    @GetMapping(value = "/secure/account", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> securePage() {
        return ResponseEntity.ok()
            .header("X-Frame-Options", "DENY")
            .header("Content-Security-Policy", "frame-ancestors 'none'")
            .body(PAGE);
    }
}

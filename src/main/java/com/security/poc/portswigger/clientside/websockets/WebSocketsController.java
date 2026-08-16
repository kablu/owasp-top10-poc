package com.security.poc.portswigger.clientside.websockets;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

/**
 * PortSwigger topic: <b>WebSockets</b> security.
 * <a href="https://portswigger.net/web-security/websockets">Reference</a>
 *
 * <p>WebSocket messages carry the same risks as HTTP: unsanitised message content
 * causes XSS in the receiving client, and a missing origin check enables
 * Cross-Site WebSocket Hijacking (CSWSH) — a malicious page opens a socket that
 * rides the victim's cookies.
 *
 * <p><b>Note:</b> to avoid extra wiring this models a single message-handler over
 * plain HTTP; the same checks apply inside a real {@code @MessageMapping} /
 * {@code WebSocketHandler}. The message is echoed to "all subscribers".
 */
@RestController
@RequestMapping("/ps/clientside/websockets")
public class WebSocketsController {

    // -----------------------------------------------------------------------
    // VULNERABLE
    //   - Accepts a message from any Origin (no handshake origin check) -> CSWSH.
    //   - Echoes the message content raw -> stored XSS in every viewer's DOM.
    // -----------------------------------------------------------------------
    @PostMapping("/vuln/message")
    public Map<String, Object> vulnMessage(@RequestHeader(value = "Origin", defaultValue = "https://evil.example") String origin,
                                           @RequestBody Map<String, String> body) {
        String message = body.getOrDefault("message", "");
        return Map.of("origin", origin, "broadcast", message,
                "note", "Origin unchecked (CSWSH) and message echoed raw (XSS).");
    }

    // -----------------------------------------------------------------------
    // SECURE
    //   - Validate the handshake Origin against an allowlist (reject others).
    //   - Authenticate the socket (token/session), and
    //   - HTML-encode message content before it reaches any browser DOM.
    // -----------------------------------------------------------------------
    @PostMapping("/secure/message")
    public ResponseEntity<?> secureMessage(@RequestHeader(value = "Origin", defaultValue = "") String origin,
                                           @RequestBody Map<String, String> body) {
        if (!"https://trusted.example.com".equals(origin)) {
            return ResponseEntity.status(403).body(Map.of("error", "origin not allowed (CSWSH blocked)"));
        }
        String safe = HtmlUtils.htmlEscape(body.getOrDefault("message", ""));
        return ResponseEntity.ok(Map.of("origin", origin, "broadcast", safe, "note", "Origin checked + content encoded."));
    }
}

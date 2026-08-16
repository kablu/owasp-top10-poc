package com.security.poc.portswigger.advanced.requestsmuggling;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PortSwigger topic: <b>HTTP request smuggling</b>.
 * <a href="https://portswigger.net/web-security/request-smuggling">Reference</a>
 *
 * <p>Request smuggling is a <i>protocol-level desync</i> between a front-end
 * (proxy/CDN) and back-end that disagree on where one request ends and the next
 * begins — typically via conflicting {@code Content-Length} (CL) and
 * {@code Transfer-Encoding} (TE) headers. It cannot be reproduced with a single
 * Spring controller because it depends on how two servers parse the raw byte
 * stream; the app layer never sees a "clean" request to act on.
 *
 * <p>This endpoint is therefore explanatory: it documents the vulnerable setup
 * and the concrete mitigations rather than emulating a byte-level desync.
 */
@RestController
@RequestMapping("/ps/advanced/requestsmuggling")
public class RequestSmugglingController {

    // -----------------------------------------------------------------------
    // VULNERABLE (configuration/topology, not a single handler)
    // -----------------------------------------------------------------------
    @GetMapping("/vuln/explain")
    public Map<String, Object> vulnExplain() {
        return Map.of(
            "variants", Map.of(
                "CL.TE", "front-end uses Content-Length, back-end uses Transfer-Encoding",
                "TE.CL", "front-end uses Transfer-Encoding, back-end uses Content-Length",
                "TE.TE", "both use TE but one can be tricked into ignoring an obfuscated header"),
            "impact", "prefix the NEXT user's request: bypass front-end controls, steal requests, cache poisoning",
            "why_no_live_demo", "requires a front-end/back-end pair disagreeing on message length at the socket level"
        );
    }

    // -----------------------------------------------------------------------
    // SECURE (mitigations)
    // -----------------------------------------------------------------------
    @GetMapping("/secure/explain")
    public Map<String, Object> secureExplain() {
        return Map.of("mitigations", java.util.List.of(
            "Use HTTP/2 end-to-end (its framing removes CL/TE ambiguity)",
            "Make front-end and back-end use the SAME server/parser and normalise requests",
            "Reject any request that has both Content-Length and Transfer-Encoding",
            "Reject malformed/obfuscated Transfer-Encoding headers",
            "Disable connection reuse between front-end and back-end if in doubt"
        ));
    }
}

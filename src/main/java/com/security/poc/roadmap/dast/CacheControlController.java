package com.security.poc.roadmap.dast;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * DAST point — <b>Sensitive response not marked non-cacheable</b> (CWE-525).
 *
 * <p>Scanners flag responses that carry private data without cache directives.
 * Such a response can be stored by the browser's disk cache, a shared forward
 * proxy, or a CDN, and later served to someone else or read off a shared machine.
 * The fix is to send {@code Cache-Control: no-store} (plus {@code Pragma: no-cache})
 * on any response containing private or authenticated data.
 *
 * <pre>
 *   # VULN: no cache headers → the balance can be cached
 *   curl -i http://localhost:8080/roadmap/dast/cache/vuln/balance
 *
 *   # SECURE: Cache-Control: no-store present
 *   curl -i http://localhost:8080/roadmap/dast/cache/secure/balance
 * </pre>
 */
@RestController
@RequestMapping("/roadmap/dast/cache")
public class CacheControlController {

    private static final String SENSITIVE_BODY = "{\"account\":\"alice\",\"balance\":\"12345.67\"}";

    // ---------------------------------------------------------------------
    // VULNERABLE — a developer explicitly made this private response cacheable
    // ("Cache-Control: public") to save a round-trip, not realising a shared
    // proxy/CDN or another user's browser can now store and re-serve the balance.
    // (Note: Spring Security sends no-store by DEFAULT; this vulnerability only
    // appears when that default is overridden, or the data is served outside the
    // security filter — which is exactly what this endpoint simulates.) CWE-525.
    // ---------------------------------------------------------------------
    @GetMapping(value = "/vuln/balance", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> vulnBalance() {
        return ResponseEntity.ok()
                .header(HttpHeaders.CACHE_CONTROL, "public, max-age=3600")   // sensitive data left cacheable
                .body(SENSITIVE_BODY);
    }

    // ---------------------------------------------------------------------
    // SECURE — explicitly forbid caching of the sensitive response.
    // no-store is the strongest directive; add no-cache/must-revalidate and the
    // legacy Pragma header for old intermediaries.
    // ---------------------------------------------------------------------
    @GetMapping(value = "/secure/balance", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> secureBalance() {
        return ResponseEntity.ok()
                .header(HttpHeaders.CACHE_CONTROL, "no-store, no-cache, must-revalidate")
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body(SENSITIVE_BODY);
    }
}

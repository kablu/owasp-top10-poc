package com.security.poc.portswigger.serverside.ssrf;

import java.net.InetAddress;
import java.net.URI;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PortSwigger topic: <b>Server-side request forgery (SSRF)</b>.
 * <a href="https://portswigger.net/web-security/ssrf">Reference</a>
 *
 * <p>A "stock check" / "fetch URL" feature makes the server issue an HTTP request
 * to a user-supplied URL. An attacker points it at internal-only services —
 * {@code http://localhost/admin}, cloud metadata {@code http://169.254.169.254/},
 * or {@code http://192.168.x.x} — abusing the server's network position.
 *
 * <p><b>Safety note:</b> we do not perform real outbound requests here. Both
 * endpoints resolve the target and report whether it points at an internal
 * address; the secure one blocks such targets before any fetch would occur.
 */
@RestController
@RequestMapping("/ps/serverside/ssrf")
public class SsrfController {

    // -----------------------------------------------------------------------
    // VULNERABLE
    // The URL is used as-is. There is no check on scheme, host, or resolved IP,
    // so the server will happily fetch internal endpoints on the attacker's
    // behalf (data exfiltration, internal port scanning, cloud creds theft).
    //   Exploit:  /vuln/fetch?url=http://169.254.169.254/latest/meta-data/
    // -----------------------------------------------------------------------
    @GetMapping("/vuln/fetch")
    public ResponseEntity<?> vulnFetch(@RequestParam String url) {
        try {
            URI uri = URI.create(url);
            String host = uri.getHost();
            // new RestTemplate().getForObject(url, String.class);  // <-- would SSRF
            return ResponseEntity.ok(Map.of(
                "wouldFetch", url,
                "resolvedHost", String.valueOf(host),
                "internal", isInternal(host),
                "note", "No validation — an internal host here means the server can be pivoted."
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // -----------------------------------------------------------------------
    // SECURE
    //   1) Enforce an allowlist of schemes (http/https only) and, ideally, of
    //      destination hosts.
    //   2) Resolve the host and REJECT private / loopback / link-local ranges
    //      (defends against DNS-rebinding-style internal access).
    //   3) Disable redirects and never reflect raw responses.
    // -----------------------------------------------------------------------
    @GetMapping("/secure/fetch")
    public ResponseEntity<?> secureFetch(@RequestParam String url) {
        try {
            URI uri = URI.create(url);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            if (scheme == null || !(scheme.equals("http") || scheme.equals("https")) || host == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "only http/https URLs allowed"));
            }
            if (isInternal(host)) {
                return ResponseEntity.status(403).body(Map.of("error", "target resolves to an internal address — blocked"));
            }
            return ResponseEntity.ok(Map.of("allowedToFetch", url, "note", "Passed scheme + internal-IP checks."));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid URL"));
        }
    }

    /** True if the host is loopback, link-local, site-local or the cloud metadata IP. */
    private boolean isInternal(String host) {
        if (host == null) return true;
        if (host.equalsIgnoreCase("localhost") || host.equals("169.254.169.254")) return true;
        try {
            for (InetAddress addr : InetAddress.getAllByName(host)) {
                if (addr.isLoopbackAddress() || addr.isLinkLocalAddress()
                        || addr.isSiteLocalAddress() || addr.isAnyLocalAddress()) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return true;   // fail closed: if we can't resolve it, don't fetch it
        }
    }
}

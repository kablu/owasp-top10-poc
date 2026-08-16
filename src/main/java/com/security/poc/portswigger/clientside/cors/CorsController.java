package com.security.poc.portswigger.clientside.cors;

import java.util.List;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PortSwigger topic: <b>Cross-origin resource sharing (CORS)</b>.
 * <a href="https://portswigger.net/web-security/cors">Reference</a>
 *
 * <p>Misconfigured CORS lets a malicious origin read responses that include the
 * victim's data. The dangerous combination is reflecting an arbitrary
 * {@code Origin} into {@code Access-Control-Allow-Origin} AND setting
 * {@code Access-Control-Allow-Credentials: true} — any site can then make
 * credentialed requests and read the reply.
 *
 * <p>Send an {@code Origin} header to see how each endpoint responds.
 */
@RestController
@RequestMapping("/ps/clientside/cors")
public class CorsController {

    private static final List<String> ALLOWED_ORIGINS = List.of("https://trusted.example.com");

    // -----------------------------------------------------------------------
    // VULNERABLE
    // Reflects whatever Origin the caller sent and allows credentials. This means
    // https://evil.example can read this authenticated response.
    // -----------------------------------------------------------------------
    @GetMapping("/vuln/data")
    public ResponseEntity<?> vulnData(@RequestHeader(value = "Origin", defaultValue = "https://evil.example") String origin) {
        return ResponseEntity.ok()
            .header("Access-Control-Allow-Origin", origin)          // reflected — any site
            .header("Access-Control-Allow-Credentials", "true")     // + credentials = dangerous
            .body(Map.of("secret", "salman-account-balance: 5000",
                    "note", "ACAO reflects the request Origin AND allows credentials."));
    }

    // -----------------------------------------------------------------------
    // SECURE
    //   - Only echo an origin that is on a strict allowlist (never "*", never a
    //     reflected arbitrary value when credentials are involved).
    //   - Omit credentials unless truly required.
    // -----------------------------------------------------------------------
    @GetMapping("/secure/data")
    public ResponseEntity<?> secureData(@RequestHeader(value = "Origin", defaultValue = "") String origin) {
        ResponseEntity.BodyBuilder resp = ResponseEntity.ok();
        if (ALLOWED_ORIGINS.contains(origin)) {
            resp.header("Access-Control-Allow-Origin", origin)
                .header("Access-Control-Allow-Credentials", "true")
                .header("Vary", "Origin");
        }
        // Origins not on the allowlist get NO CORS header -> browser blocks the read.
        return resp.body(Map.of("secret", "salman-account-balance: 5000",
                "allowedOrigins", ALLOWED_ORIGINS, "requestOrigin", origin));
    }
}

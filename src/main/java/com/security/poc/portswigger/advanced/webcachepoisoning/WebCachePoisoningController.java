package com.security.poc.portswigger.advanced.webcachepoisoning;

import java.util.Map;

import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PortSwigger topic: <b>Web cache poisoning</b>.
 * <a href="https://portswigger.net/web-security/web-cache-poisoning">Reference</a>
 *
 * <p>Different from cache <i>deception</i>: here the attacker gets a harmful
 * response cached and served to <i>other</i> users. The trick is an <b>unkeyed
 * input</b> — an input that affects the response but is NOT part of the cache key
 * — such as {@code X-Forwarded-Host}. If the app reflects it (e.g. into a script
 * URL) and the cache stores the result, everyone gets the attacker's value.
 */
@RestController
@RequestMapping("/ps/advanced/webcachepoisoning")
public class WebCachePoisoningController {

    // -----------------------------------------------------------------------
    // VULNERABLE
    // Reflects the unkeyed X-Forwarded-Host header into a cacheable response.
    //   Header:  X-Forwarded-Host: evil.example
    //   -> body loads //evil.example/script.js, and the cache serves it to all.
    // -----------------------------------------------------------------------
    @GetMapping("/vuln/home")
    public ResponseEntity<?> vulnHome(@RequestHeader(value = "X-Forwarded-Host", defaultValue = "app.example.com") String xfh) {
        String script = "<script src=\"https://" + xfh + "/resources/app.js\"></script>";
        return ResponseEntity.ok()
            .header("Cache-Control", "public, max-age=300")     // cached, incl. reflected header
            .body(Map.of("html", script, "note", "Unkeyed X-Forwarded-Host reflected into a cached page."));
    }

    // -----------------------------------------------------------------------
    // SECURE
    //   - Do NOT reflect untrusted request headers into responses.
    //   - Build asset hosts from server-side config.
    //   - Mark personalised/variable responses no-store, or include every input
    //     that changes the response in the cache key (Vary), and strip hop-by-hop
    //     headers like X-Forwarded-* at a trusted edge.
    // -----------------------------------------------------------------------
    @GetMapping("/secure/home")
    public ResponseEntity<?> secureHome() {
        String script = "<script src=\"https://app.example.com/resources/app.js\"></script>";
        return ResponseEntity.ok()
            .cacheControl(CacheControl.noStore())
            .body(Map.of("html", script, "note", "Asset host from config; request headers not reflected."));
    }
}

package com.security.poc.portswigger.advanced.prototypepollution;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PortSwigger topic: <b>Prototype pollution</b>.
 * <a href="https://portswigger.net/web-security/prototype-pollution">Reference</a>
 *
 * <p>A JavaScript-specific bug where writing to {@code __proto__} / {@code constructor}
 * during a recursive merge pollutes the shared {@code Object.prototype}, changing
 * behaviour app-wide. Java has no prototype chain, but the <b>root cause</b> —
 * an unsafe recursive merge of attacker JSON into shared state, without blocking
 * dangerous keys — maps directly. This models that: a "merge user prefs into
 * defaults" operation.
 *
 * <p>Send JSON like {@code {"__proto__":{"isAdmin":true}}} to each endpoint.
 */
@RestController
@RequestMapping("/ps/advanced/prototypepollution")
public class PrototypePollutionController {

    /** Shared defaults (stand-in for a global object/prototype). */
    private static final Map<String, Object> DEFAULTS = new HashMap<>(Map.of("theme", "light", "isAdmin", false));

    /** Keys that must never be written by a merge. */
    private static final Set<String> DANGEROUS_KEYS = Set.of("__proto__", "constructor", "prototype");

    // -----------------------------------------------------------------------
    // VULNERABLE
    // Recursively merges the client body into a copy of DEFAULTS, honouring every
    // key — including "__proto__"/"constructor". In JS this pollutes the global
    // prototype; here it lets the client inject/override privileged keys.
    // -----------------------------------------------------------------------
    @PostMapping(value = "/vuln/prefs", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> vulnMerge(@RequestBody Map<String, Object> body) {
        Map<String, Object> target = new HashMap<>(DEFAULTS);
        merge(target, body, false);
        return Map.of("merged", target, "note", "Dangerous keys honoured — prototype-pollution analogue.");
    }

    // -----------------------------------------------------------------------
    // SECURE
    //   - Reject/skip dangerous keys (__proto__, constructor, prototype).
    //   - Optionally allowlist which preference keys may be set.
    //   - Never mutate shared/global defaults from user input.
    // -----------------------------------------------------------------------
    @PostMapping(value = "/secure/prefs", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> secureMerge(@RequestBody Map<String, Object> body) {
        Map<String, Object> target = new HashMap<>(DEFAULTS);
        merge(target, body, true);
        return ResponseEntity.ok(Map.of("merged", target, "note", "Dangerous keys blocked during merge."));
    }

    @SuppressWarnings("unchecked")
    private void merge(Map<String, Object> target, Map<String, Object> source, boolean blockDangerous) {
        for (Map.Entry<String, Object> e : source.entrySet()) {
            if (blockDangerous && DANGEROUS_KEYS.contains(e.getKey())) {
                continue;   // the fix: never write these keys
            }
            if (e.getValue() instanceof Map<?, ?> child
                    && target.get(e.getKey()) instanceof Map<?, ?> existing) {
                merge((Map<String, Object>) existing, (Map<String, Object>) child, blockDangerous);
            } else {
                target.put(e.getKey(), e.getValue());
            }
        }
    }
}

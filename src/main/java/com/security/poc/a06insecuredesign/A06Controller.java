package com.security.poc.a06insecuredesign;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A06:2025 — Insecure Design.
 *
 * <p>Insecure design is a <i>missing control</i>, not a coding bug — you can't
 * patch your way out of it. Here a "redeem a discount code" feature is missing
 * two design controls: single-use enforcement and rate limiting. The secure
 * version bakes both into the workflow.
 */
@RestController
@RequestMapping("/a06")
public class A06Controller {

    // Shared "value store": each code is worth $50, once.
    private static final int CODE_VALUE = 50;

    // Secure-side state: which codes have already been consumed.
    private final Set<String> redeemedCodes = ConcurrentHashMap.newKeySet();

    // Secure-side state: simple fixed-window rate limiter (per code, per minute).
    private final Map<String, Window> attempts = new ConcurrentHashMap<>();
    private static final int MAX_ATTEMPTS_PER_MIN = 5;

    // -----------------------------------------------------------------------
    // VULNERABLE: no single-use check, no rate limit. An attacker scripts this
    // endpoint and redeems the same code thousands of times, or brute-forces the
    // code space, draining value. The bug is the *absence of a control*.
    // -----------------------------------------------------------------------
    @PostMapping("/vuln/redeem")
    public Map<String, Object> vulnRedeem(@RequestParam String code) {
        // Always "succeeds" — no state, no throttle.
        return Map.of("code", code, "credited", CODE_VALUE, "warning", "reusable + unthrottled");
    }

    // -----------------------------------------------------------------------
    // SECURE: enforce the intended business rules by design —
    //   1) each code redeems at most once (idempotent, atomic add), and
    //   2) throttle attempts to blunt brute-forcing the code space.
    // -----------------------------------------------------------------------
    @PostMapping("/secure/redeem")
    public ResponseEntity<?> secureRedeem(@RequestParam String code) {
        if (!allow(code)) {
            return ResponseEntity.status(429).body(Map.of("error", "rate limit exceeded, try later"));
        }
        // add() returns false if the code was already present -> already used.
        if (!redeemedCodes.add(code)) {
            return ResponseEntity.status(409).body(Map.of("error", "code already redeemed"));
        }
        return ResponseEntity.ok(Map.of("code", code, "credited", CODE_VALUE, "status", "redeemed once"));
    }

    /** Fixed-window rate limit keyed by code. */
    private boolean allow(String code) {
        Window w = attempts.compute(code, (k, cur) -> {
            Instant now = Instant.now();
            if (cur == null || Duration.between(cur.start, now).compareTo(Duration.ofMinutes(1)) > 0) {
                return new Window(now, new AtomicInteger(0));
            }
            return cur;
        });
        return w.count.incrementAndGet() <= MAX_ATTEMPTS_PER_MIN;
    }

    private record Window(Instant start, AtomicInteger count) {}
}

package com.security.poc.portswigger.serverside.raceconditions;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PortSwigger topic: <b>Race conditions</b>.
 * <a href="https://portswigger.net/web-security/race-conditions">Reference</a>
 *
 * <p>A limit-overrun (TOCTOU) race: a gift card can be redeemed once, but the
 * check ("is it unused?") and the act ("mark used + credit") are not atomic.
 * Two requests firing in the same instant both pass the check, so the card is
 * redeemed twice — the "limited" resource is exceeded.
 *
 * <p>Try it: fire many concurrent POSTs at {@code /vuln/redeem?card=GC1} and the
 * total credited exceeds the single card's value.
 */
@RestController
@RequestMapping("/ps/serverside/raceconditions")
public class RaceConditionsController {

    private static final int CARD_VALUE = 100;
    // card -> already redeemed?  (starts unredeemed)
    private final Map<String, Boolean> vulnRedeemed = new ConcurrentHashMap<>();
    private final Map<String, Boolean> secureRedeemed = new ConcurrentHashMap<>();

    // -----------------------------------------------------------------------
    // VULNERABLE
    // Non-atomic check-then-act. Between reading `redeemed` and writing it, a
    // concurrent request can slip through the same window (TOCTOU).
    // -----------------------------------------------------------------------
    @PostMapping("/vuln/redeem")
    public ResponseEntity<?> vulnRedeem(@RequestParam String card) {
        boolean already = vulnRedeemed.getOrDefault(card, false);   // TIME-OF-CHECK
        if (already) {
            return ResponseEntity.status(409).body(Map.of("error", "already redeemed"));
        }
        // ... imagine slow work here; another thread runs concurrently ...
        vulnRedeemed.put(card, true);                               // TIME-OF-USE (too late)
        return ResponseEntity.ok(Map.of("card", card, "credited", CARD_VALUE));
    }

    // -----------------------------------------------------------------------
    // SECURE
    // Make check-and-set a single atomic operation. putIfAbsent returns null
    // only for the FIRST caller; everyone else loses the race cleanly. (In a DB
    // you'd use SELECT ... FOR UPDATE / a unique constraint / an atomic UPDATE
    // ... WHERE redeemed = false.)
    // -----------------------------------------------------------------------
    @PostMapping("/secure/redeem")
    public ResponseEntity<?> secureRedeem(@RequestParam String card) {
        Boolean prior = secureRedeemed.putIfAbsent(card, true);    // atomic check-and-set
        if (prior != null) {
            return ResponseEntity.status(409).body(Map.of("error", "already redeemed"));
        }
        return ResponseEntity.ok(Map.of("card", card, "credited", CARD_VALUE));
    }
}

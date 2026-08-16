package com.security.poc.a09loggingfailures;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A09:2025 — Security Logging & Alerting Failures.
 *
 * <p>Two failure modes are shown on the vulnerable side: (1) security-relevant
 * actions produce NO audit trail, and (2) when something is logged it leaks
 * sensitive data. The secure side emits a structured, non-sensitive audit event
 * for every security action and raises an alert when a threshold is crossed.
 */
@RestController
@RequestMapping("/a09")
public class A09Controller {

    private static final Logger log = LoggerFactory.getLogger(A09Controller.class);

    // Secure-side: count high-value transfers per user to trigger alerting.
    private final Map<String, AtomicInteger> largeTransfers = new ConcurrentHashMap<>();
    private static final long ALERT_THRESHOLD = 10_000;

    // -----------------------------------------------------------------------
    // VULNERABLE: a money transfer — a security-critical action — happens with
    // no audit log at all. If this were abused, there'd be nothing to detect or
    // investigate with. (A common "improvement" makes it worse: logging the full
    // card/password, which then leaks into log aggregators.)
    // -----------------------------------------------------------------------
    @PostMapping("/vuln/transfer")
    public Map<String, Object> vulnTransfer(@RequestParam String to,
                                            @RequestParam long amount,
                                            @RequestParam(required = false) String cardNumber) {
        // No audit event. And if a dev "adds logging" like below, it leaks PII:
        // log.info("transfer to {} amount {} card {}", to, amount, cardNumber);
        return Map.of("status", "ok", "to", to, "amount", amount, "audit", "NONE");
    }

    // -----------------------------------------------------------------------
    // SECURE: emit a structured audit event (who/what/when/outcome) with NO
    // secrets, mask the identifiers, and raise an alert when suspicious activity
    // crosses a threshold so responders can act.
    // -----------------------------------------------------------------------
    @PostMapping("/secure/transfer")
    public Map<String, Object> secureTransfer(@RequestParam String to,
                                              @RequestParam long amount,
                                              @RequestParam(required = false) String cardNumber) {
        // Structured, non-sensitive audit trail. Card is masked, never logged raw.
        log.info("AUDIT action=transfer to={} amount={} card={} outcome=success",
                to, amount, mask(cardNumber));

        boolean alerted = false;
        if (amount >= ALERT_THRESHOLD) {
            int count = largeTransfers.computeIfAbsent(to, k -> new AtomicInteger()).incrementAndGet();
            log.warn("ALERT high-value transfer to={} amount={} count={} — notifying SOC",
                    to, amount, count);
            alerted = true;
        }
        return Map.of("status", "ok", "to", to, "amount", amount, "audited", true, "alerted", alerted);
    }

    /** Show only the last 4 digits; never log full PAN. */
    private String mask(String card) {
        if (card == null || card.length() < 4) return "****";
        return "****-****-****-" + card.substring(card.length() - 4);
    }
}

package com.security.poc.a01brokenaccesscontrol;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A01:2025 — Broken Access Control (IDOR + privilege escalation).
 *
 * <p>Accounts are keyed by a numeric id. alice owns id 1, bob owns id 2.
 */
@RestController
@RequestMapping("/a01")
public class A01Controller {

    /** In-memory "database" of accounts. id -> (owner username, balance). */
    private static final Map<Long, Account> ACCOUNTS = new LinkedHashMap<>();
    static {
        ACCOUNTS.put(1L, new Account(1L, "alice", "4111-1111-1111-1111", 5_000));
        ACCOUNTS.put(2L, new Account(2L, "bob",   "4222-2222-2222-2222", 250));
    }

    // -----------------------------------------------------------------------
    // VULNERABLE: Insecure Direct Object Reference.
    // Anyone can read ANY account just by changing the id in the URL. There is
    // no check that the caller actually owns the requested object.
    //   Exploit:  GET /a01/vuln/account/2  -> returns bob's card while logged in
    //             as alice (or with no login at all).
    // -----------------------------------------------------------------------
    @GetMapping("/vuln/account/{id}")
    public ResponseEntity<Account> vulnAccount(@PathVariable Long id) {
        Account a = ACCOUNTS.get(id);
        return a == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(a);
    }

    // -----------------------------------------------------------------------
    // SECURE: enforce ownership. The object is fetched, then we verify the
    // authenticated principal is the owner (or an admin). Deny by default.
    // -----------------------------------------------------------------------
    @GetMapping("/secure/account/{id}")
    public ResponseEntity<?> secureAccount(@PathVariable Long id, Authentication auth) {
        Account a = ACCOUNTS.get(id);
        if (a == null) {
            return ResponseEntity.notFound().build();
        }
        boolean isOwner = a.owner().equals(auth.getName());
        boolean isAdmin = auth.getAuthorities().stream()
                .anyMatch(g -> g.getAuthority().equals("ROLE_ADMIN"));
        if (!isOwner && !isAdmin) {
            // 403, and crucially we do NOT leak whether the id exists.
            return ResponseEntity.status(403).body("Forbidden: you do not own this resource.");
        }
        return ResponseEntity.ok(a);
    }

    // -----------------------------------------------------------------------
    // SECURE: function-level access control via method security.
    // Even if a low-priv user discovers this URL (forced browsing), the
    // @PreAuthorize gate rejects them before the method body runs.
    // -----------------------------------------------------------------------
    @GetMapping("/secure/admin/dashboard")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, Object> adminDashboard() {
        return Map.of("totalAccounts", ACCOUNTS.size(), "message", "admin only data");
    }

    /** Simple record used as the account DTO. */
    public record Account(Long id, String owner, String cardNumber, long balance) {}
}

package com.security.poc.portswigger.serverside.businesslogic;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PortSwigger topic: <b>Business logic vulnerabilities</b>.
 * <a href="https://portswigger.net/web-security/logic">Reference</a>
 *
 * <p>Logic flaws are valid-but-unintended flows the app never anticipated. Here a
 * checkout accepts a quantity and unit price from the client. The vulnerable
 * flow trusts them blindly, so a negative quantity produces a negative total
 * (the shop pays the attacker), and a client-supplied price can be tampered.
 */
@RestController
@RequestMapping("/ps/serverside/businesslogic")
public class BusinessLogicController {

    private static final int SERVER_PRICE = 100;   // authoritative price per unit

    // -----------------------------------------------------------------------
    // VULNERABLE
    //   - quantity is not bounded (negative -> negative total = refund/credit)
    //   - unit price comes from the CLIENT and is trusted
    //   Exploit:  /vuln/checkout?quantity=-5&unitPrice=100  -> total -500
    // -----------------------------------------------------------------------
    @PostMapping("/vuln/checkout")
    public Map<String, Object> vulnCheckout(@RequestParam int quantity, @RequestParam int unitPrice) {
        int total = quantity * unitPrice;
        return Map.of("quantity", quantity, "unitPrice", unitPrice, "total", total,
                "note", "Total blindly trusts client inputs — negative qty or tampered price wins.");
    }

    // -----------------------------------------------------------------------
    // SECURE
    //   - Validate quantity is within sane business bounds (> 0, <= max).
    //   - Use the SERVER's price; never accept price from the client.
    //   - Enforce invariants explicitly rather than assuming a "normal" user.
    // -----------------------------------------------------------------------
    @PostMapping("/secure/checkout")
    public ResponseEntity<?> secureCheckout(@RequestParam int quantity) {
        if (quantity < 1 || quantity > 100) {
            return ResponseEntity.badRequest().body(Map.of("error", "quantity must be between 1 and 100"));
        }
        int total = quantity * SERVER_PRICE;   // price sourced server-side
        return ResponseEntity.ok(Map.of("quantity", quantity, "unitPrice", SERVER_PRICE, "total", total));
    }
}

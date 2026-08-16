package com.security.poc.portswigger.serverside.apitesting;

import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PortSwigger topic: <b>API testing</b> — mass assignment / excessive binding.
 * <a href="https://portswigger.net/web-security/api-testing">Reference</a>
 *
 * <p>A "update my profile" API. The vulnerable version binds the whole JSON body
 * straight onto the internal user object, so an attacker can set fields they were
 * never meant to touch — e.g. {@code "isAdmin": true} or {@code "balance": 999999}
 * ("mass assignment" / "auto-binding"). The secure version binds only an explicit
 * allowlist of editable fields via a dedicated DTO.
 */
@RestController
@RequestMapping("/ps/serverside/apitesting")
public class ApiTestingController {

    /** Internal user model — note the privileged fields. */
    static class User {
        String displayName = "salman";
        String email = "salman@example.com";
        boolean isAdmin = false;     // privileged — must NOT be client-settable
        long balance = 0;            // privileged — must NOT be client-settable
    }

    // -----------------------------------------------------------------------
    // VULNERABLE
    // Every key in the request body is copied onto the user object. Sending
    // {"isAdmin":true,"balance":999999} silently escalates privilege / edits money.
    // -----------------------------------------------------------------------
    @PostMapping(value = "/vuln/profile", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> vulnUpdate(@RequestBody Map<String, Object> body) {
        User u = new User();
        // "bind everything the client sent" — the bug.
        if (body.containsKey("displayName")) u.displayName = String.valueOf(body.get("displayName"));
        if (body.containsKey("email"))       u.email = String.valueOf(body.get("email"));
        if (body.containsKey("isAdmin"))     u.isAdmin = Boolean.parseBoolean(String.valueOf(body.get("isAdmin")));
        if (body.containsKey("balance"))     u.balance = Long.parseLong(String.valueOf(body.get("balance")));
        return Map.of("displayName", u.displayName, "email", u.email, "isAdmin", u.isAdmin, "balance", u.balance,
                "note", "Privileged fields were bound from the client body.");
    }

    /** Explicit DTO: the ONLY fields a client is allowed to change. */
    public record ProfileUpdate(String displayName, String email) {}

    // -----------------------------------------------------------------------
    // SECURE
    // Bind to a narrow DTO that physically cannot carry isAdmin/balance. Even if
    // the attacker sends them, there is nowhere for those keys to land.
    // -----------------------------------------------------------------------
    @PostMapping(value = "/secure/profile", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> secureUpdate(@RequestBody ProfileUpdate update) {
        User u = new User();
        if (update.displayName() != null) u.displayName = update.displayName();
        if (update.email() != null)       u.email = update.email();
        // isAdmin / balance untouched — not part of the DTO.
        return Map.of("displayName", u.displayName, "email", u.email, "isAdmin", u.isAdmin, "balance", u.balance,
                "note", "Only displayName/email are bindable; privileged fields ignored.");
    }
}

package com.security.poc.a02securitymisconfiguration;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A02:2025 — Security Misconfiguration.
 *
 * <p>Demonstrates the difference between an endpoint that leaks internal
 * configuration / stack details and one that returns only what a client needs.
 * See also {@link SecureHeadersConfig} which adds hardening HTTP headers, and
 * {@code application.yml} where the H2 console + verbose errors are toggled.
 */
@RestController
@RequestMapping("/a02")
public class A02Controller {

    // -----------------------------------------------------------------------
    // VULNERABLE: verbose "debug" endpoint exposing secrets, versions, internal
    // hosts and whether debug/actuator features are open. Classic info-leak that
    // hands an attacker a roadmap (framework versions -> known CVEs, db creds).
    // -----------------------------------------------------------------------
    @GetMapping("/vuln/config")
    public Map<String, Object> vulnConfig() {
        Map<String, Object> cfg = new LinkedHashMap<>();
        cfg.put("app", "owasp-poc");
        cfg.put("javaVersion", System.getProperty("java.version"));
        cfg.put("osUser", System.getProperty("user.name"));
        cfg.put("dbUrl", "jdbc:h2:mem:owaspdb");
        cfg.put("dbUsername", "sa");
        cfg.put("dbPassword", "");                         // leaking credentials
        cfg.put("jwtSecret", "c2VjdXJlLXJhbmRvbS0zMi1ieXRl...");
        cfg.put("h2Console", "/h2-console (ENABLED, no auth)");
        cfg.put("stackTracesShown", true);
        cfg.put("internalHost", "10.0.4.12:5432");
        return cfg;
    }

    // -----------------------------------------------------------------------
    // SECURE: expose only a minimal, non-sensitive health signal. No secrets,
    // no versions, no internal topology. Actuator/H2/verbose errors are locked
    // down (see SecureHeadersConfig + application-secure notes).
    // -----------------------------------------------------------------------
    @GetMapping("/secure/config")
    public Map<String, Object> secureConfig() {
        return Map.of("status", "UP");
    }
}

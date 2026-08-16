package com.security.poc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * OWASP Top 10:2025 — Spring Boot + Spring Security PoC.
 *
 * <p>Each OWASP category lives in its own package ({@code a01...} through
 * {@code a10...}). Every package contains a <b>Vulnerable</b> path and a
 * <b>Secure</b> path so the two can be compared side by side.
 *
 * <p><b>WARNING:</b> the "vulnerable" endpoints are intentionally insecure and
 * exist only for learning in an isolated lab. Never expose this app publicly.
 */
@SpringBootApplication
public class OwaspPocApplication {

    public static void main(String[] args) {
        SpringApplication.run(OwaspPocApplication.class, args);
    }
}

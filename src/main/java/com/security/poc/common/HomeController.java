package com.security.poc.common;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Landing page: an index of every OWASP Top 10:2025 PoC in this project and the
 * vulnerable/secure endpoint pair for each.
 */
@RestController
public class HomeController {

    @GetMapping(value = {"/", "/index"}, produces = "text/plain")
    public String index() {
        return """
            OWASP Top 10:2025 — Spring Boot + Spring Security PoC
            =====================================================
            Login users (HTTP Basic or form login):
              alice / alice123   (ROLE_USER,  account id 1)
              bob   / bob123     (ROLE_USER,  account id 2)
              admin / admin123   (ROLE_USER + ROLE_ADMIN)

            Each package exposes a VULNERABLE and a SECURE endpoint.

            A01 Broken Access Control
                VULN   GET  /a01/vuln/account/{id}
                SECURE GET  /a01/secure/account/{id}         (auth; owner/admin only)
                SECURE GET  /a01/secure/admin/dashboard      (ROLE_ADMIN only)

            A02 Security Misconfiguration
                VULN   GET  /a02/vuln/config
                SECURE GET  /a02/secure/config

            A03 Software Supply Chain Failures
                VULN   GET  /a03/vuln/dependency-check
                SECURE GET  /a03/secure/dependency-check

            A04 Cryptographic Failures
                VULN   POST /a04/vuln/store?data=...
                SECURE POST /a04/secure/store?data=...

            A05 Injection (SQLi)
                VULN   GET  /a05/vuln/search?username=...
                SECURE GET  /a05/secure/search?username=...

            A06 Insecure Design (missing rate limit / business-logic abuse)
                VULN   POST /a06/vuln/redeem?code=...
                SECURE POST /a06/secure/redeem?code=...

            A07 Authentication Failures
                VULN   POST /a07/vuln/login?username=..&password=..
                SECURE POST /a07/secure/login?username=..&password=..

            A08 Software/Data Integrity Failures (insecure deserialization)
                VULN   POST /a08/vuln/import   (body: base64 java-serialized)
                SECURE POST /a08/secure/import  (body: signed JSON)

            A09 Security Logging & Alerting Failures
                VULN   POST /a09/vuln/transfer?to=..&amount=..
                SECURE POST /a09/secure/transfer?to=..&amount=..

            A10 Mishandling of Exceptional Conditions
                VULN   GET  /a10/vuln/divide?a=..&b=..
                SECURE GET  /a10/secure/divide?a=..&b=..
            """;
    }
}

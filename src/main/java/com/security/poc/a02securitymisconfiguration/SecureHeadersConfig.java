package com.security.poc.a02securitymisconfiguration;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * A02 hardening: attaches security response headers to every {@code /a02/secure/**}
 * response. In production you would apply these globally via Spring Security's
 * {@code headers()} DSL; scoped here so the vuln endpoint stays "bare" for contrast.
 *
 * <p>Mitigates: clickjacking (X-Frame-Options / CSP frame-ancestors), MIME
 * sniffing (X-Content-Type-Options), referrer leakage, and forces HTTPS (HSTS).
 */
@Component
public class SecureHeadersConfig extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        if (req.getRequestURI().startsWith("/a02/secure")) {
            res.setHeader("X-Content-Type-Options", "nosniff");
            res.setHeader("X-Frame-Options", "DENY");
            res.setHeader("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'");
            res.setHeader("Referrer-Policy", "no-referrer");
            res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
            res.setHeader("Cache-Control", "no-store");
        }
        chain.doFilter(req, res);
    }
}

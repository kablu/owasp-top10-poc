package com.security.poc.common;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Central Spring Security configuration for the PoC.
 *
 * <p>URL convention used across every package:
 * <ul>
 *   <li>{@code /a0X/vuln/**}   — intentionally insecure demo endpoints (open, no auth)</li>
 *   <li>{@code /a0X/secure/**} — the fixed counterpart (authenticated / authorized)</li>
 * </ul>
 *
 * <p>Method-level security ({@code @PreAuthorize}) is enabled so the A01
 * Broken-Access-Control package can demonstrate proper authorization.
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    /**
     * Passwords are stored using BCrypt — see A04 (Cryptographic Failures) and
     * A07 (Authentication Failures) for why plaintext / fast hashes are wrong.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService(PasswordEncoder encoder) {
        UserDetails alice = User.withUsername("alice")
                .password(encoder.encode("alice123")).roles("USER").build();
        UserDetails bob = User.withUsername("bob")
                .password(encoder.encode("bob123")).roles("USER").build();
        UserDetails admin = User.withUsername("admin")
                .password(encoder.encode("admin123")).roles("USER", "ADMIN").build();
        return new InMemoryUserDetailsManager(alice, bob, admin);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // CSRF strategy:
            //   - The a01..a10 REST demos are STATELESS (HTTP Basic, no session
            //     cookie), so CSRF adds nothing there — ignored so curl works.
            //   - The /clientside SESSION demo is cookie-based, so CSRF stays ON
            //     for /clientside/secure/** (that IS the A-CSRF demo). The
            //     /clientside/vuln/** path is ignored on purpose to show the hole.
            .csrf(csrf -> csrf.ignoringRequestMatchers(
                    "/h2-console/**",
                    "/a01/**", "/a02/**", "/a03/**", "/a04/**", "/a05/**",
                    "/a06/**", "/a07/**", "/a08/**", "/a09/**", "/a10/**",
                    "/clientside/vuln/**",
                    // PortSwigger topic PoCs are stateless REST endpoints exercised
                    // from Postman/curl, so CSRF adds nothing there.
                    "/ps/**",
                    // Roadmap gap-demos are stateless REST endpoints (curl/Postman).
                    // The /roadmap/session/** demo shows cookie/fixation mechanics
                    // directly, independent of Spring's CSRF token.
                    "/roadmap/**",
                    // PKI CA-ceremony endpoints are stateless REST (curl/Postman).
                    "/pki/**"))
            .authorizeHttpRequests(auth -> auth
                // Public: home page, static help, and every intentionally-vulnerable demo.
                .requestMatchers("/", "/index", "/error", "/h2-console/**").permitAll()
                .requestMatchers("/a0*/vuln/**", "/a10*/vuln/**").permitAll()
                // The login endpoint itself must be reachable WITHOUT prior auth,
                // otherwise you could never obtain a session/token (A07 demo).
                .requestMatchers("/a07/secure/login").permitAll()
                // Admin-only secure area (used by A01).
                .requestMatchers("/a01/secure/admin/**").hasRole("ADMIN")
                // Everything else under /secure requires authentication.
                .requestMatchers("/a0*/secure/**", "/a10*/secure/**").authenticated()
                // Client-side (XSS/CSRF) demo: public so it's easy to open in a
                // browser. CSRF protection (above) still guards the secure form.
                .requestMatchers("/clientside/**").permitAll()
                // PortSwigger topic PoCs: public. Each controller demonstrates its
                // own control (headers, tokens, allowlists) internally.
                .requestMatchers("/ps/**").permitAll()
                // Roadmap gap-demos: public so the vuln/secure pair is easy to drive.
                .requestMatchers("/roadmap/**").permitAll()
                // PKI CA-ceremony endpoints: public in the lab (HSM-backed).
                .requestMatchers("/pki/**").permitAll()
                // Actuator is left WIDE OPEN on purpose (roadmap actuator-exposure
                // demo). The secure posture — ADMIN-gated, separate port, minimal
                // exposure — is documented in ActuatorSecurityNotes. Never do this
                // in a real deployment.
                .requestMatchers("/actuator/**").permitAll()
                .anyRequest().permitAll()
            )
            // HTTP Basic is enough to demo auth; form login also enabled for browsers.
            .httpBasic(basic -> {})
            .formLogin(form -> {})
            // H2 console ships inside a frame — allow same-origin framing for the demo only.
            .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()));
        return http.build();
    }
}

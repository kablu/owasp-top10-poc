package com.security.poc.roadmap.actuator;

/**
 * Roadmap Phase 5 — the <b>secure</b> Actuator configuration, kept here as
 * reference. It is intentionally NOT wired as an active bean, because activating
 * it would lock down the endpoints and hide the vulnerable demo this lab is
 * showing. Copy these into a real service.
 *
 * <h2>1. Minimal exposure (application.yml)</h2>
 * <pre>
 * management:
 *   endpoints:
 *     web:
 *       exposure:
 *         include: health,info          # never '*'
 *   endpoint:
 *     health:
 *       show-details: when-authorized   # no internals to anonymous callers
 *   server:
 *     port: 9001                        # separate mgmt port, firewalled off the internet
 * </pre>
 *
 * <h2>2. Authorize /actuator/** (a dedicated, higher-priority filter chain)</h2>
 * <pre>
 * &#64;Bean
 * &#64;Order(1)
 * SecurityFilterChain actuatorChain(HttpSecurity http) throws Exception {
 *     http.securityMatcher(EndpointRequest.toAnyEndpoint())
 *         .authorizeHttpRequests(a -&gt; a
 *             .requestMatchers(EndpointRequest.to("health", "info")).permitAll()
 *             .anyRequest().hasRole("ADMIN"))
 *         .httpBasic(Customizer.withDefaults());
 *     return http.build();
 * }
 * </pre>
 * ({@code EndpointRequest} comes from
 * {@code org.springframework.boot.actuate.autoconfigure.security.servlet}.)
 *
 * <h2>3. Operational rules</h2>
 * <ul>
 *   <li>Disable {@code heapdump} and {@code threaddump} in production.</li>
 *   <li>Never expose {@code env}/{@code configprops} to untrusted callers —
 *       they print resolved secrets.</li>
 *   <li>Treat the management port as internal-only (network policy / firewall),
 *       not merely authenticated.</li>
 *   <li>Keep secrets in a vault and out of plain properties, so even an
 *       accidental {@code /env} leak yields references, not values.</li>
 * </ul>
 */
public final class ActuatorSecurityNotes {
    private ActuatorSecurityNotes() {
    }
}

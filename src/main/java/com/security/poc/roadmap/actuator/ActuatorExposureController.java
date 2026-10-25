package com.security.poc.roadmap.actuator;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Roadmap Phase 1 / Phase 5 — <b>Exposed Spring Boot Actuator endpoints</b>
 * (CWE-200 information exposure, often escalating to credential theft / RCE).
 *
 * <p>Actuator is the single most common Spring-specific finding. Left open, it
 * hands an attacker a map of the application and often its secrets:
 * <ul>
 *   <li>{@code /actuator/env} — every property, including DB passwords, API keys,
 *       JWT secrets that were injected as properties.</li>
 *   <li>{@code /actuator/configprops} — resolved configuration, same leak surface.</li>
 *   <li>{@code /actuator/heapdump} — a full heap dump; secrets and session data
 *       can be carved out of it offline.</li>
 *   <li>{@code /actuator/beans}, {@code /mappings} — the entire wiring and route
 *       map (recon goldmine).</li>
 *   <li>{@code /actuator/threaddump}, {@code /loggers} — runtime internals;
 *       {@code /loggers} is writable, so an attacker can flip logging to DEBUG.</li>
 *   <li>{@code /actuator/env} write + a bound refresh endpoint has historically
 *       chained to RCE.</li>
 * </ul>
 *
 * <p><b>This lab exposes Actuator wide open on purpose</b> (see
 * {@code application.yml} and {@code SecurityConfig}) so you can browse the hole:
 * <pre>
 *   GET /actuator
 *   GET /actuator/env
 *   GET /actuator/beans
 *   GET /actuator/mappings
 *   GET /actuator/configprops
 * </pre>
 * The secure posture is described by {@link ActuatorSecurityNotes} and summarised
 * at {@code GET /roadmap/actuator/explain}.
 */
@RestController
@RequestMapping("/roadmap/actuator")
public class ActuatorExposureController {

    @Value("${management.endpoints.web.exposure.include:health}")
    private String exposed;

    @GetMapping(value = "/explain", produces = "application/json")
    public Map<String, Object> explain() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("currentlyExposed", exposed);
        out.put("whyDangerous", List.of(
                "/actuator/env and /configprops leak injected secrets (DB, JWT, API keys)",
                "/actuator/heapdump lets secrets be extracted offline",
                "/actuator/beans and /mappings expose the full app structure for recon",
                "/actuator/loggers is writable — attacker can change log levels"));
        out.put("secureFix", List.of(
                "Expose only what you need: management.endpoints.web.exposure.include=health,info",
                "Require authentication/authorization on /actuator/** (ROLE_ADMIN)",
                "Move management to a separate port not reachable from the internet (management.server.port)",
                "Disable heapdump/threaddump in production, and never bind env/refresh writes",
                "Keep health details hidden: management.endpoint.health.show-details=when-authorized"));
        out.put("vulnTry", List.of("/actuator/env", "/actuator/beans", "/actuator/mappings", "/actuator/configprops"));
        return out;
    }
}

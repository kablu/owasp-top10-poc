package com.security.poc.a03supplychain;

import java.util.List;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A03:2025 — Software Supply Chain Failures.
 *
 * <p>This category is mostly about your <b>build & dependency pipeline</b>, not
 * a single request. The controller simulates the contrast between an app that
 * blindly trusts whatever versions resolve and one that pins, verifies and
 * scans its dependencies. See {@link DependencyPolicy} for the enforcing logic
 * and the README for the Gradle-side controls (lockfiles, checksum verification).
 */
@RestController
@RequestMapping("/a03")
public class A03Controller {

    // -----------------------------------------------------------------------
    // VULNERABLE: uses dynamic/unpinned versions ("latest", ranges), no
    // integrity verification, and pulls from an untrusted mirror. A poisoned or
    // typosquatted package would be pulled in silently on the next build.
    // -----------------------------------------------------------------------
    @GetMapping("/vuln/dependency-check")
    public Map<String, Object> vulnDeps() {
        return Map.of(
            "resolutionStrategy", "dynamic: uses '+' / 'latest.release'",
            "checksumVerification", false,
            "lockfile", "none",
            "repositories", List.of("mavenCentral()", "http://untrusted-mirror.example/repo"),
            "vulnerabilityScan", "never",
            "risk", "A single compromised transitive dep runs with app privileges."
        );
    }

    // -----------------------------------------------------------------------
    // SECURE: every dependency is pinned to an exact version, verified against a
    // lockfile + checksums, sourced only from trusted repos, and scanned in CI.
    // DependencyPolicy rejects anything that violates the policy.
    // -----------------------------------------------------------------------
    @GetMapping("/secure/dependency-check")
    public Map<String, Object> secureDeps() {
        var report = DependencyPolicy.evaluate(List.of(
            new DependencyPolicy.Dep("org.springframework.boot:spring-boot-starter-web", "3.3.5"),
            new DependencyPolicy.Dep("io.jsonwebtoken:jjwt-api", "0.12.6")
        ));
        return Map.of(
            "resolutionStrategy", "pinned exact versions",
            "checksumVerification", true,
            "lockfile", "gradle.lockfile (dependency locking enabled)",
            "repositories", List.of("mavenCentral() over HTTPS only"),
            "vulnerabilityScan", "OWASP Dependency-Check / dependabot in CI, build fails on CVE",
            "policyReport", report
        );
    }
}

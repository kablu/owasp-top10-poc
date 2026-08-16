package com.security.poc.a03supplychain;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Enforces supply-chain hygiene rules on a dependency set:
 * exact (pinned) versions only, no dynamic ranges, and no dependency on a
 * known-bad denylist. In a real pipeline this is what your CI check would do.
 */
public final class DependencyPolicy {

    private DependencyPolicy() {}

    /** Exact SemVer, e.g. 3.3.5 — rejects "+", "latest.release", "[1.0,2.0)". */
    private static final Pattern EXACT_VERSION = Pattern.compile("^\\d+\\.\\d+\\.\\d+$");

    /** Example denylist of packages with known-malicious/compromised releases. */
    private static final List<String> DENYLIST = List.of("evil-corp:backdoor-utils");

    public record Dep(String coordinate, String version) {}

    public record Finding(String coordinate, boolean allowed, String reason) {}

    public static List<Finding> evaluate(List<Dep> deps) {
        List<Finding> findings = new ArrayList<>();
        for (Dep d : deps) {
            if (DENYLIST.contains(d.coordinate())) {
                findings.add(new Finding(d.coordinate(), false, "on denylist (known compromise)"));
            } else if (!EXACT_VERSION.matcher(d.version()).matches()) {
                findings.add(new Finding(d.coordinate(), false, "version not pinned: " + d.version()));
            } else {
                findings.add(new Finding(d.coordinate(), true, "pinned & allowed"));
            }
        }
        return findings;
    }
}

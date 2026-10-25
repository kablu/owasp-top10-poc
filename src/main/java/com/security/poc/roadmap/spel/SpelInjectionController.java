package com.security.poc.roadmap.spel;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Roadmap Phase 4 — Injection: <b>Spring Expression Language (SpEL) injection</b>.
 *
 * <p>SpEL is a Spring-specific injection class that most generic scanners miss.
 * When untrusted input is fed into a {@link SpelExpressionParser} and evaluated
 * with the default {@code StandardEvaluationContext}, the expression can reference
 * arbitrary Java types and invoke their methods — i.e. remote code execution. This
 * is the same primitive behind several Spring CVEs (e.g. the Spring Data /
 * Spring Security SpEL RCE advisories).
 *
 * <p>Both endpoints are safe to run: the vulnerable one evaluates with the
 * dangerous context so you can observe type access, but this lab controller does
 * not itself shell out. Try the classic probes against the vuln endpoint and see
 * them blocked on the secure one.
 *
 * <pre>
 *   # arithmetic — works on both
 *   GET /roadmap/spel/vuln/eval?expr=7*7
 *   GET /roadmap/spel/secure/eval?expr=7*7
 *
 *   # type reference / method call — evaluates on vuln, rejected on secure
 *   GET /roadmap/spel/vuln/eval?expr=T(java.lang.Runtime).getRuntime()
 *   GET /roadmap/spel/secure/eval?expr=T(java.lang.Runtime).getRuntime()
 * </pre>
 */
@RestController
@RequestMapping("/roadmap/spel")
public class SpelInjectionController {

    private final ExpressionParser parser = new SpelExpressionParser();

    // A defence-in-depth allow-list for the secure path: only digits, whitespace
    // and the four arithmetic operators / parentheses are permitted through.
    private static final Pattern ARITHMETIC_ONLY = Pattern.compile("[0-9+\\-*/()\\s.]+");

    // ---------------------------------------------------------------------
    // VULNERABLE — user input parsed and evaluated with the default context.
    // The default StandardEvaluationContext exposes T(...) type references,
    // constructors and arbitrary method calls → RCE. CWE-917.
    // ---------------------------------------------------------------------
    @GetMapping(value = "/vuln/eval", produces = "application/json")
    public Map<String, Object> vulnEval(@RequestParam String expr) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("input", expr);
        try {
            Expression expression = parser.parseExpression(expr);
            // No EvaluationContext argument == StandardEvaluationContext == dangerous.
            Object value = expression.getValue();
            out.put("evaluated", true);
            out.put("result", String.valueOf(value));
            out.put("note", "Default context evaluated the expression — type refs/method calls are reachable (RCE primitive).");
        } catch (Exception e) {
            out.put("evaluated", false);
            out.put("error", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        return out;
    }

    // ---------------------------------------------------------------------
    // SECURE — two layers:
    //   1) Input allow-list: reject anything that is not plain arithmetic.
    //   2) SimpleEvaluationContext.forReadOnlyDataBinding(): even if an
    //      expression slips through, this context forbids type references,
    //      constructors and bean resolution, so T(...) / new ... cannot run.
    // The real-world rule: never evaluate user-supplied SpEL at all. If you must
    // evaluate a template, use SimpleEvaluationContext and validate the input.
    // ---------------------------------------------------------------------
    @GetMapping(value = "/secure/eval", produces = "application/json")
    public Map<String, Object> secureEval(@RequestParam String expr) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("input", expr);

        if (!ARITHMETIC_ONLY.matcher(expr).matches()) {
            out.put("evaluated", false);
            out.put("error", "Rejected: input contains characters outside the arithmetic allow-list.");
            return out;
        }
        try {
            // Read-only data-binding context: no T(...), no constructors, no beans.
            EvaluationContext safe = SimpleEvaluationContext.forReadOnlyDataBinding().build();
            Expression expression = parser.parseExpression(expr);
            Object value = expression.getValue(safe);
            out.put("evaluated", true);
            out.put("result", String.valueOf(value));
            out.put("note", "Evaluated under SimpleEvaluationContext after an allow-list check — type access is impossible.");
        } catch (Exception e) {
            out.put("evaluated", false);
            out.put("error", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        return out;
    }
}

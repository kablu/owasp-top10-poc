package com.security.poc.portswigger.advanced.ssti;

import java.util.Map;
import java.util.regex.Pattern;

import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PortSwigger topic: <b>Server-side template injection (SSTI)</b>.
 * <a href="https://portswigger.net/web-security/server-side-template-injection">Reference</a>
 *
 * <p>When user input is embedded into a template that is then evaluated, the
 * input becomes template code. The classic probe {@code ${7*7}} returning
 * {@code 49} confirms evaluation; from there attackers reach language/runtime
 * objects (in Spring, SpEL {@code T(java.lang.Runtime)}) for RCE.
 *
 * <p><b>Safety note:</b> this uses Spring's SpEL as the "template engine". To keep
 * the PoC from being a live RCE, the vulnerable endpoint blocks type-reference
 * tokens ({@code T(}, {@code Runtime}, …) while still evaluating arithmetic, so
 * you can observe injection ({@code 7*7 -> 49}) safely. The comments mark where a
 * truly vulnerable app would allow full RCE.
 */
@RestController
@RequestMapping("/ps/advanced/ssti")
public class SstiController {

    private final SpelExpressionParser parser = new SpelExpressionParser();
    /** RCE tokens we refuse to evaluate in this lab (a real vuln would run them). */
    private static final Pattern RCE_TOKENS =
            Pattern.compile("T\\(|Runtime|ProcessBuilder|exec|getClass|ClassLoader|System", Pattern.CASE_INSENSITIVE);

    // -----------------------------------------------------------------------
    // VULNERABLE
    // The "greeting template" is evaluated as an expression. Input like
    //   name=${7*7}
    // is executed -> 49, proving code evaluation. In a real vulnerable app the
    // context would be a StandardEvaluationContext allowing T(...) -> RCE.
    // -----------------------------------------------------------------------
    @GetMapping("/vuln/render")
    public ResponseEntity<?> vulnRender(@RequestParam String name) {
        // Extract the ${...} expression the way a naive template engine would.
        String expr = name.startsWith("${") && name.endsWith("}")
                ? name.substring(2, name.length() - 1) : null;
        if (expr == null) {
            return ResponseEntity.ok(Map.of("rendered", "Hello " + name));
        }
        if (RCE_TOKENS.matcher(expr).find()) {
            return ResponseEntity.ok(Map.of("rendered", "[blocked in lab]",
                    "note", "A truly vulnerable app would EXECUTE this (RCE). Blocked here for safety."));
        }
        try {
            Expression e = parser.parseExpression(expr);
            Object val = e.getValue(SimpleEvaluationContext.forReadOnlyDataBinding().build());
            return ResponseEntity.ok(Map.of("rendered", "Hello " + val,
                    "note", "Your ${expression} was evaluated as code — that's SSTI."));
        } catch (Exception ex) {
            return ResponseEntity.badRequest().body(Map.of("error", "bad expression"));
        }
    }

    // -----------------------------------------------------------------------
    // SECURE
    // Never evaluate user input as a template. Treat it as DATA: pass it as a
    // bound variable to a logic-less template, or just concatenate as plain text.
    // "${7*7}" is echoed literally, not executed.
    // -----------------------------------------------------------------------
    @GetMapping("/secure/render")
    public Map<String, Object> secureRender(@RequestParam String name) {
        return Map.of("rendered", "Hello " + name, "note", "Input treated as data; no evaluation.");
    }
}

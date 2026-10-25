package com.security.poc.roadmap.dast;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * DAST point — <b>CRLF injection / HTTP response splitting</b> (CWE-113).
 *
 * <p>When user input is copied into a response header without stripping CR/LF,
 * an attacker can inject {@code \r\n} to add headers or even a second response
 * body (response splitting), enabling header injection, cache poisoning and
 * reflected XSS via a forged body.
 *
 * <p>Modern Tomcat rejects raw CR/LF in header values, so the live attack is
 * largely mitigated at the container — but relying on that alone is fragile, and
 * scanners still flag the reflection. The correct app-level control is to
 * validate/strip CR/LF (and ideally allow-list) before the value reaches any
 * header. This demo shows the composed value both ways and whether the container
 * accepted it.
 *
 * <pre>
 *   # VULN: reflects raw input into the X-Echo header (CR/LF would split)
 *   curl -i "http://localhost:8080/roadmap/dast/crlf/vuln/echo?value=hello"
 *   curl -i "http://localhost:8080/roadmap/dast/crlf/vuln/echo?value=hello%0d%0aSet-Cookie:%20x=1"
 *
 *   # SECURE: CR/LF stripped before the header is set
 *   curl -i "http://localhost:8080/roadmap/dast/crlf/secure/echo?value=hello%0d%0aSet-Cookie:%20x=1"
 * </pre>
 */
@RestController
@RequestMapping("/roadmap/dast/crlf")
public class ResponseSplittingController {

    // ---------------------------------------------------------------------
    // VULNERABLE — raw user input placed into a response header. CWE-113.
    // (Tomcat may throw IllegalArgumentException on embedded CR/LF; we catch it
    // and report, to show why container defences are not a substitute for input
    // validation.)
    // ---------------------------------------------------------------------
    @GetMapping(value = "/vuln/echo", produces = "application/json")
    public Map<String, Object> vulnEcho(@RequestParam String value, HttpServletResponse response) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("attemptedHeaderValue", value);
        try {
            response.setHeader("X-Echo", value);   // no sanitisation
            out.put("headerSet", true);
            out.put("note", "Raw input reflected into a response header — CR/LF would split the response. CWE-113.");
        } catch (IllegalArgumentException e) {
            out.put("headerSet", false);
            out.put("note", "Container rejected embedded CR/LF — but do not rely on that; validate at the app.");
        }
        return out;
    }

    // ---------------------------------------------------------------------
    // SECURE — strip CR and LF (and other control chars) before the value ever
    // reaches a header. Defence in depth, independent of the container.
    // ---------------------------------------------------------------------
    @GetMapping(value = "/secure/echo", produces = "application/json")
    public Map<String, Object> secureEcho(@RequestParam String value, HttpServletResponse response) {
        String sanitized = value.replaceAll("[\\r\\n]", "")   // kill the split characters
                                 .replaceAll("[\\x00-\\x1F]", "");
        response.setHeader("X-Echo", sanitized);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("originalInput", value);
        out.put("sanitizedHeaderValue", sanitized);
        out.put("note", "CR/LF and control characters stripped before setting the header — no splitting possible.");
        return out;
    }
}

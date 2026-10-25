package com.security.poc.roadmap.dast;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * DAST point — <b>Sensitive data transmitted in the URL / query string</b>
 * (CWE-598).
 *
 * <p>Secrets (passwords, reset tokens, session ids, API keys) placed in the query
 * string leak through many channels even over HTTPS: web-server access logs, proxy
 * logs, browser history, bookmarks, and the {@code Referer} header sent to
 * third-party resources. Scanners flag tokens/keys seen in URLs. The fix is to
 * carry the secret in a header (or request body for POST), never the URL.
 *
 * <pre>
 *   # VULN: reset token in the query string — lands in access logs / history
 *   curl -i -X POST "http://localhost:8080/roadmap/dast/url/vuln/reset?token=SECRET-123&newPass=p"
 *
 *   # SECURE: token in a header; URL carries nothing sensitive
 *   curl -i -X POST "http://localhost:8080/roadmap/dast/url/secure/reset" \
 *        -H "X-Reset-Token: SECRET-123" -d "newPass=p"
 * </pre>
 */
@RestController
@RequestMapping("/roadmap/dast/url")
public class SensitiveDataInUrlController {

    // ---------------------------------------------------------------------
    // VULNERABLE — secret arrives as a query parameter. The full request line
    // ("POST /...reset?token=SECRET-123") is written to access logs and kept in
    // browser history / proxy logs. CWE-598.
    // ---------------------------------------------------------------------
    @PostMapping(value = "/vuln/reset", produces = "application/json")
    public Map<String, Object> vulnReset(@RequestParam String token,
                                         @RequestParam String newPass,
                                         HttpServletRequest request) {
        Map<String, Object> out = new LinkedHashMap<>();
        // Show exactly what a log line would capture — the secret is right there.
        out.put("loggedRequestLine", request.getMethod() + " " + request.getRequestURI()
                + "?" + request.getQueryString());
        out.put("note", "The reset token is in the URL — it leaks via logs, history and Referer. CWE-598.");
        return out;
    }

    // ---------------------------------------------------------------------
    // SECURE — secret travels in a request header; the URL is clean, so logs
    // and history never capture it. (Header values are not written to standard
    // access logs, unlike the request line.)
    // ---------------------------------------------------------------------
    @PostMapping(value = "/secure/reset", produces = "application/json")
    public Map<String, Object> secureReset(@RequestHeader("X-Reset-Token") String token,
                                           @RequestParam String newPass,
                                           HttpServletRequest request) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("loggedRequestLine", request.getMethod() + " " + request.getRequestURI());
        out.put("note", "Token was sent in the X-Reset-Token header — the URL carries nothing sensitive.");
        return out;
    }
}

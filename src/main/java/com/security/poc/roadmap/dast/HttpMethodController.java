package com.security.poc.roadmap.dast;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * DAST point — <b>Insecure / unneeded HTTP methods enabled</b> (CWE-650).
 *
 * <p>Scanners (OWASP ZAP "Insecure HTTP Method", Burp) flag endpoints that answer
 * methods they should not: {@code PUT}/{@code DELETE} that let a client write or
 * remove resources, and {@code TRACE} (Cross-Site Tracing / header reflection).
 * The principle: an endpoint must accept only the verbs it actually implements,
 * everything else returns {@code 405 Method Not Allowed}.
 *
 * <pre>
 *   # VULN answers whatever verb you throw at it
 *   curl -i -X GET    http://localhost:8080/roadmap/dast/httpmethods/vuln/resource
 *   curl -i -X PUT    http://localhost:8080/roadmap/dast/httpmethods/vuln/resource   # 200 (should not!)
 *   curl -i -X DELETE http://localhost:8080/roadmap/dast/httpmethods/vuln/resource   # 200 (should not!)
 *
 *   # SECURE: only GET; other verbs are rejected
 *   curl -i -X GET    http://localhost:8080/roadmap/dast/httpmethods/secure/resource # 200
 *   curl -i -X DELETE http://localhost:8080/roadmap/dast/httpmethods/secure/resource # 405
 * </pre>
 */
@RestController
@RequestMapping("/roadmap/dast/httpmethods")
public class HttpMethodController {

    // ---------------------------------------------------------------------
    // VULNERABLE — @RequestMapping with no `method` attribute maps EVERY verb
    // (GET/POST/PUT/DELETE/PATCH...). A read-only resource should never accept
    // write verbs. TRACE is handled by the container, but leaving write verbs
    // open is the app-level mistake DAST flags here. CWE-650.
    // ---------------------------------------------------------------------
    @RequestMapping("/vuln/resource")
    public Map<String, Object> vulnResource(HttpServletRequest request) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("methodHandled", request.getMethod());
        out.put("note", "This endpoint answered a verb it should not — no method restriction. CWE-650.");
        return out;
    }

    // ---------------------------------------------------------------------
    // SECURE — restrict to the exact verb implemented. Spring returns 405 for
    // anything else automatically. (Also disable TRACE at the container level
    // and avoid PUT/DELETE unless the resource genuinely supports them.)
    // ---------------------------------------------------------------------
    @GetMapping("/secure/resource")
    public ResponseEntity<Map<String, Object>> secureResource(HttpServletRequest request) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("methodHandled", request.getMethod());
        out.put("note", "Only GET is mapped; PUT/DELETE/PATCH return 405 Method Not Allowed.");
        return ResponseEntity.status(HttpStatus.OK).body(out);
    }
}

package com.security.poc.roadmap.sessionsecurity;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Roadmap Phase 3 — Session management: <b>session fixation</b> (CWE-384) and
 * <b>insecure session cookie flags</b> (CWE-1004 / CWE-614).
 *
 * <p><b>Session fixation:</b> if the session id is not rotated at the moment
 * privilege changes (login), an attacker who planted a known session id in the
 * victim's browser beforehand now shares the victim's authenticated session.
 * The fix is to issue a brand-new session id on authentication.
 *
 * <p><b>Cookie flags:</b> the session cookie must be {@code HttpOnly} (no JS
 * access → XSS can't steal it), {@code Secure} (HTTPS only), and
 * {@code SameSite=Lax/Strict} (limits CSRF). The vuln path sets a cookie with
 * none of these.
 *
 * <pre>
 *   # watch the session id: vuln keeps it, secure rotates it on login
 *   GET  /roadmap/session/whoami                       # note JSESSIONID / sessionId
 *   POST /roadmap/session/vuln/login?user=alice        # sessionIdChanged=false
 *   POST /roadmap/session/secure/login?user=alice      # sessionIdChanged=true
 *
 *   # compare Set-Cookie flags (use curl -i)
 *   GET  /roadmap/session/vuln/set-cookie              # SID=... (no flags)
 *   GET  /roadmap/session/secure/set-cookie            # HttpOnly; Secure; SameSite=Strict
 * </pre>
 *
 * <p>Note: in a real app you would not hand-roll this — Spring Security rotates
 * the session on authentication by default (session-fixation protection =
 * {@code changeSessionId}) and {@code server.servlet.session.cookie.*} sets the
 * flags. These endpoints make the mechanism visible.
 */
@RestController
@RequestMapping("/roadmap/session")
public class SessionSecurityController {

    @GetMapping(value = "/whoami", produces = "application/json")
    public Map<String, Object> whoami(HttpServletRequest request) {
        HttpSession session = request.getSession(true);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("sessionId", session.getId());
        out.put("authenticatedUser", session.getAttribute("user"));
        return out;
    }

    // ---------------------------------------------------------------------
    // VULNERABLE — authenticates the caller into the SAME session id. A
    // pre-planted (fixed) session id survives the login. CWE-384.
    // ---------------------------------------------------------------------
    @PostMapping(value = "/vuln/login", produces = "application/json")
    public Map<String, Object> vulnLogin(@RequestParam String user, HttpServletRequest request) {
        HttpSession session = request.getSession(true);
        String before = session.getId();
        session.setAttribute("user", user);          // privilege granted, id unchanged
        String after = session.getId();

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("sessionIdBefore", before);
        out.put("sessionIdAfter", after);
        out.put("sessionIdChanged", !before.equals(after));
        out.put("note", "Session id was NOT rotated on login — vulnerable to fixation.");
        return out;
    }

    // ---------------------------------------------------------------------
    // SECURE — rotate the session id at the privilege boundary. The old
    // (possibly attacker-known) id is invalidated; the authenticated state
    // lives only under the fresh id.
    // ---------------------------------------------------------------------
    @PostMapping(value = "/secure/login", produces = "application/json")
    public Map<String, Object> secureLogin(@RequestParam String user, HttpServletRequest request) {
        HttpSession session = request.getSession(true);
        String before = session.getId();
        // Servlet 3.1+ : new id, same session data, old id invalidated.
        request.changeSessionId();
        session = request.getSession(true);
        session.setAttribute("user", user);
        String after = session.getId();

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("sessionIdBefore", before);
        out.put("sessionIdAfter", after);
        out.put("sessionIdChanged", !before.equals(after));
        out.put("note", "Session id rotated on login (changeSessionId) — fixation neutralised.");
        return out;
    }

    // ---------------------------------------------------------------------
    // VULNERABLE cookie — no HttpOnly, no Secure, no SameSite. Readable by JS
    // (XSS theft), sent over plain HTTP, and attached on cross-site requests.
    // ---------------------------------------------------------------------
    @GetMapping(value = "/vuln/set-cookie", produces = "text/plain")
    public String vulnCookie(HttpServletResponse response) {
        Cookie c = new Cookie("SID", "demo-session-value");
        c.setPath("/");
        // (deliberately no flags set)
        response.addCookie(c);
        return "Set an insecure SID cookie (no HttpOnly/Secure/SameSite). Inspect with curl -i.";
    }

    // ---------------------------------------------------------------------
    // SECURE cookie — HttpOnly + Secure + SameSite=Strict. The Servlet Cookie
    // API has no SameSite setter, so set the header directly.
    // ---------------------------------------------------------------------
    @GetMapping(value = "/secure/set-cookie", produces = "text/plain")
    public String secureCookie(HttpServletResponse response) {
        response.addHeader("Set-Cookie",
                "SID=demo-session-value; Path=/; HttpOnly; Secure; SameSite=Strict");
        return "Set a hardened SID cookie (HttpOnly; Secure; SameSite=Strict). Inspect with curl -i.";
    }
}

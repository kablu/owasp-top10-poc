package com.security.poc.roadmap.ldap;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Roadmap Phase 4 — Injection: <b>LDAP injection</b>.
 *
 * <p>Especially relevant to directory-backed systems (e.g. an RA that authenticates
 * users against Active Directory). When user input is concatenated straight into
 * an LDAP search filter, an attacker can rewrite the filter logic — bypass an
 * authentication filter, widen a search, or turn a scoped lookup into "match all".
 *
 * <p>This is a <b>safe, self-contained</b> demo: there is no live LDAP server. We
 * build the filter string exactly as an app would and show how it changes, then
 * model the bind outcome. The security property is simple and honest: once every
 * value is escaped per RFC 4515, metacharacters are inert, so the bind behaves as
 * a plain literal lookup and injection payloads simply fail to match. CWE-90.
 *
 * <pre>
 *   # normal lookup — authenticated=true on both
 *   GET /roadmap/ldap/vuln/login?user=alice&password=alice123
 *   GET /roadmap/ldap/secure/login?user=alice&password=alice123
 *
 *   # injection: wildcard / filter rewrite to bypass the password check
 *   GET /roadmap/ldap/vuln/login?user=*)(uid=*))(|(uid=*&password=anything   # true  (bypass)
 *   GET /roadmap/ldap/secure/login?user=*)(uid=*))(|(uid=*&password=anything # false (escaped)
 * </pre>
 */
@RestController
@RequestMapping("/roadmap/ldap")
public class LdapInjectionController {

    // Tiny in-memory "directory": uid -> userPassword.
    private static final Map<String, String> DIRECTORY = Map.of(
            "alice", "alice123",
            "bob", "bob123",
            "admin", "admin123");

    // ---------------------------------------------------------------------
    // VULNERABLE — raw concatenation into the search filter. The attacker
    // controls the filter grammar, not just a value, so metacharacters in the
    // input rewrite the filter and bypass the password term. CWE-90.
    // ---------------------------------------------------------------------
    @GetMapping(value = "/vuln/login", produces = "application/json")
    public Map<String, Object> vulnLogin(@RequestParam String user,
                                         @RequestParam String password) {
        String filter = "(&(uid=" + user + ")(userPassword=" + password + "))";

        // Unescaped metacharacters mean the attacker reshaped the filter: model
        // that as a successful bind (the real-world auth-bypass outcome).
        boolean injected = containsLdapMeta(user) || containsLdapMeta(password);
        boolean authenticated = injected || password.equals(DIRECTORY.get(user));

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("composedFilter", filter);
        out.put("injectionDetected", injected);
        out.put("authenticated", authenticated);
        out.put("note", "Filter grammar is attacker-controlled — metacharacters rewrite the uid/password terms.");
        return out;
    }

    // ---------------------------------------------------------------------
    // SECURE — escape every user-supplied value per RFC 4515 BEFORE it enters
    // the filter. After escaping, '(' ')' '*' '\' and NUL become \28 \29 \2a
    // \5c \00, so the attacker can no longer break out of the value position;
    // the bind degrades to a literal lookup and injection payloads just miss.
    // (In real Spring code, prefer LdapQueryBuilder / parameterised filters,
    // which perform this escaping for you.)
    // ---------------------------------------------------------------------
    @GetMapping(value = "/secure/login", produces = "application/json")
    public Map<String, Object> secureLogin(@RequestParam String user,
                                           @RequestParam String password) {
        String filter = "(&(uid=" + escapeFilterValue(user)
                + ")(userPassword=" + escapeFilterValue(password) + "))";

        // Metacharacters are now inert → behaviour is a plain literal lookup.
        boolean authenticated = password.equals(DIRECTORY.get(user));

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("composedFilter", filter);
        out.put("authenticated", authenticated);
        out.put("note", "Values escaped per RFC 4515 — metacharacters are inert, the filter grammar is fixed.");
        return out;
    }

    private static boolean containsLdapMeta(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '(' || c == ')' || c == '*' || c == '\\' || c == '&'
                    || c == '|' || c == '\0') {
                return true;
            }
        }
        return false;
    }

    /** RFC 4515 §3 filter-value escaping. */
    private static String escapeFilterValue(String raw) {
        StringBuilder sb = new StringBuilder(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\5c");
                case '*'  -> sb.append("\\2a");
                case '('  -> sb.append("\\28");
                case ')'  -> sb.append("\\29");
                case '\0' -> sb.append("\\00");
                default   -> sb.append(c);
            }
        }
        return sb.toString();
    }
}

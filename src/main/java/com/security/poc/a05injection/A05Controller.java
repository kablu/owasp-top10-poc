package com.security.poc.a05injection;

import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A05:2025 — Injection (SQL injection variant).
 *
 * <p>Both endpoints "search users by username". The vulnerable one builds SQL by
 * string concatenation; the secure one uses a bound parameter so input can never
 * change the query structure.
 */
@RestController
@RequestMapping("/a05")
public class A05Controller {

    private final JdbcTemplate jdbc;

    public A05Controller(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    // -----------------------------------------------------------------------
    // VULNERABLE: user input is concatenated straight into the SQL text.
    //   Exploit:  /a05/vuln/search?username=' OR '1'='1
    //             -> dumps every row (auth/data-exfil bypass)
    //   Exploit:  /a05/vuln/search?username=x' UNION SELECT ssn,ssn,ssn FROM ...
    // -----------------------------------------------------------------------
    @GetMapping("/vuln/search")
    public List<Map<String, Object>> vulnSearch(@RequestParam String username) {
        String sql = "SELECT id, username, role FROM app_users WHERE username = '" + username + "'";
        return jdbc.queryForList(sql);   // input becomes code
    }

    // -----------------------------------------------------------------------
    // SECURE: parameterized query (PreparedStatement). The '?' placeholder is
    // bound as data, so "' OR '1'='1" is treated as a literal username and
    // simply matches nothing.
    // -----------------------------------------------------------------------
    @GetMapping("/secure/search")
    public List<Map<String, Object>> secureSearch(@RequestParam String username) {
        String sql = "SELECT id, username, role FROM app_users WHERE username = ?";
        return jdbc.queryForList(sql, username);
    }
}

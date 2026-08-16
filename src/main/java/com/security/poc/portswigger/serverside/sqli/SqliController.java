package com.security.poc.portswigger.serverside.sqli;

import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PortSwigger topic: <b>SQL injection</b> (Server-side).
 * <a href="https://portswigger.net/web-security/sql-injection">Reference</a>
 *
 * <p>Scenario mirrors the PortSwigger "product category filter" lab: a category
 * name is taken from the request and used to build a SQL query. Because the two
 * demos share the {@code app_users} table seeded by the A05 package, the same
 * classic payloads work here.
 *
 * <p>Attacks demonstrated:
 * <ul>
 *   <li><b>Filter bypass</b> — {@code ?role=USER'--} comments out the rest.</li>
 *   <li><b>Boolean/authentication bypass</b> — {@code ?role=x' OR '1'='1}.</li>
 *   <li><b>UNION exfiltration</b> — {@code ?role=x' UNION SELECT id,secret,role FROM app_users--}
 *       pulls the hidden {@code secret} column into the result set.</li>
 * </ul>
 */
@RestController
@RequestMapping("/ps/serverside/sqli")
public class SqliController {

    private final JdbcTemplate jdbc;

    public SqliController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    // -----------------------------------------------------------------------
    // VULNERABLE
    // The user-controlled `role` is concatenated directly into the SQL text, so
    // the input can terminate the string literal ('), inject new clauses
    // (OR, UNION), or comment out the trailing query (--). Input becomes code.
    // -----------------------------------------------------------------------
    @GetMapping("/vuln/users")
    public List<Map<String, Object>> vulnByRole(@RequestParam String role) {
        String sql = "SELECT id, username, role FROM app_users WHERE role = '" + role + "'";
        return jdbc.queryForList(sql);
    }

    // -----------------------------------------------------------------------
    // SECURE
    // The value is passed as a bound parameter (PreparedStatement). The database
    // compiles the query structure first, then treats the input purely as data,
    // so "USER'--" is looked up as a literal role that simply matches nothing.
    // Defence-in-depth: also validate against an allowlist of expected roles.
    // -----------------------------------------------------------------------
    @GetMapping("/secure/users")
    public List<Map<String, Object>> secureByRole(@RequestParam String role) {
        if (!List.of("USER", "ADMIN").contains(role)) {
            return List.of(Map.of("error", "unknown role"));
        }
        String sql = "SELECT id, username, role FROM app_users WHERE role = ?";
        return jdbc.queryForList(sql, role);
    }
}

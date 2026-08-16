package com.security.poc.clientside;

import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Client-side vulnerabilities demo (from Phase 2 of the learning plan):
 * <b>XSS</b> (reflected + stored) and <b>CSRF</b>. Unlike the a01..a10 REST
 * packages this one renders Thymeleaf HTML over a cookie-based session, because
 * these attacks live in the browser.
 *
 * <ul>
 *   <li>Reflected XSS — {@code /clientside/{vuln|secure}/greet?name=...}</li>
 *   <li>Stored XSS     — {@code /clientside/{vuln|secure}/comments}</li>
 *   <li>CSRF           — {@code /clientside/{vuln|secure}/change-email}</li>
 * </ul>
 */
@Controller
@RequestMapping("/clientside")
public class ClientSideController {

    // Separate stored-comment lists so the vuln and secure boards don't mix.
    private final List<String> vulnComments = new ArrayList<>(List.of("Welcome to the board!"));
    private final List<String> secureComments = new ArrayList<>(List.of("Welcome to the board!"));

    // "Account email" per demo side (in a real app this is per-user in the DB).
    private String vulnEmail = "salman@example.com";
    private String secureEmail = "salman@example.com";

    @GetMapping({"", "/"})
    public String menu() {
        return "clientside/menu";
    }

    // ---------------- Reflected XSS ----------------

    // VULN: the template prints `name` with th:utext (unescaped) -> a payload
    // like ?name=<script>alert(document.cookie)</script> executes.
    @GetMapping("/vuln/greet")
    public String vulnGreet(@RequestParam(defaultValue = "guest") String name, Model model) {
        model.addAttribute("name", name);
        model.addAttribute("escaped", false);
        return "clientside/greet";
    }

    // SECURE: same data via th:text (auto HTML-escaped) -> payload shown as text.
    @GetMapping("/secure/greet")
    public String secureGreet(@RequestParam(defaultValue = "guest") String name, Model model) {
        model.addAttribute("name", name);
        model.addAttribute("escaped", true);
        return "clientside/greet";
    }

    // ---------------- Stored XSS ----------------

    @GetMapping("/vuln/comments")
    public String vulnComments(Model model) {
        model.addAttribute("comments", vulnComments);
        model.addAttribute("escaped", false);
        model.addAttribute("postPath", "/clientside/vuln/comments");
        return "clientside/comments";
    }

    @PostMapping("/vuln/comments")
    public String addVulnComment(@RequestParam String text) {
        vulnComments.add(text);                // stored raw; rendered unescaped later
        return "redirect:/clientside/vuln/comments";
    }

    @GetMapping("/secure/comments")
    public String secureComments(Model model) {
        model.addAttribute("comments", secureComments);
        model.addAttribute("escaped", true);
        model.addAttribute("postPath", "/clientside/secure/comments");
        return "clientside/comments";
    }

    @PostMapping("/secure/comments")
    public String addSecureComment(@RequestParam String text) {
        secureComments.add(text);              // stored, but rendered escaped (th:text)
        return "redirect:/clientside/secure/comments";
    }

    // ---------------- CSRF ----------------

    // VULN: CSRF is ignored for /clientside/vuln/** (see SecurityConfig). This
    // state-changing POST accepts a request with no anti-CSRF token, so any
    // external site can auto-submit a hidden form and change the victim's email.
    @GetMapping("/vuln/change-email")
    public String vulnEmailForm(Model model) {
        model.addAttribute("currentEmail", vulnEmail);
        model.addAttribute("secure", false);
        model.addAttribute("postPath", "/clientside/vuln/change-email");
        return "clientside/email";
    }

    @PostMapping("/vuln/change-email")
    public String vulnChangeEmail(@RequestParam String email, Model model) {
        vulnEmail = email;
        model.addAttribute("currentEmail", vulnEmail);
        model.addAttribute("secure", false);
        model.addAttribute("postPath", "/clientside/vuln/change-email");
        model.addAttribute("changed", true);
        return "clientside/email";
    }

    // SECURE: CSRF protection is ON for /clientside/secure/**. The form must
    // carry the synchronizer token (added in the template); a forged cross-site
    // POST without it is rejected with 403 by Spring Security's CsrfFilter.
    @GetMapping("/secure/change-email")
    public String secureEmailForm(Model model) {
        model.addAttribute("currentEmail", secureEmail);
        model.addAttribute("secure", true);
        model.addAttribute("postPath", "/clientside/secure/change-email");
        return "clientside/email";
    }

    @PostMapping("/secure/change-email")
    public String secureChangeEmail(@RequestParam String email, Model model) {
        secureEmail = email;
        model.addAttribute("currentEmail", secureEmail);
        model.addAttribute("secure", true);
        model.addAttribute("postPath", "/clientside/secure/change-email");
        model.addAttribute("changed", true);
        return "clientside/email";
    }
}

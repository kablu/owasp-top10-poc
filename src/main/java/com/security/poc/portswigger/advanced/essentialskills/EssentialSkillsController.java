package com.security.poc.portswigger.advanced.essentialskills;

import java.util.List;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PortSwigger topic: <b>Essential skills</b>.
 * <a href="https://portswigger.net/web-security/essential-skills">Reference</a>
 *
 * <p>Unlike the other topics this is <b>methodology</b>, not a specific bug, so
 * there is no vulnerable/secure code pair. This endpoint is a quick reference to
 * the cross-cutting skills the Web Security Academy groups here, so the package
 * set stays complete against the "All topics" list.
 */
@RestController
@RequestMapping("/ps/advanced/essentialskills")
public class EssentialSkillsController {

    @GetMapping("/reference")
    public Map<String, Object> reference() {
        return Map.of(
            "topic", "Essential skills (methodology, not a single vulnerability)",
            "skills", List.of(
                "Obfuscating attacks using encodings (URL/HTML/Unicode/double-encoding)",
                "Using Burp Scanner to find vulnerabilities",
                "Exploiting vulnerabilities in APIs (recon, hidden params, mass assignment)",
                "Working with WebSockets in Burp Repeater",
                "Performing out-of-band (OAST) interactions with Burp Collaborator",
                "Escalating and chaining low-severity bugs into high impact"
            ),
            "note", "See the per-topic packages for concrete vulnerable/secure code examples."
        );
    }
}

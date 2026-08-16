package com.security.poc.portswigger.clientside.xss;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

/**
 * PortSwigger topic: <b>Cross-site scripting (XSS)</b>.
 * <a href="https://portswigger.net/web-security/cross-site-scripting">Reference</a>
 *
 * <p>Reflected XSS: a search term is echoed back inside the HTML response. The
 * vulnerable endpoint inserts it raw, so {@code <script>} executes in the
 * victim's browser; the secure endpoint HTML-encodes it so it renders as text.
 *
 * <p>Open in a browser (not Postman) to see the script actually fire, e.g.
 * {@code /vuln/search?q=<script>alert(document.domain)</script>}.
 */
@RestController
@RequestMapping("/ps/clientside/xss")
public class XssController {

    // -----------------------------------------------------------------------
    // VULNERABLE
    // User input is concatenated into the HTML with no encoding -> the browser
    // parses the injected markup/script as part of the page.
    // -----------------------------------------------------------------------
    @GetMapping(value = "/vuln/search", produces = MediaType.TEXT_HTML_VALUE)
    public String vulnSearch(@RequestParam(defaultValue = "shoes") String q) {
        return "<html><body><h2>Results for: " + q + "</h2></body></html>";
    }

    // -----------------------------------------------------------------------
    // SECURE
    // Contextual output encoding: HtmlUtils.htmlEscape() turns < > " & etc. into
    // entities, so the payload is displayed literally and never interpreted.
    // (Template engines like Thymeleaf do this automatically with th:text.)
    // -----------------------------------------------------------------------
    @GetMapping(value = "/secure/search", produces = MediaType.TEXT_HTML_VALUE)
    public String secureSearch(@RequestParam(defaultValue = "shoes") String q) {
        String safe = HtmlUtils.htmlEscape(q);
        return "<html><body><h2>Results for: " + safe + "</h2></body></html>";
    }
}

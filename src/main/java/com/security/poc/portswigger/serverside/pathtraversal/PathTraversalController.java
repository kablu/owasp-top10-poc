package com.security.poc.portswigger.serverside.pathtraversal;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import jakarta.annotation.PostConstruct;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PortSwigger topic: <b>Path traversal</b> (a.k.a. directory traversal).
 * <a href="https://portswigger.net/web-security/file-path-traversal">Reference</a>
 *
 * <p>A "download product image" feature reads a file whose name comes from the
 * request. The intended files live under a sandbox directory; the vulnerable
 * endpoint lets {@code ../} sequences escape it and read arbitrary files
 * (the lab equivalent of {@code filename=../../../../etc/passwd}).
 *
 * <p>On startup we create a temp sandbox with a public {@code image.txt} and,
 * one level up (outside the sandbox), a {@code secret.txt} the attacker targets.
 */
@RestController
@RequestMapping("/ps/serverside/pathtraversal")
public class PathTraversalController {

    private Path sandbox;   // intended, public directory
    private Path outside;   // parent dir holding a secret the user must not read

    @PostConstruct
    void setup() throws IOException {
        outside = Files.createTempDirectory("pt-demo-");
        Files.writeString(outside.resolve("secret.txt"), "TOP-SECRET: do not expose me");
        sandbox = Files.createDirectory(outside.resolve("public"));
        Files.writeString(sandbox.resolve("image.txt"), "harmless public image bytes");
    }

    // -----------------------------------------------------------------------
    // VULNERABLE
    // The filename is appended to the base path with no validation, so a value
    // like "../secret.txt" resolves outside the intended folder. Reading files
    // by attacker-chosen path leaks credentials, config and source.
    //   Exploit:  /vuln/download?filename=../secret.txt
    // -----------------------------------------------------------------------
    @GetMapping("/vuln/download")
    public ResponseEntity<?> vulnDownload(@RequestParam String filename) {
        try {
            Path target = sandbox.resolve(filename);            // no containment check
            String body = Files.readString(target, StandardCharsets.UTF_8);
            return ResponseEntity.ok(Map.of("path", target.toString(), "content", body));
        } catch (IOException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // -----------------------------------------------------------------------
    // SECURE
    // Canonicalise the resolved path and verify it still sits INSIDE the sandbox
    // before reading. Traversal sequences are normalised away by normalize(),
    // then startsWith() rejects anything that escaped. (Also strip path
    // separators from the input as defence-in-depth.)
    // -----------------------------------------------------------------------
    @GetMapping("/secure/download")
    public ResponseEntity<?> secureDownload(@RequestParam String filename) {
        try {
            Path base = sandbox.toRealPath();
            Path target = base.resolve(filename).normalize();
            if (!target.startsWith(base)) {
                return ResponseEntity.status(403).body(Map.of("error", "path traversal blocked"));
            }
            String body = Files.readString(target, StandardCharsets.UTF_8);
            return ResponseEntity.ok(Map.of("path", target.toString(), "content", body));
        } catch (IOException e) {
            return ResponseEntity.badRequest().body(Map.of("error", "not found"));
        }
    }
}

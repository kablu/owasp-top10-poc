package com.security.poc.portswigger.serverside.commandinjection;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PortSwigger topic: <b>OS command injection</b>.
 * <a href="https://portswigger.net/web-security/os-command-injection">Reference</a>
 *
 * <p>A "check stock / ping host" feature runs a shell command that embeds user
 * input. Shell metacharacters ({@code ; | & && || `` $()}) let an attacker chain
 * their own commands.
 *
 * <p><b>Safety note:</b> to keep this PoC harmless we do NOT actually spawn a
 * shell. The vulnerable method builds the exact command string a naive
 * implementation would pass to {@code Runtime.exec("sh -c ...")} and reports the
 * injected portion, so you can see how the payload breaks out — without running
 * it. The real vulnerable call is shown in comments.
 */
@RestController
@RequestMapping("/ps/serverside/commandinjection")
public class CommandInjectionController {

    /** Characters that let input escape into a new shell command. */
    private static final Pattern SHELL_METACHARS = Pattern.compile("[;&|`$()<>\\n\\r]");
    /** A hostname allowlist pattern (letters, digits, dot, hyphen). */
    private static final Pattern SAFE_HOST = Pattern.compile("^[A-Za-z0-9.-]{1,253}$");

    // -----------------------------------------------------------------------
    // VULNERABLE
    // The host is concatenated straight into a shell command line. A value like
    //   127.0.0.1; cat /etc/passwd
    // turns one command into two. The dangerous real-world call would be:
    //   Runtime.getRuntime().exec(new String[]{"sh","-c", "ping -c 1 " + host});
    // -----------------------------------------------------------------------
    @GetMapping("/vuln/ping")
    public Map<String, Object> vulnPing(@RequestParam String host) {
        String command = "ping -c 1 " + host;          // <-- injection point
        boolean injected = SHELL_METACHARS.matcher(host).find();
        // Runtime.getRuntime().exec(new String[]{"sh","-c", command});  // NEVER do this
        return Map.of(
            "commandThatWouldRun", command,
            "shellInjectionDetected", injected,
            "note", injected
                ? "Everything after the metacharacter runs as a SEPARATE command."
                : "No metacharacters this time, but the pattern is still exploitable."
        );
    }

    // -----------------------------------------------------------------------
    // SECURE
    //   1) Validate input against a strict allowlist (reject anything unusual).
    //   2) Never build a shell string; pass arguments as a discrete array so
    //      there is no shell to interpret metacharacters (ProcessBuilder).
    //   3) Best of all: avoid the OS command entirely (use a library/API).
    // -----------------------------------------------------------------------
    @GetMapping("/secure/ping")
    public ResponseEntity<?> securePing(@RequestParam String host) {
        if (!SAFE_HOST.matcher(host).matches()) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid hostname — rejected"));
        }
        // Arguments passed as a list -> no shell, so ';' etc. are literal args,
        // not command separators. (Not executed here; shown for illustration.)
        List<String> argv = List.of("ping", "-c", "1", host);
        return ResponseEntity.ok(Map.of(
            "argv", argv,
            "note", "No shell involved; each element is a single, un-interpreted argument."
        ));
    }
}

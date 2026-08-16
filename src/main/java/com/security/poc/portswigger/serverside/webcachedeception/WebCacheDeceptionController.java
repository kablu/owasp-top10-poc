package com.security.poc.portswigger.serverside.webcachedeception;

import java.util.Map;

import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PortSwigger topic: <b>Web cache deception</b>.
 * <a href="https://portswigger.net/web-security/web-cache-deception">Reference</a>
 *
 * <p>A CDN/cache is often configured to cache "static" paths by extension
 * (e.g. anything ending {@code .css}, {@code .js}, {@code .jpg}). If the app
 * serves a user's private page for a URL like {@code /account/wcd.css} — because
 * the framework ignores the extra suffix — the cache stores that personal
 * response and later serves it to <i>other</i> users. The victim's data leaks
 * via the shared cache.
 *
 * <p>The {@code Cache-Control} header this app returns is what a well-behaved
 * cache honours; the demo shows the vulnerable vs secure caching directive.
 */
@RestController
@RequestMapping("/ps/serverside/webcachedeception")
public class WebCacheDeceptionController {

    // -----------------------------------------------------------------------
    // VULNERABLE
    // Returns PERSONAL data with a cacheable directive (or none), and doesn't
    // care that the path carries a ".css" suffix. A cache keying on extension
    // will store this user-specific body and replay it to everyone.
    //   Attack path:  trick victim into visiting /vuln/profile/wcd.css, then the
    //   attacker requests the same cached URL and reads the victim's profile.
    // -----------------------------------------------------------------------
    @GetMapping({"/vuln/profile", "/vuln/profile/**"})
    public ResponseEntity<?> vulnProfile(@RequestHeader(value = "X-User", defaultValue = "salman") String user) {
        return ResponseEntity.ok()
            .header("Cache-Control", "public, max-age=60")   // caches personal data!
            .body(Map.of("user", user, "apiKey", user + "-PRIVATE-KEY",
                    "note", "Personal body marked publicly cacheable — cache deception risk."));
    }

    // -----------------------------------------------------------------------
    // SECURE
    //   - Mark all authenticated/personal responses no-store so no cache keeps
    //     them, regardless of the URL's apparent extension.
    //   - (Also fix at the edge: cache by full path + content-type, and don't
    //     cache responses to authenticated requests.)
    // -----------------------------------------------------------------------
    @GetMapping({"/secure/profile", "/secure/profile/**"})
    public ResponseEntity<?> secureProfile(@RequestHeader(value = "X-User", defaultValue = "salman") String user) {
        return ResponseEntity.ok()
            .cacheControl(CacheControl.noStore().cachePrivate())
            .body(Map.of("user", user, "apiKey", user + "-PRIVATE-KEY",
                    "note", "Cache-Control: no-store, private — never cached or shared."));
    }
}

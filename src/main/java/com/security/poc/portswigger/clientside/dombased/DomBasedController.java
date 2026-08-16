package com.security.poc.portswigger.clientside.dombased;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PortSwigger topic: <b>DOM-based vulnerabilities</b> (DOM XSS).
 * <a href="https://portswigger.net/web-security/dom-based">Reference</a>
 *
 * <p>DOM-based XSS happens entirely in the browser: JavaScript takes data from an
 * attacker-controllable <i>source</i> (e.g. {@code location.hash}) and passes it
 * to a dangerous <i>sink</i> (e.g. {@code innerHTML}) without sanitisation. The
 * server never sees the payload, so server-side encoding alone can't fix it —
 * the fix is in the client JS: use safe sinks ({@code textContent}) or sanitise.
 *
 * <p>Open the pages in a browser and append a hash, e.g.
 * {@code /vuln/page#<img src=x onerror=alert(1)>}
 */
@RestController
@RequestMapping("/ps/clientside/dombased")
public class DomBasedController {

    // -----------------------------------------------------------------------
    // VULNERABLE
    // Client JS reads location.hash (source) and writes it into innerHTML (sink).
    // The markup in the fragment is parsed and executed by the browser.
    // -----------------------------------------------------------------------
    @GetMapping(value = "/vuln/page", produces = MediaType.TEXT_HTML_VALUE)
    public String vulnPage() {
        return """
            <html><body>
              <h2>Welcome</h2>
              <div id="out"></div>
              <script>
                // SOURCE: attacker-controlled fragment; SINK: innerHTML (dangerous)
                var name = decodeURIComponent(location.hash.slice(1));
                document.getElementById('out').innerHTML = 'Hi ' + name;   // DOM XSS
              </script>
            </body></html>
            """;
    }

    // -----------------------------------------------------------------------
    // SECURE
    // Same data flow, but the sink is textContent, which never parses HTML — the
    // payload is inserted as inert text. (Alternatively sanitise with a trusted
    // library / use safe framework bindings.)
    // -----------------------------------------------------------------------
    @GetMapping(value = "/secure/page", produces = MediaType.TEXT_HTML_VALUE)
    public String securePage() {
        return """
            <html><body>
              <h2>Welcome</h2>
              <div id="out"></div>
              <script>
                var name = decodeURIComponent(location.hash.slice(1));
                document.getElementById('out').textContent = 'Hi ' + name;  // safe sink
              </script>
            </body></html>
            """;
    }
}

# OWASP Top 10:2025 — Spring Boot + Spring Security PoC

A hands-on lab that demonstrates each **OWASP Top 10:2025** category with a
**vulnerable** endpoint and its **secure** counterpart, side by side. Built with
**Java 21 + Spring Boot 3.3 + Spring Security**. Every category lives in its own
package so you can study them in isolation.

> ⚠️ **Lab use only.** The `/vuln/**` endpoints are intentionally insecure.
> Never deploy this application to a public/shared environment.

---

## Run it

```bash
./gradlew bootRun
```

App starts on <http://localhost:8080>. Open `/` for a plain-text index of every
endpoint. H2 console (demo only) is at `/h2-console`
(JDBC URL `jdbc:h2:mem:owaspdb`, user `sa`, empty password).

### Demo users

| Username | Password    | Roles              | Account id |
|----------|-------------|--------------------|------------|
| alice    | `alice123`  | USER               | 1          |
| bob      | `bob123`    | USER               | 2          |
| admin    | `admin123`  | USER + ADMIN       | —          |

Secure endpoints use **HTTP Basic** (`curl -u alice:alice123 ...`), except
`/a07/secure/login` which is public (it *is* the login).

---

## Package layout

```
com.security.poc
├── common                         SecurityConfig, HomeController (index)
├── a01brokenaccesscontrol         IDOR + privilege escalation
├── a02securitymisconfiguration    info-leak config + security headers
├── a03supplychain                 dependency pinning / integrity policy
├── a04cryptographicfailures       Base64/MD5  vs  AES-GCM + BCrypt
├── a05injection                   SQL injection  vs  parameterized query
├── a06insecuredesign              missing single-use + rate-limit controls
├── a07authenticationfailures      plaintext/weak-JWT  vs  BCrypt+lockout+strong-JWT
├── a08integrityfailures           Java deserialization  vs  HMAC-signed JSON
├── a09loggingfailures             no audit trail  vs  structured audit + alerting
├── a10exceptionalconditions       stack-trace leak / fail-open  vs  sanitized fail-closed
└── clientside                     XSS (reflected + stored) + CSRF, Thymeleaf session demo
```

---

## The 10 categories

### A01 — Broken Access Control
**Vuln:** `GET /a01/vuln/account/{id}` returns any account by id (IDOR — no
ownership check).
**Secure:** `GET /a01/secure/account/{id}` verifies the authenticated caller owns
the object (or is admin) and returns `403` otherwise; `GET /a01/secure/admin/dashboard`
is gated with `@PreAuthorize("hasRole('ADMIN')")`.

```bash
curl "http://localhost:8080/a01/vuln/account/2"                       # leaks bob's card
curl -u alice:alice123 "http://localhost:8080/a01/secure/account/2"   # 403 Forbidden
```

### A02 — Security Misconfiguration
**Vuln:** `GET /a02/vuln/config` dumps DB creds, JWT secret, internal hosts,
versions.
**Secure:** `GET /a02/secure/config` returns only `{"status":"UP"}` and
`SecureHeadersConfig` attaches CSP / X-Frame-Options / HSTS / nosniff headers.

### A03 — Software Supply Chain Failures *(new in 2025)*
**Vuln:** `GET /a03/vuln/dependency-check` — dynamic versions, untrusted mirror,
no checksums/scanning.
**Secure:** `GET /a03/secure/dependency-check` — `DependencyPolicy` rejects
unpinned versions and denylisted packages. Build-side controls: Gradle dependency
locking, HTTPS-only `mavenCentral()`, and a CI CVE scan.

### A04 — Cryptographic Failures
**Vuln:** `POST /a04/vuln/store?data=...` — Base64 ("encryption theatre") + MD5.
**Secure:** `POST /a04/secure/store?data=...` — AES-256-GCM with a random IV per
message (authenticated encryption) + BCrypt password hashing. Key from config,
never hardcoded.

### A05 — Injection (SQLi)
**Vuln:** `GET /a05/vuln/search?username=...` concatenates input into SQL.
**Secure:** `GET /a05/secure/search?username=...` uses a bound `?` parameter.

```bash
curl "http://localhost:8080/a05/vuln/search?username=' OR '1'='1"            # dumps all rows
curl -u alice:alice123 "http://localhost:8080/a05/secure/search?username=' OR '1'='1"  # []
```

### A06 — Insecure Design
**Vuln:** `POST /a06/vuln/redeem?code=...` — a discount code with no single-use
and no rate limit (business-logic abuse).
**Secure:** `POST /a06/secure/redeem?code=...` — atomic single-use enforcement
(`409` on reuse) + fixed-window rate limit (`429`). *Insecure design is a missing
control, not a code bug — you design it in, you don't patch it.*

### A07 — Authentication Failures
**Vuln:** `POST /a07/vuln/login` — plaintext password compare, user enumeration,
no lockout, long-lived token signed with a guessable key.
**Secure:** `POST /a07/secure/login` — BCrypt verify, uniform error message,
account lockout after 5 failures (`423`), short-lived HS256 JWT with a strong key.

### A08 — Software / Data Integrity Failures
**Vuln:** `POST /a08/vuln/import` — native Java `ObjectInputStream` deserialization
of untrusted bytes (gadget-chain / RCE risk).
**Secure:** `POST /a08/secure/import` — HMAC-SHA256 signature verified (constant
time) *before* parsing, then bound only to a known DTO.

### A09 — Security Logging & Alerting Failures
**Vuln:** `POST /a09/vuln/transfer` — a money transfer with **no** audit trail
(and the "obvious fix" of logging the full card would leak PII).
**Secure:** `POST /a09/secure/transfer` — structured audit event (who/what/when/
outcome), PAN masked, and an alert raised when the amount crosses a threshold.

### A10 — Mishandling of Exceptional Conditions *(new in 2025)*
**Vuln:** `GET /a10/vuln/divide?a=..&b=..` returns the raw stack trace;
`GET /a10/vuln/access` **fails open** (exception → access granted).
**Secure:** `GET /a10/secure/divide` validates input and returns a generic error;
`GET /a10/secure/access` **fails closed**; `GlobalExceptionHandler` logs details
under a correlation id and returns only that id to the client.

### Client-side — XSS & CSRF (Phase 2 of the learning plan)
A Thymeleaf **session** demo (cookie-based, so CSRF is meaningful here). Open
<http://localhost:8080/clientside> for the menu.

- **Reflected XSS** — `GET /clientside/{vuln|secure}/greet?name=...`
  vuln uses `th:utext` (raw) so `<script>` runs; secure uses `th:text` (escaped).
  *Note:* Tomcat rejects raw `<`/`>` in a URL (400), so encode the payload:
  `?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E`.
- **Stored XSS** — `/clientside/{vuln|secure}/comments`
  post `<img src=x onerror=alert(1)>`; it fires on the vuln board for every
  visitor and is shown as inert text on the secure board.
- **CSRF** — `/clientside/{vuln|secure}/change-email`
  CSRF is **enabled** for `/clientside/secure/**`: the form carries the
  synchronizer token, and a POST without it gets `403`. The vuln path is
  exempt on purpose, so a forged cross-site POST succeeds.

```bash
# Reflected XSS: raw vs escaped
curl "http://localhost:8080/clientside/vuln/greet?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
curl "http://localhost:8080/clientside/secure/greet?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
# CSRF: secure POST without a token is rejected
curl -i -X POST "http://localhost:8080/clientside/secure/change-email?email=x@evil.com"  # 403
```

---

## PortSwigger Web Security Academy — all topics

A second, topic-wise PoC tree under `com.security.poc.portswigger`, mirroring the
[PortSwigger "All topics"](https://portswigger.net/web-security/all-topics) list.
Every topic is its own package with a `vuln` and a `secure` endpoint under
`/ps/{serverside|clientside|advanced}/<topic>/...` and detailed comments citing
the PortSwigger reference. These are stateless REST endpoints (public, CSRF-exempt)
so they drive cleanly from Postman/curl.

**Server-side** (`/ps/serverside`): SQL injection, Authentication, Path traversal,
Command injection, Business logic, Information disclosure, Access control,
File upload, Race conditions, SSRF, XXE, NoSQL injection, API testing (mass
assignment), Web cache deception.

**Client-side** (`/ps/clientside`): XSS, CSRF, CORS, Clickjacking, DOM-based,
WebSockets.

**Advanced** (`/ps/advanced`): Insecure deserialization, Web LLM attacks, GraphQL,
SSTI, Web cache poisoning, HTTP Host header, HTTP request smuggling (explainer),
OAuth, JWT attacks, Prototype pollution (Java analogue), Essential skills (reference).

> A few topics are demonstrated safely rather than as live weapons: command
> injection reports the composed command instead of spawning a shell; SSRF
> validates without making outbound calls; SSTI evaluates arithmetic but blocks
> RCE tokens; request smuggling is protocol-level so it ships as an explainer.
> Each such case is called out in that controller's comments.

### Postman collections
Import the three category collections from [`postman/`](postman/):

- `PortSwigger-ServerSide.postman_collection.json`
- `PortSwigger-ClientSide.postman_collection.json`
- `PortSwigger-Advanced.postman_collection.json`

Each has one folder per topic with the VULN and SECURE requests pre-filled
(payloads, headers, bodies). They use a `baseUrl` collection variable defaulting
to `http://localhost:8080`. A few chained requests (CSRF token, JWT mint) ask you
to paste a value from the previous response — noted in the request name.

Quick taste:
```bash
# SQLi filter bypass vs parameterized
curl "http://localhost:8080/ps/serverside/sqli/vuln/users?role=USER'--"
curl "http://localhost:8080/ps/serverside/sqli/secure/users?role=USER'--"
# SSTI: expression evaluated (49) vs treated as data
curl "http://localhost:8080/ps/advanced/ssti/vuln/render?name=\${7*7}"
```

---

## Roadmap gap-demos (`/roadmap/**` + `/actuator/**`)

A third tree under `com.security.poc.roadmap`, added to cover items from the
professional **pentest & vulnerability-assessment roadmap** that the OWASP /
PortSwigger trees above did not already demonstrate. Each is a `vuln` + `secure`
pair, stateless (curl/Postman friendly). Full phase → endpoint mapping is in
[`docs/roadmap-coverage.md`](docs/roadmap-coverage.md).

### SpEL injection — Phase 4 (CWE-917)
Spring-specific RCE primitive most generic scanners miss.
```bash
curl "http://localhost:8080/roadmap/spel/vuln/eval?expr=T(java.lang.Runtime)"     # type ref evaluates
curl "http://localhost:8080/roadmap/spel/secure/eval?expr=T(java.lang.Runtime)"   # rejected (allow-list + SimpleEvaluationContext)
```

### LDAP injection — Phase 4 (CWE-90)
Relevant to AD/directory-backed auth (e.g. an RA).
```bash
curl "http://localhost:8080/roadmap/ldap/vuln/login?user=alice)(%26)&password=x"    # authenticated=true (bypass)
curl "http://localhost:8080/roadmap/ldap/secure/login?user=alice)(%26)&password=x"  # authenticated=false (RFC 4515 escaping)
```

### Open redirect — Phase 4 (CWE-601)
```bash
curl -i "http://localhost:8080/roadmap/openredirect/vuln/go?next=https://evil.example"    # 302 off-site
curl -i "http://localhost:8080/roadmap/openredirect/secure/go?next=https://evil.example"  # 400 (allow-list)
```

### Session fixation & cookie flags — Phase 3 (CWE-384 / CWE-1004 / CWE-614)
```bash
curl -X POST "http://localhost:8080/roadmap/session/vuln/login?user=alice"     # sessionIdChanged=false
curl -X POST "http://localhost:8080/roadmap/session/secure/login?user=alice"   # sessionIdChanged=true
curl -i "http://localhost:8080/roadmap/session/secure/set-cookie"              # HttpOnly; Secure; SameSite=Strict
```

### Actuator exposure — Phase 1/5 (CWE-200)
Actuator is left **wide open on purpose** (`management.endpoints.web.exposure.include: "*"`).
```bash
curl "http://localhost:8080/actuator/env"      # leaks poc.jwt.strong-secret and more
curl "http://localhost:8080/actuator/beans"    # full app wiring
curl "http://localhost:8080/roadmap/actuator/explain"   # the secure posture, documented
```
Secure configuration lives in `roadmap/actuator/ActuatorSecurityNotes` (minimal
exposure, ADMIN-gated filter chain, separate management port).

## DAST-flagged points (`/roadmap/dast/**`)

Runtime issues a DAST scanner (OWASP ZAP / Burp) typically reports, each with a
`vuln` + `secure` pair.

### Insecure HTTP methods — CWE-650
```bash
curl -i -X DELETE http://localhost:8080/roadmap/dast/httpmethods/vuln/resource    # 200 (bad)
curl -i -X DELETE http://localhost:8080/roadmap/dast/httpmethods/secure/resource  # 405
```

### Cacheable sensitive data — CWE-525
```bash
curl -i http://localhost:8080/roadmap/dast/cache/vuln/balance      # Cache-Control: public, max-age=3600
curl -i http://localhost:8080/roadmap/dast/cache/secure/balance    # Cache-Control: no-store, ...
```

### Secret in URL / query string — CWE-598
```bash
curl -X POST "http://localhost:8080/roadmap/dast/url/vuln/reset?token=SECRET-123&newPass=p"   # token in URL/logs
curl -X POST  http://localhost:8080/roadmap/dast/url/secure/reset -H "X-Reset-Token: SECRET-123" -d newPass=p
```

### CRLF injection / HTTP response splitting — CWE-113
```bash
curl "http://localhost:8080/roadmap/dast/crlf/vuln/echo?value=hello%0d%0aSet-Cookie:%20x=1"
curl "http://localhost:8080/roadmap/dast/crlf/secure/echo?value=hello%0d%0aSet-Cookie:%20x=1"   # CR/LF stripped
```

## PKI CA ceremony with SoftHSM (`com.security.poc.pki`)

A BouncyCastle + PKCS#11 (SunPKCS11) flow that mirrors a real external-CA
enrolment (e.g. submitting a CSR to CCA India and binding the returned cert to an
HSM key). Keys are generated **inside SoftHSM** and never leave the token.

Steps: (1) Root CA keypair in HSM + self-sign → (2) Intermediate keypair in HSM +
PKCS#10 CSR → (3) Root signs the CSR (role of the external CA) → (4) bind the
issued cert to its HSM key and verify the chain.

### Prerequisites (WSL — the JVM must run where the native lib is)

```bash
# Linux JVM: a Windows JVM cannot load libsofthsm2.so
softhsm2-util --init-token --slot 0 --label ra-poc --so-pin 3537 --pin 1234
```

`softhsm-pkcs11.cfg` points SunPKCS11 at `/usr/lib/softhsm/libsofthsm2.so`,
`slotListIndex = 0`. Config/PIN are overridable via `pki.pkcs11.config` and
`pki.pkcs11.pin`.

### Run the whole ceremony standalone (inside WSL)

> **Do NOT run this from the IDE / Gradle on Windows.** SoftHSM's library is a
> Linux `.so`; a Windows JVM cannot load it, and Windows SunPKCS11 even rejects a
> `/usr/...` path with *"Absolute path required for library value"*. Build on
> Windows if you like (`gradlew compileJava`), but **run inside WSL**.

Easiest — the helper script (builds the classpath, picks the WSL JVM):

```bash
# in a WSL/Ubuntu shell
cd /mnt/c/eclipse-workspace/owasp-top10-poc
./run-pki-ceremony.sh                 # defaults: softhsm-pkcs11.cfg, PIN 1234
```

Or by hand:

```bash
BC=~/.gradle/caches/modules-2/files-2.1/org.bouncycastle   # or /mnt/c/Users/<you>/.gradle/...
CP="build/classes/java/main:$BC/bcprov-jdk18on/1.78.1/*/bcprov-jdk18on-1.78.1.jar:\
$BC/bcpkix-jdk18on/1.78.1/*/bcpkix-jdk18on-1.78.1.jar:\
$BC/bcutil-jdk18on/1.78.1/*/bcutil-jdk18on-1.78.1.jar"
~/jdk21/bin/java --add-modules jdk.crypto.cryptoki -cp "$CP" \
     com.security.poc.pki.PkiCeremonyRunner softhsm-pkcs11.cfg 1234
```

### Or step through it over REST (run the app in WSL)

```bash
curl -X POST http://localhost:8080/pki/root/create         # 1 keypair in HSM + self-sign
curl -X POST http://localhost:8080/pki/intermediate/csr    # 2 keypair in HSM + CSR
curl -X POST http://localhost:8080/pki/intermediate/sign   # 3 Root signs the CSR
curl -X POST http://localhost:8080/pki/chain/build         # 4 bind + verify chain
curl      http://localhost:8080/pki/entries                # HSM token aliases
```

Classes: `HsmContext` (opens the token), `CaCeremonyService` (BC ceremony,
Spring-free), `PkiController` (REST), `PkiCeremonyRunner` (standalone `main`).

## Navigable index

Open [`docs/index.html`](docs/index.html) in a browser for a single, filterable
page listing every demo as **Problem → Solution** (sidebar navigation + live
search box). The full roadmap phase → endpoint map is in
[`docs/roadmap-coverage.md`](docs/roadmap-coverage.md).

## Notes on Spring Security config

- `common/SecurityConfig` centralizes auth. Convention: `/a0X/vuln/**` is public,
  `/a0X/secure/**` requires authentication (exception: `/a07/secure/login`).
- Method security (`@EnableMethodSecurity`) drives the A01 admin gate.
- **CSRF is disabled** here because this is a *stateless* REST API using HTTP
  Basic (no session cookie for an attacker to ride). **A cookie/session browser
  app must keep CSRF protection ON** — do not copy this setting blindly.
- H2 console + verbose config are enabled only to make the A02 demo visible; a
  real deployment disables both.

## Build

```bash
./gradlew build        # compile + tests
./gradlew bootRun      # run on :8080
```

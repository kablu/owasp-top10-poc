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

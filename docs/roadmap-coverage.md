# Pentest roadmap → PoC endpoint coverage

This maps every item in the professional penetration-testing & vulnerability-assessment
roadmap (Phases 1–5) to a demonstrated **vulnerable + secure** endpoint in this project,
so nothing in the roadmap is left without a working example.

Legend: **[NEW]** = added under `com.security.poc.roadmap`; others were already present
in the OWASP Top 10 (`/a0X`) or PortSwigger (`/ps`) trees.

## Phase 1 — Reconnaissance / information gathering

| Roadmap item | Vuln → Secure endpoint | CWE |
|---|---|---|
| Actuator endpoint exposure **[NEW]** | `GET /actuator/env`, `/beans`, `/mappings` → `GET /roadmap/actuator/explain` (+ `ActuatorSecurityNotes`) | CWE-200 |
| Config / version info leak | `GET /a02/vuln/config` → `GET /a02/secure/config` | CWE-200 |
| Verbose error / stack-trace disclosure | `GET /a10/vuln/divide` → `GET /a10/secure/divide` | CWE-209 |
| Information disclosure (general) | `GET /ps/serverside/informationdisclosure/vuln/...` → `.../secure/...` | CWE-200 |

## Phase 2 — DAST-flagged runtime checks

| Roadmap item | Vuln → Secure endpoint | CWE |
|---|---|---|
| Insecure HTTP methods (PUT/DELETE/TRACE) **[NEW]** | `/roadmap/dast/httpmethods/vuln/resource` → `.../secure/resource` | CWE-650 |
| Cacheable sensitive data **[NEW]** | `/roadmap/dast/cache/vuln/balance` → `.../secure/balance` | CWE-525 |
| Secret in URL / query string **[NEW]** | `/roadmap/dast/url/vuln/reset` → `.../secure/reset` | CWE-598 |
| CRLF injection / response splitting **[NEW]** | `/roadmap/dast/crlf/vuln/echo` → `.../secure/echo` | CWE-113 |
| Missing security headers (CSP/HSTS/nosniff/frame) | `GET /a02/vuln/config` → `SecureHeadersConfig` | CWE-693 |
| Insecure session cookie flags | `/roadmap/session/vuln/set-cookie` → `.../secure/set-cookie` | CWE-1004/CWE-614 |
| Open redirect | `/roadmap/openredirect/vuln/go` → `.../secure/go` | CWE-601 |
| CORS misconfiguration | `/ps/clientside/cors/vuln/...` → `.../secure/...` | CWE-942 |
| Clickjacking / X-Frame-Options | `/ps/clientside/clickjacking/vuln/...` → `.../secure/...` | CWE-1021 |

## Phase 3 — Authentication, session & access control

| Roadmap item | Vuln → Secure endpoint | CWE |
|---|---|---|
| Weak auth / user enumeration / no lockout | `POST /a07/vuln/login` → `POST /a07/secure/login` | CWE-307/CWE-204 |
| Authentication (PortSwigger) | `/ps/serverside/authentication/vuln/...` → `.../secure/...` | CWE-287 |
| Session fixation **[NEW]** | `POST /roadmap/session/vuln/login` → `POST /roadmap/session/secure/login` | CWE-384 |
| Insecure session cookie flags **[NEW]** | `GET /roadmap/session/vuln/set-cookie` → `.../secure/set-cookie` | CWE-1004/CWE-614 |
| JWT attacks (alg:none, confusion, weak key, exp) | `/ps/advanced/jwt/vuln/...` → `.../secure/...`; also A07 JWT | CWE-347 |
| IDOR / BOLA | `GET /a01/vuln/account/{id}` → `GET /a01/secure/account/{id}` | CWE-639 |
| Vertical privilege escalation / function-level authz | `GET /a01/secure/admin/dashboard` (`@PreAuthorize`) | CWE-285 |
| Access control (PortSwigger) | `/ps/serverside/accesscontrol/vuln/...` → `.../secure/...` | CWE-284 |
| Mass assignment | `/ps/serverside/apitesting/vuln/...` → `.../secure/...` | CWE-915 |

## Phase 4 — Input handling & injection

| Roadmap item | Vuln → Secure endpoint | CWE |
|---|---|---|
| SQL injection | `GET /a05/vuln/search` → `.../secure/search`; `/ps/serverside/sqli/...` | CWE-89 |
| NoSQL injection | `/ps/serverside/nosqli/vuln/...` → `.../secure/...` | CWE-943 |
| Command injection | `/ps/serverside/commandinjection/vuln/...` → `.../secure/...` | CWE-78 |
| LDAP injection **[NEW]** | `GET /roadmap/ldap/vuln/login` → `.../secure/login` | CWE-90 |
| SpEL injection **[NEW]** | `GET /roadmap/spel/vuln/eval` → `.../secure/eval` | CWE-917 |
| Template injection (SSTI) | `/ps/advanced/ssti/vuln/render` → `.../secure/render` | CWE-1336 |
| XSS (reflected/stored/DOM) | `/clientside/{vuln|secure}/...`; `/ps/clientside/xss/...` | CWE-79 |
| SSRF | `/ps/serverside/ssrf/vuln/...` → `.../secure/...` | CWE-918 |
| Open redirect **[NEW]** | `GET /roadmap/openredirect/vuln/go` → `.../secure/go` | CWE-601 |
| Path traversal | `/ps/serverside/pathtraversal/vuln/...` → `.../secure/...` | CWE-22 |
| File upload | `/ps/serverside/fileupload/vuln/...` → `.../secure/...` | CWE-434 |
| XXE | `/ps/serverside/xxe/vuln/...` → `.../secure/...` | CWE-611 |
| Insecure deserialization | `POST /a08/vuln/import` → `.../secure/import`; `/ps/advanced/insecuredeserialization/...` | CWE-502 |
| CORS misconfiguration | `/ps/clientside/cors/vuln/...` → `.../secure/...` | CWE-942 |

## Phase 5 — Business logic & configuration

| Roadmap item | Vuln → Secure endpoint | CWE |
|---|---|---|
| Business-logic abuse / missing rate limit | `POST /a06/vuln/redeem` → `.../secure/redeem`; `/ps/serverside/businesslogic/...` | CWE-840 |
| Race conditions (TOCTOU) | `/ps/serverside/raceconditions/vuln/...` → `.../secure/...` | CWE-367 |
| Actuator lockdown | see Phase 1 (`ActuatorSecurityNotes`) | CWE-16 |
| Missing security headers | `GET /a02/vuln/config` → `SecureHeadersConfig` (CSP/HSTS/nosniff/frame) | CWE-693 |
| Fail-open error handling | `GET /a10/vuln/access` → `GET /a10/secure/access` (fail-closed) | CWE-636 |
| Logging/alerting failures / PII in logs | `POST /a09/vuln/transfer` → `.../secure/transfer` | CWE-778/CWE-532 |
| Weak cryptography / key handling | `POST /a04/vuln/store` → `.../secure/store` (AES-GCM + BCrypt) | CWE-327 |
| Supply-chain / dependency integrity | `GET /a03/vuln/dependency-check` → `.../secure/dependency-check` | CWE-1104 |

## Not demonstrated as live weapons (by design)

These are explained safely rather than exploited, because a live exploit is
protocol-level, destructive, or environment-specific:

- HTTP request smuggling — explainer (`/ps/advanced/requestsmuggling`)
- Web cache poisoning / deception — explainer endpoints
- TLS configuration — operational (test with `testssl.sh`/`sslyze`, not app code)
- MFA bypass — depends on an MFA provider not wired into this lab

> All `/vuln/**` and the open `/actuator/**` endpoints are intentionally insecure.
> Run this project only on localhost / an isolated lab. Never deploy it.

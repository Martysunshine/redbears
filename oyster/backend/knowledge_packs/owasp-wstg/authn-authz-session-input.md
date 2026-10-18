# OWASP WSTG — Authentication, Authorization, Session, Input Validation

*Original condensed summary. Source: OWASP WSTG (CC BY-SA 4.0) — https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/.*

## Authentication (WSTG-ATHN)

Verify *who* the user is, safely:

- **Credentials over an encrypted channel (ATHN-01)** — never accept credentials over cleartext HTTP.
- **Default / weak credentials (ATHN-02)** — test vendor defaults and common passwords against admin accounts.
- **Lockout & rate limiting (ATHN-03)** — is brute force throttled? Is lockout abusable for DoS?
- **Bypass (ATHN-04)** — forced browsing to post-login pages, parameter tampering (`admin=true`), direct API calls skipping the login flow.
- **Password reset & recovery (ATHN-09)** — predictable tokens, host-header poisoning of reset links, user enumeration via differing responses.
- **MFA weaknesses** — fallback flows, missing re-prompt on sensitive actions, OTP brute force.

## Authorization (WSTG-ATHZ)

Verify *what* an authenticated user may do — the most common source of high-impact web bugs:

- **IDOR / BOLA (ATHZ-04)** — change an object identifier (`/invoice/1001` → `1002`) and see if you get another tenant's data. Test every object reference with a second, lower-privileged account.
- **Privilege escalation (ATHZ-03)** — reach admin functions as a normal user; horizontal (peer data) and vertical (higher role) escalation.
- **Path traversal (ATHZ-01)** — `../` sequences reaching files outside the intended directory.
- **Missing function-level access control** — the UI hides a button but the endpoint still honors the request.

Always test authorization with **two accounts of different privilege**; comparing responses is how you prove a real finding versus a benign 403.

## Session Management (WSTG-SESS)

- **Cookie attributes (SESS-02)** — `Secure`, `HttpOnly`, `SameSite`.
- **Session fixation (SESS-03)** — does the session ID rotate on login?
- **Logout & timeout (SESS-06/07)** — is the token actually invalidated server-side?
- **CSRF (SESS-05)** — state-changing requests must require an unpredictable, per-session token or equivalent.
- **JWT** — check `alg:none`, weak signing keys, and missing expiry/audience validation.

## Input Validation (WSTG-INPV)

Where injection lives:

- **SQL injection (INPV-05)** — error-based, boolean/time-based blind; validate reflection before automating with `sqlmap`.
- **Cross-Site Scripting (INPV-01/02)** — reflected, stored, DOM; test each input and its output context (HTML, attribute, JS, URL).
- **Command / template / LDAP / XML injection** — untrusted input reaching a shell, template engine, directory, or parser.
- **SSRF** — server-side fetches driven by user input; probe cloud metadata endpoints only within authorized scope.
- **File upload** — content-type and extension bypass, path control, and whether uploads are served/executed.

For each input, reason about the **sink** (where it lands) to predict the class of bug, then confirm with a minimal, non-destructive proof before reporting. Capture request/response evidence for the report.

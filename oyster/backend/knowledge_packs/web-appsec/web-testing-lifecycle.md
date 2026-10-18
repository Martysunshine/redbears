# Web Assessment Lifecycle (WSTG) & Tooling

The OWASP Web Security Testing Guide (WSTG) organizes web testing into phases. A practical flow:

1. **Information gathering / mapping** — spider the app, enumerate content and parameters, fingerprint tech stack, find hidden endpoints and virtual hosts. Tools: Burp Suite (proxy + crawler), Katana, `ffuf`/Feroxbuster/Gobuster (content discovery), Arjun (parameter discovery), browser dev tools.
2. **Configuration & deployment** — security headers, TLS config, error verbosity, exposed admin/`.git`/backup files.
3. **Identity & authentication** — username enumeration, weak password policy, credential stuffing resistance, MFA, account lockout, password reset flows.
4. **Session management** — token entropy/rotation, cookie flags (HttpOnly, Secure, SameSite), fixation, logout invalidation.
5. **Authorization** — vertical/horizontal privilege escalation, IDOR, forced browsing. Test with two accounts of different privilege.
6. **Input validation** — injection (SQLi/NoSQLi/command/LDAP/template), XSS, header injection, host-header attacks.
7. **Business logic** — abuse valid features (quantity/price tampering, workflow bypass), **race conditions** (parallel requests), rate-limit bypass.
8. **Client-side** — DOM XSS, postMessage, CORS misconfig, clickjacking.
9. **Advanced** — HTTP request smuggling, web cache deception/poisoning, deserialization, SSTI, GraphQL introspection abuse, WebSocket auth.

## Core tools
- **Burp Suite** — the daily driver for web/API testing (Community = manual; Professional = active scan + extensions). ZAP and **Caido** are alternatives; **mitmproxy** for scriptable interception.
- `ffuf` / Feroxbuster / Gobuster — fuzzing paths/params/vhosts with wordlists (SecLists).
- Nuclei — templated checks for known issues/misconfigurations.
- Postman / Insomnia — API request crafting; `curl` for reproducible evidence.

## Method
Prefer manual verification over scanner output; scanners find candidates, humans confirm exploitability and business impact. Record reproducible request/response evidence for every finding.

## References
- OWASP WSTG — https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger Web Security Academy — https://portswigger.net/web-security
- SecLists wordlists — https://github.com/danielmiessler/SecLists

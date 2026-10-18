# OWASP Top 10 (2021) — Web Risks, Detection & Remediation

The OWASP Top 10 is the baseline awareness document for web application risk. Categories (2021):

1. **A01 Broken Access Control** — most impactful. IDOR, missing function-level checks, path traversal, forced browsing. Test object- and function-level authorization with two accounts (horizontal/vertical). Fix: deny-by-default, server-side checks per request, avoid trusting client-supplied IDs/roles. (CWE-284, CWE-639)
2. **A02 Cryptographic Failures** — weak/missing TLS, plaintext secrets, weak hashing (MD5/SHA1 for passwords). Fix: TLS 1.2+, HSTS, Argon2/bcrypt/scrypt for passwords, no secrets in code. (CWE-327)
3. **A03 Injection** — SQLi, NoSQLi, OS command, LDAP, and **XSS** now folded here. Root cause: untrusted input reaching an interpreter. Fix: parameterized queries/prepared statements, context-aware output encoding, allowlist validation. (CWE-89, CWE-79, CWE-78)
4. **A04 Insecure Design** — flaws in the design itself; needs threat modeling, not just a patch.
5. **A05 Security Misconfiguration** — default creds, verbose errors, open cloud buckets, missing security headers.
6. **A06 Vulnerable & Outdated Components** — known-CVE libraries. Fix: SCA (Snyk/Dependabot/OWASP Dependency-Check), SBOM, patch cadence.
7. **A07 Identification & Authentication Failures** — credential stuffing, weak session management, missing MFA.
8. **A08 Software & Data Integrity Failures** — insecure deserialization, unsigned updates, CI/CD supply-chain. (CWE-502)
9. **A09 Security Logging & Monitoring Failures** — you can't detect what you don't log.
10. **A10 Server-Side Request Forgery (SSRF)** — server fetches an attacker-controlled URL. Test cloud metadata (169.254.169.254), internal ranges. Fix: allowlist egress, block link-local/internal, no raw URL fetching. (CWE-918)

## Notes
- XSS types: reflected, stored, DOM-based. Defense-in-depth: output encoding + CSP + HttpOnly/SameSite cookies.
- CSRF: mitigated by SameSite cookies + anti-CSRF tokens; still relevant for state-changing requests.
- Validate as a professional under authorization; capture request/response evidence for each finding.

## References
- OWASP Top 10 — https://owasp.org/www-project-top-ten/
- OWASP ASVS (verification requirements) — https://owasp.org/www-project-application-security-verification-standard/
- OWASP Cheat Sheet Series — https://cheatsheetseries.owasp.org/

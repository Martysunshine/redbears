# OWASP API Security Top 10 (2023)

APIs shift most risk to **authorization** and **automation abuse**. Categories:

1. **API1 Broken Object Level Authorization (BOLA/IDOR)** — the #1 API risk. Endpoint accepts an object ID and returns another user's data. Test by swapping IDs across two accounts. Fix: enforce per-object ownership checks server-side on every request; use unguessable IDs but never rely on that alone.
2. **API2 Broken Authentication** — weak JWT validation (accepting `alg:none`, unverified signature, no expiry), credential stuffing, weak token issuance. Fix: validate signature + `exp`/`aud`/`iss`, short-lived tokens, rotate keys.
3. **API3 Broken Object Property Level Authorization** — merges **excessive data exposure** (returns fields the caller shouldn't see) and **mass assignment** (client sets fields it shouldn't, e.g., `is_admin=true`). Fix: explicit allowlists for readable/writable properties (DTOs), never bind requests straight to models.
4. **API4 Unrestricted Resource Consumption** — no rate limits/quotas → DoS or **denial-of-wallet**. Fix: rate limiting, pagination caps, payload size limits, timeouts.
5. **API5 Broken Function Level Authorization** — regular user reaches admin functions by guessing routes/verbs. Fix: deny-by-default per function/role.
6. **API6 Unrestricted Access to Sensitive Business Flows** — automation abuse of legitimate flows (bulk purchase, scraping). Fix: bot/abuse detection, step-up controls.
7. **API7 Server-Side Request Forgery (SSRF)** — API fetches attacker URL. Fix: egress allowlist, block internal/link-local, no raw URL fetching.
8. **API8 Security Misconfiguration** — verbose errors, missing headers, permissive CORS, unpatched components.
9. **API9 Improper Inventory Management** — forgotten/undocumented endpoints, old `v1` APIs, staging exposed. Fix: maintain an API inventory + retire old versions.
10. **API10 Unsafe Consumption of Third-Party APIs** — trusting upstream data blindly.

## Protocols & auth
- REST, GraphQL (test introspection, deep queries, batching abuse), SOAP, WebSockets, webhooks.
- OAuth 2.0 / OpenID Connect flows; JWT (verify signature/claims, don't trust `alg`); API keys (scope + rotate).
- Tools: Burp Suite, Postman/Insomnia, InQL (GraphQL), `ffuf` for route discovery, schema/contract validation (OpenAPI).

## References
- OWASP API Security Top 10 (2023) — https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- JWT best practices (RFC 8725) — https://datatracker.ietf.org/doc/html/rfc8725

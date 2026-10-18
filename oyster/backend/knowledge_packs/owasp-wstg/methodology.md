# OWASP WSTG — Methodology and Reconnaissance

*Original condensed summary of the OWASP Web Security Testing Guide. Source: https://owasp.org/www-project-web-security-testing-guide/ (CC BY-SA 4.0). Test IDs (e.g. WSTG-INFO-02) reference the canonical guide.*

## The WSTG phased approach

WSTG frames a web assessment as phases, each with numbered tests. A thorough test covers, in rough order: **Information Gathering → Configuration & Deployment → Identity/Authentication → Authorization → Session Management → Input Validation → Error Handling → Cryptography → Business Logic → Client-side → API**. Reporting wraps the whole engagement.

Lead with recon: understanding the app's surface, stack, and roles determines everything else.

## Information Gathering (WSTG-INFO)

- **Search-engine & OSINT discovery (INFO-01)** — find exposed content, docs, and credentials indexed publicly before touching the target.
- **Fingerprint web server & framework (INFO-02/08/09)** — headers, error pages, cookies, and file extensions reveal the stack (nginx/Apache, Express, Django, Rails, etc.).
- **Enumerate content & endpoints (INFO-05/06/07)** — spidering, `robots.txt`, sitemaps, and directory brute-forcing (`ffuf`, `feroxbuster`) map reachable paths, admin panels, and backups.
- **Identify entry points (INFO-06)** — every parameter, header, cookie, and upload is an input to test later.
- **Map application architecture (INFO-10)** — CDNs, WAFs, reverse proxies, and microservice boundaries change how findings behave.

Record the technology, roles, and full endpoint inventory as evidence — it drives the test plan and the report's scope section.

## Configuration & Deployment (WSTG-CONF)

- Look for default/sample content, admin interfaces, and old versions (CONF-01..05).
- Check HTTP methods, HSTS, TLS configuration, and security headers (CONF-06..07, plus the header tests).
- Review file-handling and cross-domain policies (CORS, `crossdomain.xml`).

## How to use this in a plan

For each in-scope application, instantiate the categories as concrete tests against the discovered inputs and roles. Prioritize by exposure (internet-facing first) and by the sensitivity of the data behind each function. Only test hosts named in the **written authorized scope** — content discovered during recon that points to other systems is *not* authorization to test them.

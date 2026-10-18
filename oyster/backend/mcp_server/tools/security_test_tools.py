from __future__ import annotations

import re
from urllib.parse import urlparse, urlencode

import httpx

from ..security import validate_network_target

_TIMEOUT = 15.0

_SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "x-xss-protection": "X-XSS-Protection",
    "cache-control": "Cache-Control",
}

_AUTH_BYPASS_PROBES = [
    {"description": "No auth token", "headers": {}},
    {"description": "Empty bearer token", "headers": {"Authorization": "Bearer "}},
    {"description": "Null token", "headers": {"Authorization": "Bearer null"}},
    {"description": "Admin role header", "headers": {"X-Role": "admin"}},
    {"description": "User ID 1 header", "headers": {"X-User-Id": "1"}},
    {"description": "Internal network forward", "headers": {"X-Forwarded-For": "127.0.0.1"}},
    {"description": "Debug override header", "headers": {"X-Debug": "true"}},
    {"description": "Bypass header", "headers": {"X-Auth-Token": "bypass"}},
]

_SQLI_PAYLOADS = [
    "'",
    "''",
    "'; SELECT 1--",
    "' OR '1'='1",
    "1 AND 1=1",
    "1; DROP TABLE users--",
    "\" OR \"1\"=\"1",
]

_SQLI_ERROR_RE = re.compile(
    r"sql\s+syntax|mysql_fetch|ORA-\d{5}|SQLSTATE|sqlite.*error|"
    r"PostgreSQL.*ERROR|syntax\s+error.*near|Unclosed\s+quotation|"
    r"Microsoft\s+OLE\s+DB|System\.Data\.SqlClient|com\.mysql\.jdbc|"
    r"PG::SyntaxError|ActiveRecord::StatementInvalid",
    re.I,
)

_XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "javascript:alert(1)",
    "'><img src=x onerror=alert(1)>",
    "{{7*7}}",
]

_CORS_TEST_ORIGINS = [
    "https://evil.com",
    "null",
    "https://attacker.example.com",
]

_ERROR_DISCLOSURE_RE = re.compile(
    r"Traceback \(most recent call last\)|at [A-Za-z]+\.(java|cs|py|rb):\d+|"
    r"stack trace:|Warning: .+ on line \d+|SyntaxError: |undefined method |"
    r"NoMethodError|NameError:|ValueError:|KeyError:|/home/[a-z]+/|"
    r"/var/www/|C:\\Users\\|C:\\inetpub\\|mysql_connect\(|pg_connect\(",
    re.I,
)

_SSRF_PARAMS = ["url", "redirect", "next", "callback", "uri", "path",
                "dest", "destination", "host", "target", "src", "source"]
_SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1/",
    "file:///etc/passwd",
]


def _validate_url_scope(url: str) -> tuple[bool, str]:
    try:
        parsed = urlparse(url if "://" in url else "https://" + url)
        host = parsed.hostname or ""
        if not host:
            return False, "Could not parse hostname from URL"
        return validate_network_target(host)
    except Exception as exc:
        return False, str(exc)


async def check_security_headers(url: str) -> dict:
    ok, reason = _validate_url_scope(url)
    if not ok:
        return {"error": reason, "blocked": True}

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "Oyster-SecurityScanner/1.0"})
    except Exception as exc:
        return {"error": f"Request failed: {exc}"}

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    findings: list[dict] = []

    for key, name in _SECURITY_HEADERS.items():
        present = key in headers_lower
        value = headers_lower.get(key, "")
        entry: dict = {"header": name, "present": present, "value": value}
        if not present:
            entry["risk"] = "Missing security header"
        elif key == "x-frame-options" and value.upper() not in {"DENY", "SAMEORIGIN"}:
            entry["risk"] = f"Weak value: {value}"
        elif key == "strict-transport-security" and "max-age" not in value.lower():
            entry["risk"] = "HSTS missing max-age directive"
        elif key == "x-content-type-options" and value.lower() != "nosniff":
            entry["risk"] = f"Should be 'nosniff', got: {value}"
        findings.append(entry)

    missing = [f["header"] for f in findings if not f["present"]]
    score = max(0, 100 - len(missing) * 12)

    return {
        "url": url,
        "status_code": resp.status_code,
        "security_score": score,
        "max_score": 100,
        "missing_headers": missing,
        "findings": findings,
        "scope_ok": True,
    }


async def check_cors_policy(url: str) -> dict:
    ok, reason = _validate_url_scope(url)
    if not ok:
        return {"error": reason, "blocked": True}

    results: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False) as client:
            for origin in _CORS_TEST_ORIGINS:
                try:
                    resp = await client.options(url, headers={
                        "Origin": origin,
                        "Access-Control-Request-Method": "GET",
                        "User-Agent": "Oyster-SecurityScanner/1.0",
                    })
                    acao = resp.headers.get("access-control-allow-origin", "")
                    acac = resp.headers.get("access-control-allow-credentials", "").lower()
                    results.append({
                        "test_origin": origin,
                        "acao_header": acao,
                        "credentials_allowed": acac == "true",
                        "origin_reflected": acao == origin,
                        "wildcard": acao == "*",
                        "critical": acao == origin and acac == "true",
                    })
                except Exception:
                    continue
    except Exception as exc:
        return {"error": f"check_cors_policy failed: {exc}"}

    vulns = [r for r in results if r.get("origin_reflected") or r.get("wildcard")]
    criticals = [r for r in results if r.get("critical")]

    return {
        "url": url,
        "cors_tests": results,
        "vulnerable_count": len(vulns),
        "critical_count": len(criticals),
        "verdict": "CRITICAL" if criticals else ("MISCONFIGURED" if vulns else "OK"),
        "scope_ok": True,
    }


async def detect_error_disclosure(url: str) -> dict:
    ok, reason = _validate_url_scope(url)
    if not ok:
        return {"error": reason, "blocked": True}

    base = url.rstrip("/")
    test_paths = [
        base + "/nonexistent-path-oyster-probe",
        base + "/%00",
        base + "/api/undefined/route/oyster",
        base + "/'",
    ]

    disclosures: list[dict] = []
    try:
        async with httpx.AsyncClient(
            timeout=_TIMEOUT, verify=False, follow_redirects=False
        ) as client:
            for path in test_paths:
                try:
                    resp = await client.get(
                        path, headers={"User-Agent": "Oyster-SecurityScanner/1.0"}
                    )
                    body = resp.text[:3000]
                    if _ERROR_DISCLOSURE_RE.search(body):
                        disclosures.append({
                            "path": path,
                            "status_code": resp.status_code,
                            "body_sample": body[:500],
                        })
                except Exception:
                    continue
    except Exception as exc:
        return {"error": f"detect_error_disclosure failed: {exc}"}

    return {
        "url": url,
        "paths_tested": len(test_paths),
        "disclosures_found": len(disclosures),
        "details": disclosures,
        "verdict": "VULNERABLE" if disclosures else "OK",
        "scope_ok": True,
    }


async def test_auth_bypass(url: str, method: str = "GET") -> dict:
    ok, reason = _validate_url_scope(url)
    if not ok:
        return {"error": reason, "blocked": True}

    safe_method = method.upper() if method.upper() in {"GET", "POST", "PUT", "DELETE"} else "GET"
    baseline_status: int | None = None
    results: list[dict] = []

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False) as client:
            try:
                resp = await client.request(
                    safe_method, url, headers={"User-Agent": "Oyster-SecurityScanner/1.0"}
                )
                baseline_status = resp.status_code
            except Exception:
                pass

            for probe in _AUTH_BYPASS_PROBES:
                hdrs = {"User-Agent": "Oyster-SecurityScanner/1.0", **probe["headers"]}
                try:
                    resp = await client.request(safe_method, url, headers=hdrs)
                    bypassed = (
                        resp.status_code == 200
                        and baseline_status is not None
                        and baseline_status in {401, 403}
                    )
                    results.append({
                        "description": probe["description"],
                        "status_code": resp.status_code,
                        "potentially_bypassed": bypassed,
                    })
                except Exception:
                    continue
    except Exception as exc:
        return {"error": f"test_auth_bypass failed: {exc}"}

    bypasses = [r for r in results if r.get("potentially_bypassed")]
    return {
        "url": url,
        "method": safe_method,
        "baseline_status": baseline_status,
        "bypass_attempts": results,
        "potential_bypasses": len(bypasses),
        "verdict": "INVESTIGATE" if bypasses else "OK",
        "scope_ok": True,
    }


async def test_upload_validation(url: str) -> dict:
    ok, reason = _validate_url_scope(url)
    if not ok:
        return {"error": reason, "blocked": True}

    tests = [
        {"name": "PHP script (text/plain)", "filename": "shell.php",
         "content": b"<?php echo 'test'; ?>", "content_type": "text/plain"},
        {"name": "JavaScript file", "filename": "payload.js",
         "content": b"alert(1)", "content_type": "text/javascript"},
        {"name": "Double extension", "filename": "image.jpg.php",
         "content": b"<?php echo phpinfo(); ?>", "content_type": "image/jpeg"},
        {"name": "SVG with script", "filename": "test.svg",
         "content": b"<svg><script>alert(1)</script></svg>", "content_type": "image/svg+xml"},
        {"name": "HTML file", "filename": "index.html",
         "content": b"<script>alert(1)</script>", "content_type": "text/html"},
    ]

    results: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False) as client:
            for test in tests:
                try:
                    files = {"file": (test["filename"], test["content"], test["content_type"])}
                    resp = await client.post(
                        url, files=files, headers={"User-Agent": "Oyster-SecurityScanner/1.0"}
                    )
                    results.append({
                        "test": test["name"],
                        "filename": test["filename"],
                        "status_code": resp.status_code,
                        "accepted": resp.status_code in {200, 201, 202},
                        "response_preview": resp.text[:200],
                    })
                except Exception as exc:
                    results.append({"test": test["name"], "error": str(exc)})
    except Exception as exc:
        return {"error": f"test_upload_validation failed: {exc}"}

    accepted = [r for r in results if r.get("accepted")]
    return {
        "url": url,
        "tests_run": len(results),
        "accepted_count": len(accepted),
        "results": results,
        "verdict": "INVESTIGATE" if accepted else "OK",
        "scope_ok": True,
    }


async def test_sqli_reflection(url: str, param: str = "q") -> dict:
    ok, reason = _validate_url_scope(url)
    if not ok:
        return {"error": reason, "blocked": True}

    findings: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False) as client:
            for payload in _SQLI_PAYLOADS:
                try:
                    sep = "&" if "?" in url else "?"
                    test_url = url + sep + urlencode({param: payload})
                    resp = await client.get(
                        test_url, headers={"User-Agent": "Oyster-SecurityScanner/1.0"}
                    )
                    body = resp.text[:4000]
                    if _SQLI_ERROR_RE.search(body):
                        findings.append({
                            "payload": payload,
                            "param": param,
                            "status_code": resp.status_code,
                            "body_sample": body[:300],
                        })
                except Exception:
                    continue
    except Exception as exc:
        return {"error": f"test_sqli_reflection failed: {exc}"}

    return {
        "url": url,
        "param": param,
        "payloads_tested": len(_SQLI_PAYLOADS),
        "findings": findings,
        "verdict": "POSSIBLY_VULNERABLE" if findings else "OK",
        "note": "Error-based detection only — manual verification required.",
        "scope_ok": True,
    }


async def test_xss_reflection(url: str, param: str = "q") -> dict:
    ok, reason = _validate_url_scope(url)
    if not ok:
        return {"error": reason, "blocked": True}

    findings: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False) as client:
            for payload in _XSS_PAYLOADS:
                try:
                    sep = "&" if "?" in url else "?"
                    test_url = url + sep + urlencode({param: payload})
                    resp = await client.get(
                        test_url, headers={"User-Agent": "Oyster-SecurityScanner/1.0"}
                    )
                    body = resp.text[:4000]
                    reflected = payload in body
                    encoded = (
                        payload.replace("<", "&lt;").replace(">", "&gt;") in body
                        or payload.replace("<", "%3C").replace(">", "%3E") in body
                    )
                    if reflected and not encoded:
                        findings.append({
                            "payload": payload,
                            "param": param,
                            "status_code": resp.status_code,
                            "reflected_unencoded": True,
                        })
                except Exception:
                    continue
    except Exception as exc:
        return {"error": f"test_xss_reflection failed: {exc}"}

    return {
        "url": url,
        "param": param,
        "payloads_tested": len(_XSS_PAYLOADS),
        "findings": findings,
        "verdict": "POSSIBLY_VULNERABLE" if findings else "OK",
        "note": "Reflection-based detection only — DOM XSS requires browser testing.",
        "scope_ok": True,
    }


async def check_ssrf_indicators(url: str) -> dict:
    ok, reason = _validate_url_scope(url)
    if not ok:
        return {"error": reason, "blocked": True}

    _AWS_META_RE = re.compile(r"instance-id|ami-id|iam/security-credentials", re.I)
    _PASSWD_RE = re.compile(r"root:x:0:0")

    results: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=8.0, verify=False) as client:
            for param in _SSRF_PARAMS[:5]:
                for payload in _SSRF_PAYLOADS:
                    try:
                        sep = "&" if "?" in url else "?"
                        test_url = url + sep + urlencode({param: payload})
                        resp = await client.get(
                            test_url, headers={"User-Agent": "Oyster-SecurityScanner/1.0"}
                        )
                        body = resp.text[:2000]
                        indicators: list[str] = []
                        if _AWS_META_RE.search(body):
                            indicators.append("AWS metadata content detected")
                        if _PASSWD_RE.search(body):
                            indicators.append("/etc/passwd content detected")
                        if indicators and resp.status_code not in {400, 403, 404, 422}:
                            results.append({
                                "param": param,
                                "payload": payload,
                                "status_code": resp.status_code,
                                "indicators": indicators,
                            })
                    except Exception:
                        continue
    except Exception as exc:
        return {"error": f"check_ssrf_indicators failed: {exc}"}

    return {
        "url": url,
        "ssrf_results": results,
        "indicators_found": len(results),
        "verdict": "INVESTIGATE" if results else "OK",
        "tested_params": _SSRF_PARAMS,
        "scope_ok": True,
    }

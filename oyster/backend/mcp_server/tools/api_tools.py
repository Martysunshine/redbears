from __future__ import annotations

import asyncio
from urllib.parse import urlparse, urlencode

import httpx

from ..security import validate_network_target

_TIMEOUT = 15.0

_COMMON_ROUTES = [
    "/", "/health", "/api", "/api/v1", "/api/v2", "/v1", "/v2",
    "/admin", "/admin/", "/dashboard", "/login", "/logout",
    "/register", "/signup", "/profile", "/users", "/users/me",
    "/docs", "/swagger", "/openapi.json", "/redoc", "/api-docs",
    "/status", "/ping", "/version", "/metrics", "/actuator",
    "/api/users", "/api/auth", "/api/auth/login", "/api/auth/register",
    "/api/health", "/graphql", "/api/graphql",
    "/api/v1/users", "/api/v1/auth", "/api/v1/health",
    "/.well-known/security.txt", "/robots.txt", "/sitemap.xml",
    "/api/upload", "/upload", "/files", "/static",
    "/api/admin", "/manage", "/management", "/console",
    "/.env", "/config", "/configuration", "/settings",
    "/api/search", "/search", "/api/products", "/api/orders",
    "/__debug__", "/debug", "/trace", "/error",
    "/api/me", "/api/profile", "/api/token", "/api/refresh",
]

_FRAMEWORK_BODY_PATTERNS: list[tuple[str, str]] = [
    ("__NEXT_DATA__", "Next.js"),
    ("_next/", "Next.js"),
    ("ng-version", "Angular"),
    ("data-reactroot", "React"),
    ("data-vue-", "Vue.js"),
    ("Powered by Express", "Express.js"),
    ("Django", "Django"),
    ("werkzeug", "Flask/Werkzeug"),
    ("FastAPI", "FastAPI"),
    ("swagger-ui", "Swagger UI"),
    ("redoc", "ReDoc"),
]


def _validate_url_scope(url: str) -> tuple[bool, str, str]:
    try:
        parsed = urlparse(url if "://" in url else "https://" + url)
        host = parsed.hostname or ""
        if not host:
            return False, "Could not parse hostname from URL", ""
        ok, reason = validate_network_target(host)
        return ok, reason, host
    except Exception as exc:
        return False, f"URL validation error: {exc}", ""


async def http_probe(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: str = "",
) -> dict:
    ok, reason, _ = _validate_url_scope(url)
    if not ok:
        return {"error": reason, "blocked": True, "url": url}

    safe_method = method.upper() if method.upper() in {
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"
    } else "GET"

    req_headers = {"User-Agent": "Oyster-SecurityScanner/1.0", **(headers or {})}
    try:
        async with httpx.AsyncClient(
            timeout=_TIMEOUT, follow_redirects=True, verify=False
        ) as client:
            resp = await client.request(
                safe_method,
                url,
                headers=req_headers,
                content=body.encode() if body else None,
            )
            return {
                "url": url,
                "method": safe_method,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body_preview": resp.text[:4000],
                "content_type": resp.headers.get("content-type", ""),
                "redirect_history": [str(r.url) for r in resp.history],
                "scope_ok": True,
            }
    except httpx.TimeoutException:
        return {"error": f"Request timed out after {_TIMEOUT}s", "url": url}
    except Exception as exc:
        return {"error": f"http_probe failed: {exc}", "url": url}


async def tech_stack_detect(url: str) -> dict:
    ok, reason, _ = _validate_url_scope(url)
    if not ok:
        return {"error": reason, "blocked": True, "url": url}

    try:
        async with httpx.AsyncClient(
            timeout=_TIMEOUT, follow_redirects=True, verify=False
        ) as client:
            resp = await client.get(
                url, headers={"User-Agent": "Oyster-SecurityScanner/1.0"}
            )
    except Exception as exc:
        return {"error": f"tech_stack_detect failed: {exc}", "url": url}

    detected: list[str] = []
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    for h in ("server", "x-powered-by", "x-generator", "via"):
        val = headers_lower.get(h, "")
        if val:
            detected.append(f"{h.title()}: {val}")

    cookies = headers_lower.get("set-cookie", "")
    if "laravel_session" in cookies or "xsrf-token" in cookies.lower():
        detected.append("Framework: Laravel (PHP)")
    if "jsessionid" in cookies.upper():
        detected.append("Runtime: Java (Spring/Tomcat)")
    if "csrftoken" in cookies.lower() or "django" in cookies.lower():
        detected.append("Framework: Django (Python)")
    if "rack.session" in cookies or "sinatra" in cookies.lower():
        detected.append("Framework: Sinatra/Rack (Ruby)")

    body = resp.text[:8000]
    for marker, framework in _FRAMEWORK_BODY_PATTERNS:
        if marker.lower() in body.lower():
            detected.append(f"Framework: {framework}")

    sec_headers = {
        h: headers_lower.get(h, "MISSING")
        for h in [
            "content-security-policy",
            "x-frame-options",
            "strict-transport-security",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
        ]
    }

    return {
        "url": url,
        "status_code": resp.status_code,
        "detected_tech": list(set(detected)),
        "security_headers": sec_headers,
        "response_headers": dict(resp.headers),
        "scope_ok": True,
    }


async def _probe_route(client: httpx.AsyncClient, url: str) -> dict:
    try:
        resp = await client.get(
            url, headers={"User-Agent": "Oyster-SecurityScanner/1.0"}
        )
        result: dict = {
            "status_code": resp.status_code,
            "content_type": resp.headers.get("content-type", ""),
        }
        if resp.is_redirect:
            result["redirect_to"] = resp.headers.get("location", "")
        return result
    except Exception:
        return {"status_code": -1}


async def discover_api_routes(base_url: str, wordlist: str = "common") -> dict:
    ok, reason, _ = _validate_url_scope(base_url)
    if not ok:
        return {"error": reason, "blocked": True, "url": base_url}

    base = base_url.rstrip("/")
    found: list[dict] = []

    async with httpx.AsyncClient(
        timeout=8.0, follow_redirects=False, verify=False
    ) as client:
        tasks = [_probe_route(client, base + route) for route in _COMMON_ROUTES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for route, result in zip(_COMMON_ROUTES, results):
        if isinstance(result, Exception):
            continue
        status = result.get("status_code", -1)
        if status not in {-1, 404, 410}:
            found.append({
                "path": route,
                "status": status,
                "content_type": result.get("content_type", ""),
                "redirect_to": result.get("redirect_to"),
            })

    return {
        "base_url": base_url,
        "found": found,
        "found_count": len(found),
        "total_probed": len(_COMMON_ROUTES),
        "scope_ok": True,
    }

"""HTTP inspection adapter (Class 2 — low-impact active).

Pure-Python (httpx). Performs a single HEAD/GET/OPTIONS against an in-scope
target, capturing the status, headers, redirect chain, TLS/cert metadata and a
size-capped body. It **manually follows redirects** so each hop can be
re-validated against scope — a redirect that leaves approved scope is refused,
not followed. Always available (httpx is a core dependency), which makes it the
engine's reference executable for local E2E.
"""

from __future__ import annotations

import ssl
from datetime import datetime, timezone

import httpx

from ..scope_engine import validate_redirect
from .base import AdapterContext, AdapterResult

_ALLOWED_METHODS = {"HEAD", "GET", "OPTIONS"}
_MAX_REDIRECTS = 5

# Headers worth flagging for a security review.
_SECURITY_HEADERS = [
    "strict-transport-security", "content-security-policy", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
]


async def run(ctx: AdapterContext) -> AdapterResult:
    method = str(ctx.parameters.get("method", "GET")).upper()
    if method not in _ALLOWED_METHODS:
        return AdapterResult(exit_code=2, error_summary=f"Method '{method}' not allowed (HEAD/GET/OPTIONS only).")

    body_limit = min(int(ctx.parameters.get("max_body_bytes", 65536)), ctx.max_output_bytes)
    url = ctx.target
    if "://" not in url:
        url = "http://" + url

    chain: list[dict] = []
    tls_info: dict = {}
    lines: list[str] = []

    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=ctx.timeout_seconds,
                                     verify=True) as client:
            current = url
            final_resp = None
            for hop in range(_MAX_REDIRECTS + 1):
                try:
                    resp = await client.request(method, current)
                except httpx.ConnectError as exc:
                    return AdapterResult(exit_code=1, error_summary=f"Connection failed: {exc}")
                final_resp = resp
                chain.append({"url": current, "status": resp.status_code})
                if resp.is_redirect and resp.headers.get("location"):
                    loc = str(resp.next_request.url) if resp.next_request else resp.headers["location"]
                    sc = validate_redirect(loc, ctx.scope)
                    if not sc.allowed:
                        lines.append(f"[BLOCKED] redirect to {loc} left scope: {sc.reason}")
                        return AdapterResult(
                            stdout="\n".join(lines),
                            exit_code=0,
                            parsed={
                                "final_url": current,
                                "redirect_chain": chain,
                                "redirect_blocked": {"location": loc, "reason": sc.reason},
                                "status": resp.status_code,
                            },
                            error_summary=None,
                        )
                    current = loc
                    continue
                break

            resp = final_resp
            # TLS/cert metadata (only for https)
            if current.lower().startswith("https"):
                tls_info = _peek_tls(httpx.URL(current))

            headers = {k.lower(): v for k, v in resp.headers.items()}
            missing = [h for h in _SECURITY_HEADERS if h not in headers]

            body_text = ""
            if method == "GET":
                raw = resp.content[:body_limit]
                truncated = len(resp.content) > body_limit
                try:
                    body_text = raw.decode(resp.encoding or "utf-8", errors="replace")
                except Exception:
                    body_text = raw.decode("utf-8", errors="replace")
            else:
                truncated = False

            lines.append(f"{method} {current} -> {resp.status_code} {resp.reason_phrase}")
            lines.append("")
            lines.append("Response headers:")
            for k, v in resp.headers.items():
                lines.append(f"  {k}: {v}")
            if body_text:
                lines.append("")
                lines.append(f"Body ({len(body_text)} chars{' truncated' if truncated else ''}):")
                lines.append(body_text)

            parsed = {
                "final_url": current,
                "method": method,
                "status": resp.status_code,
                "reason": resp.reason_phrase,
                "http_version": resp.http_version,
                "redirect_chain": chain,
                "headers": dict(resp.headers),
                "server": resp.headers.get("server"),
                "content_type": resp.headers.get("content-type"),
                "content_length": resp.headers.get("content-length"),
                "security_headers_present": [h for h in _SECURITY_HEADERS if h in headers],
                "security_headers_missing": missing,
                "tls": tls_info,
                "body_truncated": truncated,
            }
            return AdapterResult(stdout="\n".join(lines), exit_code=0, parsed=parsed, truncated=truncated)

    except httpx.TimeoutException:
        return AdapterResult(exit_code=124, error_summary=f"Request timed out after {ctx.timeout_seconds}s")
    except Exception as exc:  # noqa: BLE001
        return AdapterResult(exit_code=1, error_summary=f"HTTP inspection error: {exc}")


def _peek_tls(url: httpx.URL) -> dict:
    """Best-effort TLS certificate metadata via a short handshake."""
    import socket

    host = url.host
    port = url.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        info = {
            "subject_cn": subject.get("commonName"),
            "issuer_cn": issuer.get("commonName"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "tls_version": version,
            "cipher": cipher[0] if cipher else None,
        }
        # expiry check
        if cert.get("notAfter"):
            try:
                exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                info["expired"] = datetime.now(timezone.utc) > exp
                info["days_until_expiry"] = (exp - datetime.now(timezone.utc)).days
            except Exception:
                pass
        return info
    except Exception as exc:  # noqa: BLE001
        return {"error": f"TLS handshake failed: {exc}"}


def version() -> str:
    return f"httpx {httpx.__version__}"

"""Security primitives shared by every transport and tool.

Nothing here is transport-specific. These are the boundary controls the MCP
gateway relies on regardless of whether a request arrived over stdio or HTTP:

* secret redaction  — no credential, key or env value ever leaves in a result
* result bounding   — a single tool result can never exceed a byte budget
* rate limiting     — a per-identity sliding-window limiter for the HTTP surface
* path canonicalization — reject traversal / symlink escape / absolute paths
* SSRF classification    — reject loopback/link-local/metadata/private targets
* correlation ids   — one id per request, returned to the client and logged

These functions are deliberately dependency-free (stdlib only) so they can be
unit-tested in isolation and reused by both the stdio and HTTP entrypoints.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import time
import uuid
from collections import deque
from pathlib import Path
from threading import Lock
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Correlation ids
# ---------------------------------------------------------------------------

def new_correlation_id() -> str:
    return "mcp_" + uuid.uuid4().hex[:16]


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------
# Retrieved knowledge and project files are DATA. Even so, a tool result must
# never carry a live credential out to the client — a knowledge passage might
# quote an example key, an uploaded file might contain one, an error string
# might echo an Authorization header. These patterns are conservative (they
# favour redacting a false positive over leaking a real secret) and are applied
# to every string in every result before it leaves the gateway.

_REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # PEM private key blocks (any type)
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
                re.DOTALL), "<REDACTED:private-key>"),
    # Authorization: Bearer <token>
    (re.compile(r"(?i)\b(authorization|proxy-authorization)\b\s*[:=]\s*\S+"),
     r"\1: <REDACTED>"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{12,}"), "bearer <REDACTED>"),
    # Cloud / provider token shapes
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "<REDACTED:aws-key-id>"),
    (re.compile(r"\bASIA[0-9A-Z]{16}\b"), "<REDACTED:aws-key-id>"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "<REDACTED:github-token>"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "<REDACTED:slack-token>"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b"), "<REDACTED:google-key>"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "<REDACTED:api-key>"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}\b"),
     "<REDACTED:jwt>"),
    # KEY=VALUE / "key": "value" where the key name implies a secret
    (re.compile(r"(?i)\b([A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API[_-]?KEY|"
                r"PRIVATE[_-]?KEY|CREDENTIAL|ACCESS[_-]?KEY)[A-Z0-9_]*)\b"
                r"(\s*[:=]\s*)(\"?)([^\s\"',}]+)(\3)"),
     r"\1\2\3<REDACTED>\5"),
]


def redact_text(text: str) -> str:
    if not text:
        return text
    out = text
    for pat, repl in _REDACTION_PATTERNS:
        out = pat.sub(repl, out)
    return out


def redact(obj):
    """Recursively redact secrets from any JSON-serialisable structure."""
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {k: redact(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact(v) for v in obj]
    return obj


# ---------------------------------------------------------------------------
# Result bounding
# ---------------------------------------------------------------------------

def bound_result(obj, max_bytes: int) -> tuple[object, bool]:
    """Return (possibly-truncated object, truncated?).

    A structured result stays structured until it exceeds the budget; past that
    it is replaced by an honest, small marker rather than silently dropping
    fields (which would look like a successful-but-empty answer)."""
    try:
        raw = json.dumps(obj, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        raw = str(obj)
    if len(raw.encode("utf-8")) <= max_bytes:
        return obj, False
    # Too big — try trimming list-valued fields first (the common case: many
    # search hits), then fall back to a marker.
    if isinstance(obj, dict):
        trimmed = dict(obj)
        for key in list(trimmed.keys()):
            if isinstance(trimmed[key], list) and len(trimmed[key]) > 1:
                while trimmed[key] and len(
                    json.dumps(trimmed, ensure_ascii=False, default=str).encode("utf-8")
                ) > max_bytes:
                    trimmed[key] = trimmed[key][:-1]
                trimmed["_truncated"] = True
                if len(json.dumps(trimmed, ensure_ascii=False, default=str)
                       .encode("utf-8")) <= max_bytes:
                    return trimmed, True
    return {
        "_truncated": True,
        "_reason": f"result exceeded {max_bytes} bytes and was withheld",
    }, True


# ---------------------------------------------------------------------------
# Rate limiting (per identity, sliding window)
# ---------------------------------------------------------------------------

class RateLimiter:
    """A simple in-process sliding-window limiter keyed by an opaque identity.

    Good enough for a single-process gateway; a multi-process deployment behind
    a proxy should add limiting at the proxy too (documented in the threat
    model). Never leaks WHY across identities — each key is independent."""

    def __init__(self, per_minute: int):
        self.per_minute = max(1, int(per_minute))
        self._hits: dict[str, deque[float]] = {}
        self._lock = Lock()

    def check(self, key: str, now: float | None = None) -> tuple[bool, int]:
        """Return (allowed, retry_after_seconds)."""
        now = now if now is not None else time.monotonic()
        window_start = now - 60.0
        with self._lock:
            dq = self._hits.setdefault(key, deque())
            while dq and dq[0] < window_start:
                dq.popleft()
            if len(dq) >= self.per_minute:
                retry = int(dq[0] + 60.0 - now) + 1
                return False, max(1, retry)
            dq.append(now)
            return True, 0


# ---------------------------------------------------------------------------
# Path canonicalization — traversal / symlink / absolute-path defence
# ---------------------------------------------------------------------------

class PathValidationError(ValueError):
    pass


def canonical_relative_path(rel: str, allowed_root: Path) -> Path:
    """Resolve ``rel`` strictly inside ``allowed_root``.

    Rejects absolute paths, ``..`` traversal, and any resolution (following
    symlinks) that escapes the allowlisted root. The gateway's project-file
    tools address artifacts by DB id and never touch the filesystem, so this is
    defence-in-depth for any code path that ever maps a client string to a real
    path — and it is exercised directly by the security tests."""
    if rel is None:
        raise PathValidationError("path is required")
    s = str(rel)
    if "\x00" in s:
        raise PathValidationError("path contains a null byte")
    if s.startswith("/") or s.startswith("~") or (len(s) > 1 and s[1] == ":"):
        raise PathValidationError("absolute paths are not allowed")
    root = allowed_root.resolve()
    # Resolve WITH symlinks followed, then confirm containment.
    candidate = (root / s).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        raise PathValidationError("path escapes the allowed root")
    return candidate


# ---------------------------------------------------------------------------
# SSRF classification
# ---------------------------------------------------------------------------
# The gateway itself performs no outbound requests for its read-only tools. The
# only outbound capability is a governed scan, and that goes through the
# Execution Engine which re-validates the target against an explicit engagement
# scope (default-deny) and has its own SSRF protection. This function is a
# gateway-boundary pre-check (defence-in-depth) and the unit under the SSRF
# tests: it flags any target that resolves to a non-public address so the
# gateway can refuse it before a proposal is ever minted.

_METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "fd00:ec2::254"}


def _ip_is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_multicast or addr.is_reserved or addr.is_unspecified
    )


def classify_ssrf(target: str, *, resolve_dns: bool = False) -> tuple[bool, str]:
    """Return (is_internal, reason). is_internal=True means REFUSE.

    A bare host, an ip, or a URL are all accepted. When ``resolve_dns`` is set,
    a hostname is resolved and every returned address is checked (so a name that
    points at 127.0.0.1 or the cloud metadata IP is caught)."""
    if not target or not str(target).strip():
        return True, "empty target"
    raw = str(target).strip()
    host = raw
    if "://" in raw:
        parsed = urlparse(raw)
        if parsed.scheme.lower() not in ("http", "https"):
            return True, f"scheme '{parsed.scheme}' is not allowed"
        host = parsed.hostname or ""
    else:
        host = host.split("/")[0].split(":")[0]
    host = host.strip("[]").lower()
    if not host:
        return True, "no host in target"
    if host in _METADATA_HOSTS or host.endswith(".internal") or host == "localhost":
        return True, "cloud-metadata / internal hostname"
    # Literal IP?
    try:
        ipaddress.ip_address(host)
        if not _ip_is_public(host):
            return True, "target is a private / loopback / link-local address"
        return False, "public ip"
    except ValueError:
        pass
    # Hostname
    if resolve_dns:
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            return True, "hostname does not resolve"
        for info in infos:
            ip = info[4][0]
            if not _ip_is_public(ip):
                return True, f"hostname resolves to non-public address {ip}"
        return False, "hostname resolves to public address(es)"
    return False, "hostname (not resolved at gateway boundary)"

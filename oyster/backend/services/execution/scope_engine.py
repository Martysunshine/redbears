"""Deterministic engagement-scope validation for real tool execution.

This is the authorization gate. It is intentionally stricter than the legacy
``services.scope_service.validate_target`` (which uses ``fnmatch`` substring
style checks and powers the advisory red-team endpoints). Here we *parse and
normalize* every target and match it against explicit, typed scope rules,
because a wrong answer means a real tool runs against a real host.

Key guarantees
--------------
- Targets are parsed (URL → host+port+scheme, IP vs hostname) — never matched
  as raw substrings.
- IPs are matched against approved CIDRs with ``ipaddress`` (v4 and v6).
- Hostnames are matched against approved domains (exact or subdomain), never
  ``in`` substring checks. ``evil-corp.com`` does NOT match ``corp.com``.
- When the scope declares IP ranges AND a hostname is given, the resolved IP is
  additionally required to fall in scope — this blocks DNS-rebinding / a
  hostname that points at an out-of-scope address.
- Ports / protocols / prohibited techniques / excluded paths are enforced.
- Expired scopes and closed testing windows are rejected.
- The exact scope rule that allowed (or the exact reason that blocked) is
  returned, so it can be recorded on the policy decision.

The scope itself is read from the active project's stored scope (via
``scope_service.load_scope`` — bridged from the project). New optional keys are
read if present and ignored if absent, so existing scopes keep working.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse


@dataclass
class ParsedTarget:
    raw: str
    scheme: str | None
    host: str
    port: int | None
    path: str
    is_ip: bool
    ip_version: int | None


@dataclass
class ScopeResult:
    allowed: bool
    reason: str
    matched_rule: str | None = None
    resolved_ip: str | None = None
    parsed: ParsedTarget | None = None
    prohibited: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

def normalize_target(raw: str) -> ParsedTarget:
    """Parse a raw target string into scheme/host/port/path with IP detection."""
    raw = (raw or "").strip()
    scheme: str | None = None
    port: int | None = None
    path = ""

    work = raw
    if "://" in work:
        parsed = urlparse(work)
        scheme = (parsed.scheme or "").lower() or None
        host = (parsed.hostname or "").lower()
        port = parsed.port
        path = parsed.path or ""
    else:
        # host[:port][/path]
        host_part = work
        if "/" in host_part:
            host_part, _, rest = host_part.partition("/")
            path = "/" + rest
        # IPv6 in brackets
        if host_part.startswith("[") and "]" in host_part:
            bracket, _, after = host_part.partition("]")
            host = bracket[1:].lower()
            if after.startswith(":"):
                try:
                    port = int(after[1:])
                except ValueError:
                    port = None
        elif host_part.count(":") == 1:
            h, _, p = host_part.partition(":")
            host = h.lower()
            try:
                port = int(p)
            except ValueError:
                port = None
        else:
            host = host_part.lower()

    is_ip = False
    ip_version: int | None = None
    try:
        ip = ipaddress.ip_address(host)
        is_ip = True
        ip_version = ip.version
    except ValueError:
        pass

    # default port from scheme
    if port is None and scheme:
        port = {"http": 80, "https": 443, "ftp": 21, "ssh": 22}.get(scheme)

    return ParsedTarget(raw=raw, scheme=scheme, host=host, port=port,
                        path=path, is_ip=is_ip, ip_version=ip_version)


def _domain_matches(host: str, pattern: str) -> bool:
    """Exact or subdomain match — NOT substring. 'a.corp.com' matches 'corp.com'
    and '*.corp.com'; 'evilcorp.com' does not match 'corp.com'."""
    host = host.lower().rstrip(".")
    pattern = pattern.lower().lstrip("*.").rstrip(".")
    if not pattern:
        return False
    return host == pattern or host.endswith("." + pattern)


def _resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Scope window / expiry
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(value: str) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(value)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def scope_window_ok(scope: dict) -> tuple[bool, str]:
    """Check expiry + end_date + testing window. Returns (ok, reason)."""
    now = _now()
    # explicit expiration
    exp = scope.get("expiration") or scope.get("expires_at")
    if exp:
        dt = _parse_dt(exp)
        if dt and now > dt:
            return False, f"Engagement scope expired at {exp}."
    end = scope.get("end_date")
    if end:
        dt = _parse_dt(end)
        # end_date is a day; allow through the whole day
        if dt and now.date() > dt.date():
            return False, f"Engagement testing window ended on {end}."
    start = scope.get("start_date")
    if start:
        dt = _parse_dt(start)
        if dt and now.date() < dt.date():
            return False, f"Engagement testing window has not started (starts {start})."
    return True, "within testing window"


# ---------------------------------------------------------------------------
# Main validation
# ---------------------------------------------------------------------------

def _is_active(scope: dict) -> bool:
    has_name = bool(scope.get("engagement_name") or scope.get("project"))
    has_targets = bool(
        scope.get("domains") or scope.get("ip_ranges")
        or scope.get("allowed_targets") or scope.get("approved_cidrs")
    )
    return has_name and has_targets


def validate(target: str, scope: dict, *, technique: str | None = None,
             resolve_dns: bool = True) -> ScopeResult:
    """Validate a single target against a scope dict. Pure + deterministic.

    ``resolve_dns`` can be disabled in tests to avoid real DNS lookups.
    """
    p = normalize_target(target)

    if not p.host:
        return ScopeResult(False, "Empty or unparseable target.", parsed=p)

    if not _is_active(scope):
        return ScopeResult(
            False,
            "No active engagement scope with authorized targets. Store a scope "
            "(project scope / POST /scope/set) before requesting real execution.",
            parsed=p,
        )

    # Window / expiry
    ok, why = scope_window_ok(scope)
    if not ok:
        return ScopeResult(False, why, parsed=p)

    # Explicitly blocked targets first (host or url prefix)
    for blocked in scope.get("blocked_targets", []) or []:
        bp = normalize_target(blocked)
        if bp.host and bp.host == p.host:
            return ScopeResult(False, f"Target host '{p.host}' is explicitly excluded from scope.", parsed=p)

    # Excluded paths
    for xpath in scope.get("excluded_paths", []) or []:
        if xpath and p.path.startswith(xpath):
            return ScopeResult(False, f"Path '{p.path}' is excluded from scope ({xpath}).", parsed=p)

    # Prohibited techniques
    prohibited = [t.lower() for t in (scope.get("prohibited_techniques", []) or [])]
    if technique and technique.lower() in prohibited:
        return ScopeResult(False, f"Technique '{technique}' is prohibited by this engagement.",
                           parsed=p, prohibited=[technique])

    # Allowed techniques (allow-list, only enforced when present)
    allowed_tech = [t.lower() for t in (scope.get("allowed_techniques", []) or scope.get("allowed_tests", []) or [])]
    if allowed_tech and technique and technique.lower() not in allowed_tech:
        return ScopeResult(False, f"Technique '{technique}' is not in the allowed-techniques list.",
                           parsed=p, prohibited=[technique])

    # Port allow-list (only enforced when the scope declares approved ports)
    approved_ports = scope.get("approved_ports") or []
    if approved_ports and p.port is not None and p.port not in approved_ports:
        return ScopeResult(False, f"Port {p.port} is not in the approved ports {approved_ports}.", parsed=p)

    # Protocol allow-list (only enforced when declared)
    approved_protocols = [s.lower() for s in (scope.get("approved_protocols") or [])]
    if approved_protocols and p.scheme and p.scheme not in approved_protocols:
        return ScopeResult(False, f"Protocol '{p.scheme}' is not in the approved protocols {approved_protocols}.", parsed=p)

    resolved_ip: str | None = None

    # ---- IP target -------------------------------------------------------
    if p.is_ip:
        resolved_ip = p.host
        cidrs = (scope.get("ip_ranges") or []) + (scope.get("approved_cidrs") or [])
        for cidr in cidrs:
            try:
                if ipaddress.ip_address(p.host) in ipaddress.ip_network(cidr, strict=False):
                    return ScopeResult(True, f"IP {p.host} is within approved range {cidr}.",
                                       matched_rule=f"ip_range:{cidr}", resolved_ip=resolved_ip, parsed=p)
            except ValueError:
                continue
        # explicit allowed_targets that are literal IPs
        for t in scope.get("allowed_targets", []) or []:
            tp = normalize_target(t)
            if tp.host == p.host:
                return ScopeResult(True, f"IP {p.host} matches allowed target {t}.",
                                   matched_rule=f"allowed_target:{t}", resolved_ip=resolved_ip, parsed=p)
        return ScopeResult(False, f"IP {p.host} is not within any approved range.",
                           resolved_ip=resolved_ip, parsed=p)

    # ---- Hostname target -------------------------------------------------
    # exact allowed_targets (url list) match
    for t in scope.get("allowed_targets", []) or []:
        tp = normalize_target(t)
        if tp.host and tp.host == p.host:
            matched = f"allowed_target:{t}"
            break
    else:
        matched = None

    if matched is None:
        for pattern in scope.get("domains", []) or []:
            if _domain_matches(p.host, pattern):
                matched = f"domain:{pattern}"
                break

    if matched is None:
        return ScopeResult(False, f"Host '{p.host}' does not match any approved domain or target.", parsed=p)

    # DNS-rebinding guard: if the scope pins IP ranges, the resolved address
    # must ALSO be in range (a hostname can't point at an out-of-scope IP).
    cidrs = (scope.get("ip_ranges") or []) + (scope.get("approved_cidrs") or [])
    if cidrs and resolve_dns:
        resolved_ip = _resolve(p.host)
        if resolved_ip is None:
            return ScopeResult(False, f"Host '{p.host}' could not be resolved for scope verification.",
                               matched_rule=matched, parsed=p)
        in_range = False
        for cidr in cidrs:
            try:
                if ipaddress.ip_address(resolved_ip) in ipaddress.ip_network(cidr, strict=False):
                    in_range = True
                    break
            except ValueError:
                continue
        # Loopback hostnames resolving to loopback are fine even without a CIDR match
        loopback = ipaddress.ip_address(resolved_ip).is_loopback if resolved_ip else False
        if not in_range and not loopback:
            return ScopeResult(
                False,
                f"Host '{p.host}' resolves to {resolved_ip}, which is outside the approved IP ranges "
                f"(possible DNS rebinding / out-of-scope redirect).",
                matched_rule=matched, resolved_ip=resolved_ip, parsed=p,
            )

    return ScopeResult(True, f"Host '{p.host}' authorized via {matched}.",
                       matched_rule=matched, resolved_ip=resolved_ip, parsed=p)


def validate_redirect(location: str, scope: dict) -> ScopeResult:
    """Validate that a redirect Location stays within scope. Used by the HTTP
    adapter to refuse following a redirect that leaves approved scope."""
    return validate(location, scope, resolve_dns=False)

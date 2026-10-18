from __future__ import annotations

import fnmatch
import ipaddress
import json
from urllib.parse import urlparse

import config

SCOPE_FILE = config.SCOPE_FILE
SCOPE_FILE.parent.mkdir(parents=True, exist_ok=True)

_EMPTY_SCOPE: dict = {
    "engagement_name": "",
    "authorized_by": "",
    "start_date": "",
    "end_date": "",
    "domains": [],
    "ip_ranges": [],
    "repositories": [],
    "notes": "",
}


def load_scope() -> dict:
    if not SCOPE_FILE.exists():
        return dict(_EMPTY_SCOPE)
    try:
        return json.loads(SCOPE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return dict(_EMPTY_SCOPE)


def save_scope(data: dict) -> dict:
    SCOPE_FILE.parent.mkdir(parents=True, exist_ok=True)
    SCOPE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data


def is_scope_active(scope: dict | None = None) -> bool:
    """Is there a usable engagement scope?

    ``scope=None`` reads the global scope file, which is what every operator
    call site has always done. Callers that hold a specific account's scope
    (see ``services/project_context``) pass it in, so per-account red-team
    checks never consult — or depend on — the shared file.
    """
    if scope is None:
        scope = load_scope()
    has_name = bool(scope.get("engagement_name") or scope.get("project"))
    has_targets = bool(
        scope.get("domains")
        or scope.get("ip_ranges")
        or scope.get("repositories")
        or scope.get("allowed_targets")
    )
    return has_name and has_targets


def _normalize_target(target: str) -> str:
    """Strip URL scheme/path so 'https://api.corp.com/v1' becomes 'api.corp.com'."""
    target = target.strip()
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target
    return target


def validate_target(target: str, scope: dict | None = None) -> tuple[bool, str]:
    """Return (is_authorized, reason_string).

    ``scope=None`` validates against the global scope file (operator default,
    unchanged). Pass an explicit scope dict to validate against one account's
    own engagement — that is what keeps one account's authorised targets
    invisible to another.
    """
    if scope is None:
        scope = load_scope()

    if not is_scope_active(scope):
        return (
            False,
            "No active engagement scope. Define scope via POST /scope/set before running security workflows.",
        )

    normalized = _normalize_target(target)

    # IP address check
    try:
        target_ip = ipaddress.ip_address(normalized)
        for cidr in scope.get("ip_ranges", []):
            try:
                if target_ip in ipaddress.ip_network(cidr, strict=False):
                    return True, f"Target IP is within authorized range: {cidr}"
            except ValueError:
                continue
    except ValueError:
        pass  # Not an IP — try domain / repo

    # Domain check (supports wildcards like *.corp.com)
    for pattern in scope.get("domains", []):
        if fnmatch.fnmatch(normalized, pattern):
            return True, f"Target matches authorized domain: {pattern}"
        if fnmatch.fnmatch(normalized, f"*.{pattern}"):
            return True, f"Target is a subdomain of authorized domain: {pattern}"

    # Repository check (supports wildcards like github.com/corp/*)
    for pattern in scope.get("repositories", []):
        if fnmatch.fnmatch(normalized, pattern) or fnmatch.fnmatch(target, pattern):
            return True, f"Target matches authorized repository: {pattern}"

    # allowed_targets URL list (e.g. http://localhost:3000)
    for url_target in scope.get("allowed_targets", []):
        parsed_allowed = urlparse(url_target)
        allowed_host = parsed_allowed.hostname or url_target
        if normalized == allowed_host:
            return True, f"Target matches allowed target: {url_target}"
        # also match localhost variants (127.0.0.1 == localhost)
        if normalized in ("localhost", "127.0.0.1") and allowed_host in ("localhost", "127.0.0.1"):
            return True, f"Target matches allowed localhost target: {url_target}"
        if target.startswith(url_target):
            return True, f"Target is under allowed target: {url_target}"

    return (
        False,
        f"Target '{target}' is NOT in the authorized engagement scope. "
        "Verify with your rules of engagement and update scope via POST /scope/set if needed.",
    )

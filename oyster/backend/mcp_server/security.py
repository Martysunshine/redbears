from __future__ import annotations

import re
from typing import Tuple

# Always-allowed loopback targets — no scope required
ALWAYS_ALLOWED_HOSTS: frozenset[str] = frozenset({
    "127.0.0.1", "localhost", "0.0.0.0", "::1",
})

# Valid hostname/IP pattern — blocks shell metacharacters
_TARGET_RE = re.compile(r"^[a-zA-Z0-9._:\-/\[\]]+$")


def validate_network_target(target: str) -> Tuple[bool, str]:
    """
    Return (allowed, reason).
    Loopback addresses are always allowed.
    All other targets require an active scope entry.
    """
    if not _TARGET_RE.match(target):
        return False, f"Target '{target}' contains invalid characters"

    clean = target.lower().rstrip("/")
    if clean in ALWAYS_ALLOWED_HOSTS:
        return True, "loopback — always allowed"

    try:
        from services import scope_service

        if not scope_service.is_scope_active():
            return False, (
                f"No active engagement scope. Target '{target}' is not in the loopback "
                f"allow-list (127.0.0.1 / localhost / ::1). Set scope via POST /scope/set."
            )

        scope = scope_service.load_scope()
        allowed_targets: list[str] = scope.get("allowed_targets", [])
        if target in allowed_targets or clean in allowed_targets:
            return True, "target in scope allowed_targets"

        ok, reason = scope_service.validate_target(target)
        if ok:
            return True, reason
        return False, f"Target '{target}' is not authorised in the current engagement scope"

    except Exception as exc:
        return False, f"Scope check failed: {exc}"


def validate_nmap_target(target: str) -> Tuple[bool, str]:
    """Alias kept for clarity; currently identical to validate_network_target."""
    return validate_network_target(target)

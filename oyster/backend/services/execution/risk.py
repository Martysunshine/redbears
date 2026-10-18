"""Deterministic execution classes (0–4) and approval requirements.

Risk is a property of the *tool action*, declared in the tool profile — it is
never inferred from an LLM. This module only names the classes and maps a class
to an approval requirement + default output/runtime caps, so the policy layer
stays declarative.
"""

from __future__ import annotations

from dataclasses import dataclass

# Execution classes ---------------------------------------------------------
CLASS_READ_ONLY = 0        # local analysis: parse/hash/search, static analysis
CLASS_PASSIVE = 1          # passive external retrieval: fetch docs/advisories
CLASS_LOW_ACTIVE = 2       # low-impact active: host discovery, header/TLS check
CLASS_INTRUSIVE = 3        # intrusive: vuln scan, auth test, fuzzing, exploit-validate
CLASS_DESTRUCTIVE = 4      # destructive/high-consequence: DoS, data deletion, persistence

# Approval requirements -----------------------------------------------------
APPROVAL_NONE = "none"                 # allowed by project, no prompt
APPROVAL_CONFIG = "config"             # needs valid config/egress policy (class 1)
APPROVAL_SCOPE = "scope"               # needs an in-scope target (class 2)
APPROVAL_REMEMBERABLE = "remember_ok"  # class 2 where policy may remember approval
APPROVAL_EXPLICIT = "explicit"         # class 3 — human approval immediately before
APPROVAL_BLOCKED = "blocked"           # class 4 — blocked by default

CLASS_NAMES = {
    CLASS_READ_ONLY: "Read-only local analysis",
    CLASS_PASSIVE: "Passive external retrieval",
    CLASS_LOW_ACTIVE: "Low-impact active testing",
    CLASS_INTRUSIVE: "Intrusive testing",
    CLASS_DESTRUCTIVE: "Destructive / high-consequence",
}

RISK_LABEL = {
    CLASS_READ_ONLY: "informational",
    CLASS_PASSIVE: "low",
    CLASS_LOW_ACTIVE: "medium",
    CLASS_INTRUSIVE: "high",
    CLASS_DESTRUCTIVE: "critical",
}


@dataclass
class RiskProfile:
    execution_class: int
    risk_level: str
    default_approval: str
    requires_scope: bool
    default_timeout: int
    default_max_output: int
    blocked: bool


def profile_for_class(execution_class: int) -> RiskProfile:
    ec = int(execution_class)
    if ec <= CLASS_READ_ONLY:
        return RiskProfile(CLASS_READ_ONLY, RISK_LABEL[0], APPROVAL_NONE, False, 30, 1_048_576, False)
    if ec == CLASS_PASSIVE:
        return RiskProfile(CLASS_PASSIVE, RISK_LABEL[1], APPROVAL_CONFIG, False, 30, 1_048_576, False)
    if ec == CLASS_LOW_ACTIVE:
        return RiskProfile(CLASS_LOW_ACTIVE, RISK_LABEL[2], APPROVAL_SCOPE, True, 60, 2_097_152, False)
    if ec == CLASS_INTRUSIVE:
        return RiskProfile(CLASS_INTRUSIVE, RISK_LABEL[3], APPROVAL_EXPLICIT, True, 120, 4_194_304, False)
    # class 4+
    return RiskProfile(CLASS_DESTRUCTIVE, RISK_LABEL[4], APPROVAL_BLOCKED, True, 0, 0, True)

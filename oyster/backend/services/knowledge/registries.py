"""Read-only access to the disabled-by-default knowledge registries and a
content risk classifier.

Registries (``knowledge_registries/*.json``) are DEFINITIONS ONLY — dataset
providers, isolated labs, large secondary payload/wordlist sources, and
adversarial-recognition fixtures. Nothing here is downloaded, ingested, trained
on, or executed. They exist so Oyster can *recommend* the right resource to an
approved, scoped workflow and keep high-risk payload knowledge separated from
ordinary guidance.

``classify_content_risk`` flags payload/exploit-shaped content so it can be
gated behind scope + approval before any *tool* acts on it (the knowledge itself
stays read-only).
"""

from __future__ import annotations

import json
import re

import config

_DIR = config.KNOWLEDGE_REGISTRIES_DIR


def _load(name: str) -> dict:
    fp = _DIR / f"{name}.json"
    if not fp.exists():
        return {"registry": name, "items": [], "error": "registry file not found"}
    try:
        return json.loads(fp.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        return {"registry": name, "items": [], "error": f"unreadable: {e}"}


def datasets() -> dict:
    return _load("datasets")


def labs() -> dict:
    return _load("labs")


def secondary_sources() -> dict:
    return _load("secondary_sources")


def adversarial_fixtures() -> dict:
    return _load("adversarial_fixtures")


def summary() -> dict:
    def _count(d: dict) -> int:
        return len(d.get("items", []))
    return {
        "datasets": {"count": _count(datasets()), "training_disabled": True, "enabled": 0},
        "labs": {"count": _count(labs()), "auto_start": False},
        "secondary_sources": {"count": _count(secondary_sources()), "enabled": 0},
        "adversarial_fixtures": {"count": _count(adversarial_fixtures()), "enabled": 0},
        "note": "All registries are disabled by default; definitions only, nothing is executed or ingested.",
    }


# ---------------------------------------------------------------------------
# Payload / high-risk content classifier
# ---------------------------------------------------------------------------

_HIGH_RISK_PATTERNS = [
    (re.compile(r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){6,}"), "shellcode-byte-array"),
    (re.compile(r"\bmsfvenom\b|\bmeterpreter\b", re.I), "exploit-framework-payload"),
    (re.compile(r"\bnc\s+-e\b|/bin/sh\s+-i|bash\s+-i\s+>&\s*/dev/tcp", re.I), "reverse-shell"),
    (re.compile(r"(?:union\s+select|'\s*or\s*'1'\s*=\s*'1)", re.I), "sqli-payload"),
    (re.compile(r"<script>[^<]*</script>|onerror\s*=", re.I), "xss-payload"),
    (re.compile(r"seclists|rockyou|payloadsallthethings", re.I), "wordlist-or-payload-corpus"),
    (re.compile(r"\x90{8,}"), "nop-sled"),
]

_MEDIUM_RISK_PATTERNS = [
    (re.compile(r"\bsudo\s+-l\b|getcap\s+-r|find\s+/\s+-perm\s+-4000", re.I), "privesc-enumeration"),
    (re.compile(r"\bkerberoast|dcsync|mimikatz|lsass\b", re.I), "credential-access-technique"),
]


def classify_content_risk(text: str) -> dict:
    """Classify a piece of content for payload/exploit risk.

    Returns the highest matched risk level plus the scope/approval flags that a
    tool would have to honor before acting on the content. Read-only: this never
    executes anything.
    """
    text = text or ""
    reasons: list[str] = []
    level = "informational"
    for pat, label in _HIGH_RISK_PATTERNS:
        if pat.search(text):
            reasons.append(label)
            level = "high"
    if level != "high":
        for pat, label in _MEDIUM_RISK_PATTERNS:
            if pat.search(text):
                reasons.append(label)
                level = "medium"
    high = level == "high"
    medium = level in ("high", "medium")
    return {
        "risk_level": level,
        "reasons": sorted(set(reasons)),
        "requires_target_scope": medium,
        "approval_required": medium,
        "active_execution_possible": high,
        "authorized_lab_only": high,
    }

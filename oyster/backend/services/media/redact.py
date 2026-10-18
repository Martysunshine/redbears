"""Redact likely secrets before they reach a UI preview or a log line.

Detection is best-effort and intentionally conservative — a match is an
*indicator*, never a guaranteed finding. Full secret values are never surfaced;
they are replaced by a masked stub that preserves a short prefix for triage.
"""

from __future__ import annotations

import re

# (label, compiled pattern). Order matters — more specific first.
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})")),
    ("github_token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("bearer", re.compile(r"(?i)\b(?:bearer|authorization)\s*[:=]\s*['\"]?([A-Za-z0-9._\-]{16,})")),
    ("password_assignment", re.compile(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[=:]\s*['\"]?([^\s'\"]{6,})")),
    ("generic_hex_secret", re.compile(r"\b[0-9a-fA-F]{32,64}\b")),
    # Financial / government identifiers — never persisted automatically.
    ("credit_card", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")),
]


def _luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _mask(value: str) -> str:
    value = value.strip()
    if len(value) <= 6:
        return "•" * len(value)
    return f"{value[:4]}…{value[-2:]} [redacted {len(value)} chars]"


def _plausible(label: str, raw: str) -> bool:
    """Extra validation for patterns that would otherwise over-match."""
    if label == "credit_card":
        digits = re.sub(r"[ -]", "", raw)
        return 13 <= len(digits) <= 19 and _luhn_valid(digits)
    if label == "generic_hex_secret":
        # a run of hex chars that's actually all-decimal is more likely a plain
        # number than a secret; require at least one a-f character.
        return re.search(r"[a-fA-F]", raw) is not None
    return True


def scan(text: str) -> list[dict]:
    """Return a list of possible-secret indicators (values already masked)."""
    if not text:
        return []
    found: list[dict] = []
    seen: set[str] = set()
    for label, pat in _PATTERNS:
        for m in pat.finditer(text):
            raw = m.group(1) if m.groups() else m.group(0)
            if not _plausible(label, raw):
                continue
            key = f"{label}:{raw}"
            if key in seen:
                continue
            seen.add(key)
            found.append({"type": label, "masked": _mask(raw)})
            if len(found) >= 25:
                return found
    return found


def redact(text: str) -> str:
    """Return text with any detected secret values masked in place."""
    if not text:
        return text
    out = text
    for label, pat in _PATTERNS:
        def _sub(m: re.Match, _label: str = label) -> str:
            raw = m.group(1) if m.groups() else m.group(0)
            if not _plausible(_label, raw):
                return m.group(0)
            return m.group(0).replace(raw, _mask(raw))
        out = pat.sub(_sub, out)
    return out


def contains_sensitive(text: str) -> bool:
    """Fast boolean check — used to block automatic persistence outright."""
    return len(scan(text)) > 0
